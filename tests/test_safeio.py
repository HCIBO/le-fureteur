import io
import os
import shutil
import stat
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from scakit import safeio
from scakit.safeio import SafeZipFile, UnsafeInput, budget, csv_cell, safe_extract, xml_fromstring


def _zip(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data, link in entries:
            zi = zipfile.ZipInfo(name)
            if link:
                zi.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(zi, data)
    return buf.getvalue()


class ExtractTest(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.dest = self.base / "scakit-abc"
        self.sibling = self.base / "scakit-abcEVIL"

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def test_zip_slip_and_links(self):
        p = self.base / "x.zip"
        p.write_bytes(_zip([("ok/a.txt", "ok", False), ("../evil1.txt", "x", False), ("/tmp/evil2.txt", "x", False),
                            ("..\\evil3.txt", "x", False), ("C:/evil4.txt", "x", False),
                            ("../scakit-abcEVIL/evil5.txt", "x", False), ("link", "/etc/passwd", True)]))
        safe_extract(p, self.dest)
        files = sorted(str(f.relative_to(self.dest)) for f in self.dest.rglob("*") if f.is_file())
        self.assertEqual(files, ["ok/a.txt"])
        self.assertFalse((self.base / "evil1.txt").exists())
        self.assertFalse(self.sibling.exists())
        self.assertFalse(Path("/tmp/evil2.txt").exists())

    def test_tar_links_devices(self):
        p = self.base / "x.tar"
        with tarfile.open(p, "w") as tf:
            def add(name, typ=tarfile.REGTYPE, data=b"ok", linkname=""):
                ti = tarfile.TarInfo(name)
                ti.type, ti.linkname, ti.size = typ, linkname, len(data) if typ == tarfile.REGTYPE else 0
                tf.addfile(ti, io.BytesIO(data) if typ == tarfile.REGTYPE else None)
            add("ok.txt")
            add("sym", tarfile.SYMTYPE, linkname="/etc/passwd")
            add("hard", tarfile.LNKTYPE, linkname="/etc/passwd")
            add("dev", tarfile.CHRTYPE)
            add("../../evil.txt")
            add("sym/through.txt")
        safe_extract(p, self.dest)
        found = sorted(f.name for f in self.dest.rglob("*"))
        self.assertIn("ok.txt", found)
        self.assertFalse(any((self.dest / n).is_symlink() for n in ("sym", "hard")))
        self.assertNotIn("dev", found)
        self.assertFalse((self.base / "evil.txt").exists())

    def test_zip_bomb_member_and_budget(self):
        old = dict(safeio.LIMITS)
        try:
            safeio.LIMITS.update(member=1000, total=2500)
            big = self.base / "big.zip"
            big.write_bytes(_zip([("big.bin", "A" * 5000, False)]))
            with self.assertRaises(UnsafeInput):
                safe_extract(big, self.dest)
            many = self.base / "many.zip"
            many.write_bytes(_zip([(f"f{i}.bin", "A" * 900, False) for i in range(5)]))
            with budget(), self.assertRaises(UnsafeInput):
                safe_extract(many, self.dest / "m")
            with budget():
                z = SafeZipFile(io.BytesIO(_zip([("a", "A" * 900, False), ("b", "A" * 900, False), ("c", "A" * 900, False)])))
                z.read("a")
                z.read("b")
                with self.assertRaises(UnsafeInput):
                    z.read("c")
        finally:
            safeio.LIMITS.clear()
            safeio.LIMITS.update(old)

    def test_walk_skips_symlinks(self):
        secret = self.base / "secret.key"
        secret.write_text("/*! jQuery v3.4.1 | (c) */")
        d = self.base / "app"
        d.mkdir()
        (d / "real.LICENSE.txt").write_text("hello")
        os.symlink(secret, d / "x.LICENSE.txt")
        os.symlink(self.base, d / "loopdir")
        files = {p.name for p in safeio.walk_files(d)}
        self.assertEqual(files, {"real.LICENSE.txt"})
        with self.assertRaises(UnsafeInput):
            safeio.read_file(d / "x.LICENSE.txt")
        from scakit.collectors.blackbox.desktop import scan_binaries
        comps, _ = scan_binaries(d, "t")
        self.assertFalse(any("jquery" in c.name.lower() for c in comps))


class XmlCsvTest(unittest.TestCase):
    def test_xxe_and_billion_laughs(self):
        xxe = b'<?xml version="1.0"?><!DOCTYPE p [<!ENTITY x SYSTEM "file:///etc/passwd">]><project><version>&x;</version></project>'
        lol = b'<!DOCTYPE l [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]><l>&b;</l>'
        for doc in (xxe, lol):
            with self.assertRaises(UnsafeInput):
                xml_fromstring(doc)
        from scakit.collectors.whitebox.jvm import parse_pom
        self.assertEqual(parse_pom(xxe.decode(), "pom.xml"), [])
        self.assertEqual(xml_fromstring(b"<project><version>1</version></project>").find("version").text, "1")

    def test_csv_formula(self):
        for v in ("=HYPERLINK(\"http://x\")", "+1+1", "-2", "@SUM(A1)", "\t=1", "＝1"):
            self.assertTrue(csv_cell(v).startswith("'"), v)
        self.assertEqual(csv_cell("lodash"), "lodash")
        self.assertEqual(csv_cell(None), "")

    def test_report_escaping(self):
        from scakit.report import document
        from scakit.report.render import vuln_url

        class F:
            vuln_id = 'GHSA-x"><img src=x>'
            source = "OSV"
        self.assertNotIn('"', vuln_url(F())[len("https://"):].split("/", 1)[1])
        try:
            import reportlab
        except ImportError:
            self.skipTest("reportlab yok")
        from reportlab.platypus import Paragraph
        from reportlab.lib.styles import getSampleStyleSheet
        esc = lambda s: str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
        Paragraph(esc('<img src="/etc/passwd"/>'), getSampleStyleSheet()["Normal"])
        self.assertTrue(hasattr(document, "to_pdf"))


@unittest.skipIf(not (shutil.which("7z") or shutil.which("7zz")), "7z yok")
class SevenZipTest(unittest.TestCase):
    def test_precheck_rejects_links_and_traversal(self):
        from scakit.collectors.blackbox.desktop import _seven_zip, precheck_7z
        d = Path(tempfile.mkdtemp())
        try:
            (d / "link.zip").write_bytes(_zip([("ok", "1", False), ("l", "/etc/passwd", True)]))
            (d / "trav.zip").write_bytes(_zip([("../../x", "1", False)]))
            (d / "ok.zip").write_bytes(_zip([("a/b.txt", "1", False)]))
            for bad in ("link.zip", "trav.zip"):
                with self.assertRaises(UnsafeInput):
                    precheck_7z(_seven_zip(), str(d / bad))
            precheck_7z(_seven_zip(), str(d / "ok.zip"))
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
