import io
import json
import plistlib
import sqlite3
import struct
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path

from scakit.collectors.binary import asar_files, macho_encrypted, pe_info, scan_native
from scakit.collectors.blackbox.desktop import scan_binaries
from scakit.collectors.blackbox.ipa import scan_ipa
from scakit.collectors.whitebox.ospkg import os_ecosystem, parse_package_list, parse_rpm_packages
from scakit.collectors.whitebox.rpmdb import read_rpmdb
from scakit.matcher import match_inventory
from scakit.models import Component, Evidence
from scakit.usage import annotate, collect_imports, go_reachability
from scakit.versions import cpe_cmp
from scakit.vulndb import nvd
from scakit.vulndb.db import VulnDB

from .helpers import FIX, eco_range, osv, osv_zip


def rpm_header(fields: dict) -> bytes:
    index, store = b"", b""
    for tag, val in fields.items():
        if isinstance(val, int):
            while len(store) % 4:
                store += b"\x00"
            index += struct.pack(">iiii", tag, 4, len(store), 1)
            store += struct.pack(">i", val)
        else:
            index += struct.pack(">iiii", tag, 6, len(store), 1)
            store += val.encode() + b"\x00"
    return struct.pack(">II", len(fields), len(store)) + index + store


def fake_pe(product_version: str, managed: bool = True, company: str = "Newtonsoft") -> bytes:
    pe = bytearray(0x200)
    pe[0:2] = b"MZ"
    struct.pack_into("<I", pe, 0x3C, 0x80)
    pe[0x80:0x84] = b"PE\x00\x00"
    opt = 0x80 + 24
    struct.pack_into("<H", pe, opt, 0x20B)
    if managed:
        struct.pack_into("<II", pe, opt + 112 + 14 * 8, 0x2000, 0x48)
    def kv(k, v):
        pe.extend(k.encode("utf-16-le") + b"\x00\x00")
        while len(pe) % 4:
            pe.extend(b"\x00")
        pe.extend(v.encode("utf-16-le") + b"\x00\x00\x00\x00")
        while len(pe) % 4:
            pe.extend(b"\x00")
    kv("CompanyName", company)
    kv("ProductVersion", product_version)
    return bytes(pe)


def macho64(encrypted: bool) -> bytes:
    hdr = struct.pack("<IiiIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, 24, 0) + b"\x00" * 4
    cmd = struct.pack("<IIIIII", 0x2C, 24, 0x4000, 0x1000, 1 if encrypted else 0, 0)
    return hdr + cmd + b"\x00" * 64


class RpmTest(unittest.TestCase):
    def test_sqlite_rpmdb_and_lists(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "rpmdb.sqlite"
            con = sqlite3.connect(p)
            con.execute("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY, blob BLOB)")
            for i, h in enumerate([
                {1000: "openssl-libs", 1001: "3.0.1", 1002: "23.el9_0", 1003: 1, 1044: "openssl-3.0.1-23.el9_0.src.rpm"},
                {1000: "curl", 1001: "7.76.1", 1002: "14.el9", 1044: "curl-7.76.1-14.el9.src.rpm", 1014: "MIT"},
                {1000: "gpg-pubkey", 1001: "x", 1002: "y"},
            ]):
                con.execute("INSERT INTO Packages VALUES (?,?)", (i, rpm_header(h)))
            con.commit()
            con.close()
            pk = read_rpmdb(str(p))
        self.assertEqual([(x["name"], x["version"], x["source"]) for x in pk],
                         [("openssl-libs", "1:3.0.1-23.el9_0", "openssl"), ("curl", "7.76.1-14.el9", "curl")])
        rocky = parse_rpm_packages(pk, "db", "Rocky Linux:9")
        self.assertEqual({c.name for c in rocky}, {"openssl", "curl"})
        rh = parse_rpm_packages(pk, "db", "Red Hat:9")
        self.assertEqual({c.name for c in rh}, {"openssl-libs", "curl"})
        lst = parse_package_list("openssl-libs\t1:3.0.1-23.el9_0\topenssl-3.0.1-23.el9_0.src.rpm\n"
                                 "bash\t0:5.1.8-4.el9\tbash-5.1.8-4.el9.src.rpm\n", "l", "Rocky Linux:9")
        self.assertEqual([(c.name, c.version) for c in lst], [("openssl", "1:3.0.1-23.el9_0"), ("bash", "5.1.8-4.el9")])

    def test_os_release(self):
        self.assertEqual(os_ecosystem('ID="rocky"\nVERSION_ID="9.0"'), "Rocky Linux:9")
        self.assertEqual(os_ecosystem('ID="centos"\nVERSION_ID="7"'), "Red Hat:7")
        self.assertEqual(os_ecosystem('ID=ubuntu\nVERSION_ID="22.04"'), "Ubuntu:22.04:LTS")

    def test_redhat_ecosystem_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = VulnDB(Path(tmp) / "db.sqlite")
            db.import_osv_zip(osv_zip([osv("RHSA-1", "Red Hat:enterprise_linux:9::baseos", "openssl-libs",
                                           eco_range(("introduced", "0"), ("fixed", "1:3.0.7-16.el9_2")))]), "t")
            fs, _ = match_inventory([Component("Red Hat:9", "openssl-libs", "1:3.0.1-23.el9_0"),
                                     Component("Red Hat:8", "openssl-libs", "1:3.0.1-23.el9_0")], db)
            self.assertEqual([(f.vuln_id, f.component_key.split("|")[0]) for f in fs], [("RHSA-1", "Red Hat")])
            self.assertEqual(fs[0].upgrade_to, "1:3.0.7-16.el9_2")
            db.close()


class NvdTest(unittest.TestCase):
    def test_cpe_cmp(self):
        for a, b, e in [("1.1.1k", "1.1.1", 1), ("1.1.1k", "1.1.1l", -1), ("2.4.41", "2.4.9", 1),
                        ("8.0.0-beta1", "8.0.0", -1), ("1.0.2k", "1.0.2zh", -1), ("6.0", "6.0.0", 0)]:
            self.assertEqual(cpe_cmp(a, b), e, (a, b))

    def test_nvd_match(self):
        cve = {"id": "CVE-2021-0001", "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {
            "baseScore": 9.8, "baseSeverity": "CRITICAL", "vectorString": "CVSS:3.1/AV:N"}}]},
            "descriptions": [{"lang": "en", "value": "openssl bug"}],
            "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [
                {"vulnerable": True, "criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
                 "versionStartIncluding": "1.1.1", "versionEndExcluding": "1.1.1l"}]}]}]}
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "nvd_openssl_openssl.json").write_text(json.dumps(
                {"cpe": "openssl:openssl", "vulnerabilities": [{"cve": cve}]}))
            db = VulnDB(Path(tmp) / "db.sqlite")
            nvd.import_dir(db, tmp, log=lambda m: None)
            ok = Component("generic", "openssl", "1.1.1k", evidence=[Evidence("binary-strings", "x")])
            distro = Component("generic", "openssl", "1.1.1j", evidence=[Evidence("header", "u", "OpenSSL (Ubuntu)")])
            fixed = Component("generic", "openssl", "1.1.1l")
            fs, notes = match_inventory([ok, distro, fixed], db)
            got = {f.component_key: f for f in fs}
            self.assertEqual(len(fs), 2)
            f = got[ok.key]
            self.assertEqual((f.source, f.severity, f.upgrade_to, f.confidence), ("NVD", "CRITICAL", "1.1.1l", "high"))
            self.assertEqual(got[distro.key].confidence, "low")
            db.close()


class MobileDesktopTest(unittest.TestCase):
    def test_ipa(self):
        b = io.BytesIO()
        with zipfile.ZipFile(b, "w") as z:
            z.writestr("Payload/Demo.app/Info.plist", plistlib.dumps({"CFBundleExecutable": "Demo",
                                                                      "CFBundleIdentifier": "com.x.demo",
                                                                      "CFBundleShortVersionString": "2.1"}))
            z.writestr("Payload/Demo.app/Demo", macho64(encrypted=True))
            z.writestr("Payload/Demo.app/Frameworks/Alamofire.framework/Info.plist", plistlib.dumps(
                {"CFBundleIdentifier": "org.cocoapods.Alamofire", "CFBundleShortVersionString": "5.4.0",
                 "CFBundleExecutable": "Alamofire"}))
            z.writestr("Payload/Demo.app/Frameworks/Alamofire.framework/Alamofire", b"_TtC9Alamofire7Session")
            z.writestr("Payload/Demo.app/Frameworks/OpenSSL.framework/Info.plist", plistlib.dumps(
                {"CFBundleExecutable": "OpenSSL", "CFBundleShortVersionString": "1.0"}))
            z.writestr("Payload/Demo.app/Frameworks/OpenSSL.framework/OpenSSL", b"\x00OpenSSL 1.1.1g  21 Apr 2020\x00")
            z.writestr("Payload/Demo.app/main.jsbundle", "var V={major:0,minor:64,patch:1};/*! DOMPurify 2.0.8 */")
        with tempfile.NamedTemporaryFile(suffix=".ipa") as f:
            f.write(b.getvalue())
            f.flush()
            comps, notes = scan_ipa(f.name)
        got = {(c.ecosystem, c.name, c.version) for c in comps}
        for exp in [("CocoaPods", "Alamofire", "5.4.0"), ("generic", "openssl", "1.1.1g"),
                    ("npm", "react-native", "0.64.1"), ("npm", "dompurify", "2.0.8")]:
            self.assertIn(exp, got)
        self.assertNotIn(("SwiftURL", "github.com/Alamofire/Alamofire", None), got)
        self.assertTrue(any("FairPlay" in n[2] for n in notes))
        self.assertTrue(macho_encrypted(macho64(True)))
        self.assertFalse(macho_encrypted(macho64(False)))

    def test_pe_asar_native(self):
        info = pe_info(fake_pe("13.0.1+ae9fe44e1323e91bcbd185ca1a14099fba7c021f"))
        self.assertTrue(info["managed"])
        self.assertEqual(info["ProductVersion"].split("+")[0], "13.0.1")
        self.assertFalse(pe_info(fake_pe("1.0", managed=False))["managed"])
        files = {"node_modules": {"files": {"lodash": {"files": {"package.json": {"size": 0, "offset": "0"}}}}}}
        pj = b'{"name":"lodash","version":"4.17.15"}'
        files["node_modules"]["files"]["lodash"]["files"]["package.json"]["size"] = len(pj)
        hdr = json.dumps({"files": files}).encode()
        pickle = struct.pack("<II", len(hdr) + 4, len(hdr)) + hdr
        asar = struct.pack("<II", 4, len(pickle)) + pickle + pj
        self.assertEqual(list(asar_files(asar)), [("node_modules/lodash/package.json", pj)])
        self.assertEqual(scan_native(b"xx Electron/22.3.1 yy")[0][:3], ("npm", "electron", "22.3.1"))
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "Newtonsoft.Json.dll").write_bytes(fake_pe("12.0.3+abc"))
            for i in range(3):
                (Path(tmp) / f"Vendor.Part{i}.dll").write_bytes(fake_pe("1.0.0", company="Acme Corp"))
            (Path(tmp) / "resources").mkdir()
            (Path(tmp) / "resources" / "app.asar").write_bytes(asar)
            comps, _ = scan_binaries(Path(tmp), "t")
        got = {(c.ecosystem, c.name, c.version) for c in comps}
        self.assertEqual(got, {("NuGet", "Newtonsoft.Json", "12.0.3"), ("npm", "lodash", "4.17.15")})


class UsageTest(unittest.TestCase):
    def test_imports_and_go_reachability(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "a.ts").write_text("import _ from 'lodash';\nconst ax = require('@scope/pkg/sub');\nimport './x';")
            Path(tmp, "b.py").write_text("import yaml\nfrom django.db import models\n")
            Path(tmp, "C.java").write_text("import org.apache.logging.log4j.LogManager;\n")
            Path(tmp, "m.go").write_text('package main\nimport (\n "golang.org/x/text/language"\n)\n'
                                         'func f(){ language.Parse("x") }\n')
            imp = collect_imports(tmp)
        comps = [Component("npm", "lodash", "1", direct=True), Component("npm", "@scope/pkg", "1", direct=True),
                 Component("npm", "axios", "1", direct=True), Component("PyPI", "PyYAML", "5", direct=True),
                 Component("PyPI", "Django", "3", direct=True), Component("PyPI", "requests", "2", direct=True),
                 Component("Maven", "org.apache.logging.log4j:log4j-core", "2", direct=True),
                 Component("NuGet", "Newtonsoft.Json", "13", direct=True)]
        annotate(comps, imp)
        self.assertEqual([c.usage for c in comps], ["imported", "imported", "not-imported", "imported", "imported",
                                                    "not-imported", "imported", None])
        go = Component("Go", "golang.org/x/text", "0.3.6")
        v = lambda syms: {"affected": [{"ecosystem_specific": {"imports": [
            {"path": "golang.org/x/text/language", "symbols": syms}]}}]}
        self.assertEqual(go_reachability(v(["Parse"]), go, imp["go_calls"]), "called")
        self.assertEqual(go_reachability(v(["MatchStrings"]), go, imp["go_calls"]), "not-called")


class DocumentTest(unittest.TestCase):
    def test_pdf_docx(self):
        try:
            import docx
            import reportlab
        except ImportError:
            self.skipTest("reportlab / python-docx yok")
        from scakit.cli import main
        with tempfile.TemporaryDirectory() as tmp:
            dbp = Path(tmp) / "db.sqlite"
            db = VulnDB(dbp)
            db.import_osv_zip(osv_zip([osv("GHSA-x", "npm", "lodash", eco_range(("introduced", "0"), ("fixed", "4.17.21")),
                                           severity="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")]), "t")
            db.close()
            eng = Path(tmp) / "e"
            main(["init", str(eng), "--name", "Doküman Testi", "--client", "Şirket"])
            main(["add", str(eng), str(FIX / "app" / "web")])
            main(["match", str(eng), "--db", str(dbp)])
            for lang in ("tr", "en"):
                main(["report", str(eng), "--lang", lang, "--formats", "pdf,docx"])
            files = sorted(p.name for p in (eng / "reports").iterdir())
            self.assertEqual(len(files), 4)
            pdf = next((eng / "reports").glob("*_TR.pdf")).read_bytes()
            self.assertTrue(pdf.startswith(b"%PDF"))
            d = __import__("docx").Document(str(next((eng / "reports").glob("*_EN.docx"))))
            text = "\n".join(p.text for p in d.paragraphs)
            self.assertIn("Executive Summary", text)


if __name__ == "__main__":
    unittest.main()
