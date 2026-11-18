import io
import os
import tarfile
import tempfile
import unittest
from pathlib import Path


class BackupTest(unittest.TestCase):
    def _env(self, d):
        os.environ["SCAKIT_DATA_DIR"] = d
        os.environ.pop("SCAKIT_DATABASE_URL", None)
        os.environ.pop("SCAKIT_SECRET_KEY", None)
        from scakit.server import config, db
        config.get_config.cache_clear()
        db.reset_for_tests()
        db.init_db()

    def tearDown(self):
        from scakit.server import db
        db.reset_for_tests()

    def test_roundtrip_encrypted(self):
        from scakit.server import backup as bk
        from scakit.server import settings_store
        from scakit.server.db import SessionLocal
        from scakit.server.models import Organization, User
        a, b, out = tempfile.mkdtemp(), tempfile.mkdtemp(), Path(tempfile.mkdtemp()) / "y.lfbk"
        self._env(a)
        s = SessionLocal()
        s.add(User(email="x@y.z", password_hash="h", role="admin"))
        s.add(Organization(name="Örnek A.Ş.", allowed_domains=["*.ornek.com"]))
        s.commit()
        settings_store.set_value(s, "nvd_api_key", "gizli-123")
        s.close()
        up = Path(a) / "targets" / "1"
        up.mkdir(parents=True)
        (up / "kod.zip").write_bytes(b"PK..")
        bk.backup(out, "parola-123", log=lambda *_: None)
        self.assertTrue(bk.is_encrypted(out))
        self.assertNotIn(b"gizli-123", out.read_bytes())
        self.assertNotIn("Örnek".encode(), out.read_bytes())
        self._env(b)
        with self.assertRaises(bk.BackupError):
            bk.restore(out, "yanlis", log=lambda *_: None)
        bk.restore(out, "parola-123", log=lambda *_: None)
        from scakit.server import config
        config.get_config.cache_clear()
        s = SessionLocal()
        self.assertEqual(s.query(Organization).one().allowed_domains, ["*.ornek.com"])
        self.assertEqual(settings_store.get(s, "nvd_api_key"), "gizli-123")
        self.assertTrue((Path(b) / "targets" / "1" / "kod.zip").exists())
        with self.assertRaises(bk.BackupError):
            bk.restore(out, "parola-123", log=lambda *_: None)
        s.close()

    def test_tamper_and_traversal(self):
        from scakit.server import backup as bk
        a, out = tempfile.mkdtemp(), Path(tempfile.mkdtemp()) / "y.lfbk"
        self._env(a)
        bk.backup(out, "p", log=lambda *_: None)
        data = bytearray(out.read_bytes())
        data[-5] ^= 0xFF
        bad = out.with_name("bozuk.lfbk")
        bad.write_bytes(bytes(data))
        with self.assertRaises(bk.BackupError):
            bk.restore(bad, "p", log=lambda *_: None)
        cut = out.with_name("kesik.lfbk")
        cut.write_bytes(out.read_bytes()[:-40])
        with self.assertRaises(bk.BackupError):
            bk.restore(cut, "p", log=lambda *_: None)
        evil = Path(tempfile.mkdtemp()) / "evil.lfbk"
        with tarfile.open(evil, "w:gz") as tf:
            def add(name, data=b"x", typ=tarfile.REGTYPE, link=""):
                ti = tarfile.TarInfo(name)
                ti.type, ti.linkname, ti.size = typ, link, len(data) if typ == tarfile.REGTYPE else 0
                tf.addfile(ti, io.BytesIO(data) if typ == tarfile.REGTYPE else None)
            add("manifest.json", b'{"tables": {}, "created_at": "x", "version": "0"}')
            add("files/../../escape.txt")
            add("files/scans/../../../escape2.txt")
            add("files/targets/link", typ=tarfile.SYMTYPE, link="/etc/passwd")
            add("files/config.py")
        self._env(tempfile.mkdtemp())
        from scakit.server.config import get_config
        root = get_config().data_dir
        bk.restore(evil, None, log=lambda *_: None)
        self.assertFalse((root.parent / "escape.txt").exists())
        self.assertFalse((root / "targets" / "link").exists())
        self.assertFalse((root / "config.py").exists())


if __name__ == "__main__":
    unittest.main()
