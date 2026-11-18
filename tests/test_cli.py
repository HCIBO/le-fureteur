import json
import os
import tempfile
import unittest
from pathlib import Path

from scakit.cli import detect_type, main
from scakit.vulndb.db import VulnDB

from .helpers import FIX, eco_range, osv, osv_zip


class CliTest(unittest.TestCase):
    def test_pipeline(self):
        with tempfile.TemporaryDirectory() as tmp:
            dbp = Path(tmp) / "db.sqlite"
            db = VulnDB(dbp)
            db.import_osv_zip(osv_zip([osv("GHSA-x", "npm", "lodash", eco_range(("introduced", "0"), ("fixed", "4.17.21")),
                                            severity="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")]), "t")
            db.close()
            eng = Path(tmp) / "eng"
            main(["init", str(eng), "--name", "Test İş", "--client", "Müşteri"])
            main(["add", str(eng), str(FIX / "app" / "web"), "--target", "web"])
            main(["add", str(eng), str(FIX / "image-oci.tar")])
            main(["match", str(eng), "--db", str(dbp)])
            main(["report", str(eng), "--formats", "html,md,cdx,csv,spdx"])
            inv = json.loads((eng / "inventory.json").read_text())
            self.assertGreaterEqual(len(inv["components"]), 8)
            self.assertEqual(len(inv["runs"]), 2)
            f = json.loads((eng / "findings.json").read_text())
            self.assertEqual([x["vuln_id"] for x in f["findings"]], ["GHSA-x"])
            reports = sorted(p.name for p in (eng / "reports").iterdir())
            self.assertEqual(len(reports), 5)
            spdx = json.loads(next((eng / "reports").glob("*.spdx.json")).read_text())
            self.assertEqual(spdx["spdxVersion"], "SPDX-2.3")
            bom = json.loads(next((eng / "reports").glob("*.cdx.json")).read_text())
            self.assertEqual(bom["specVersion"], "1.5")
            self.assertEqual(bom["vulnerabilities"][0]["recommendation"], "Upgrade to 4.17.21")
            html = next((eng / "reports").glob("*_EN.html")).read_text()
            self.assertIn("Remediation Plan", html)
            self.assertIn("lodash", html)
            main(["report", str(eng), "--lang", "tr", "--formats", "html"])
            self.assertIn("Düzeltme Planı", next((eng / "reports").glob("*_TR.html")).read_text())

    def test_suppress_and_spdx(self):
        from scakit.cli import apply_suppressions
        from scakit.models import Finding
        fs = [Finding("GHSA-1", "npm|lodash|4.17.20", "p", aliases=["CVE-1"]), Finding("GHSA-2", "npm|qs|6.7.0", "q")]
        keep, out = apply_suppressions(fs, [{"id": "CVE-1", "component": "lodash@4.17.20", "kind": "false-positive",
                                             "reason": "x", "date": "2026-01-01"}])
        self.assertEqual([f.vuln_id for f in keep], ["GHSA-2"])
        self.assertEqual(out[0]["suppression"]["kind"], "false-positive")
        keep, out = apply_suppressions(fs, [{"id": "*", "component": "qs", "kind": "accepted-risk", "reason": "y"}])
        self.assertEqual([f.vuln_id for f in keep], ["GHSA-1"])

    def test_detect(self):
        self.assertEqual(detect_type("https://x.com"), "web")
        self.assertEqual(detect_type(str(FIX / "image-docker.tar")), "image")
        self.assertEqual(detect_type(str(FIX / "app")), "source")
        self.assertEqual(detect_type(str(FIX / "app" / "api" / "app.war")), "archive")


if __name__ == "__main__":
    unittest.main()
