import tempfile
import unittest
from pathlib import Path

from scakit.cvss import cvss3_base_score
from scakit.matcher import match_inventory
from scakit.models import Component
from scakit.vulndb.db import VulnDB

from .helpers import eco_range, osv, osv_zip

CRIT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


class MatcherTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = VulnDB(Path(cls.tmp.name) / "t.sqlite")
        cls.db.import_osv_zip(osv_zip([
            osv("GHSA-1", "npm", "lodash", eco_range(("introduced", "0"), ("fixed", "4.17.21"), typ="SEMVER"),
                severity=CRIT, aliases=["CVE-2021-0001"]),
            osv("CVE-2021-0001", "npm", "lodash", eco_range(("introduced", "0"), ("fixed", "4.17.21"), typ="SEMVER")),
            osv("GHSA-2", "Maven", "org.x:lib", eco_range(("introduced", "2.0"), ("last_affected", "2.14.1")),
                db_sev="HIGH"),
            osv("GHSA-3", "Maven", "org.x:lib", eco_range(("introduced", "0"), ("fixed", "1.5"),
                                                        ("introduced", "2.0"), ("fixed", "2.12.2"))),
            osv("PYSEC-1", "PyPI", "Django", versions=["3.2.0", "3.2.1"], db_sev="MODERATE"),
            osv("GHSA-W", "PyPI", "django", eco_range(("introduced", "0")), withdrawn="2024-01-01"),
            osv("DSA-1", "Debian:11", "openssl", eco_range(("introduced", "0"), ("fixed", "1.1.1n-0+deb11u4")),
                upstream=["CVE-2023-0286"]),
            osv("DEBIAN-CVE-2023-0286", "Debian:12", "openssl", eco_range(("introduced", "0"), ("fixed", "3.0.8-1")),
                severity="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H", upstream=["CVE-2023-0286"]),
            osv("MAL-1", "npm", "evil-pkg", eco_range(("introduced", "0"))),
            osv("GHSA-4", "Maven", "org.apache.commons:commons-text",
                eco_range(("introduced", "1.5"), ("fixed", "1.10.0")), severity=CRIT),
        ]), "test")
        kev = b'{"vulnerabilities":[{"cveID":"CVE-2021-0001","dateAdded":"2024-01-01","knownRansomwareCampaignUse":"Known"}]}'
        cls.db.import_kev(kev)
        cls.db.import_epss(b"#model_version:v2025\ncve,epss,percentile\nCVE-2021-0001,0.97,0.999\n")

    @classmethod
    def tearDownClass(cls):
        cls.db.close()
        cls.tmp.cleanup()

    def ids(self, eco, name, ver):
        fs, _ = match_inventory([Component(eco, name, ver)], self.db)
        return {f.vuln_id: f for f in fs}

    def test_semver_fixed(self):
        hit = self.ids("npm", "lodash", "4.17.20")
        self.assertEqual(set(hit), {"GHSA-1"})
        f = hit["GHSA-1"]
        self.assertIn("CVE-2021-0001", f.aliases)
        self.assertTrue(f.kev and f.kev_ransomware)
        self.assertAlmostEqual(f.epss, 0.97)
        self.assertEqual((f.severity, f.cvss_score, f.upgrade_to), ("CRITICAL", 9.8, "4.17.21"))
        self.assertEqual(self.ids("npm", "lodash", "4.17.21"), {})

    def test_last_affected_and_multi_range(self):
        self.assertEqual(set(self.ids("Maven", "org.x:lib", "2.14.1")), {"GHSA-2"})
        self.assertEqual(set(self.ids("Maven", "org.x:lib", "2.15.0")), set())
        self.assertEqual(set(self.ids("Maven", "org.x:lib", "2.10")), {"GHSA-2", "GHSA-3"})
        self.assertEqual(set(self.ids("Maven", "org.x:lib", "1.6")), set())
        self.assertEqual(set(self.ids("Maven", "org.x:lib", "1.0")), {"GHSA-3"})
        self.assertEqual(self.ids("Maven", "org.x:lib", "2.14.1")["GHSA-2"].severity, "HIGH")

    def test_versions_list_name_normalization_withdrawn(self):
        hit = self.ids("PyPI", "django", "3.2.1")
        self.assertEqual(set(hit), {"PYSEC-1"})
        self.assertEqual(hit["PYSEC-1"].severity, "MEDIUM")
        self.assertEqual(self.ids("PyPI", "Django", "3.2.2"), {})

    def test_distro_release_and_upstream_severity(self):
        hit = self.ids("Debian:11", "openssl", "1.1.1n-0+deb11u3")
        self.assertEqual(set(hit), {"DSA-1"})
        self.assertEqual(hit["DSA-1"].severity, "HIGH")
        self.assertIn("CVE-2023-0286", hit["DSA-1"].aliases)

    def test_malicious(self):
        f = self.ids("npm", "evil-pkg", "1.0.0")["MAL-1"]
        self.assertTrue(f.malicious)
        self.assertEqual(f.severity, "CRITICAL")

    def test_groupid_resolution(self):
        fs, notes = match_inventory([Component("Maven", "commons-text", "1.9", confidence="medium")], self.db)
        self.assertEqual([f.vuln_id for f in fs], ["GHSA-4"])
        self.assertEqual(fs[0].confidence, "medium")

    def test_cvss(self):
        self.assertEqual(cvss3_base_score(CRIT), 9.8)
        self.assertEqual(cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10.0)
        self.assertEqual(cvss3_base_score("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"), 1.8)
        self.assertEqual(cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N"), 6.4)


if __name__ == "__main__":
    unittest.main()
