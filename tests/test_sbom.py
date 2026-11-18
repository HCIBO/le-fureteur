import json
import tempfile
import unittest
from pathlib import Path

from scakit.analysis import detect_type
from scakit.collectors.sbom import parse_purl, scan_sbom
from scakit.models import make_purl


class PurlTest(unittest.TestCase):
    def test_round_trip(self):
        cases = [("Debian:12", "openssl", "3.0.11-1~deb12u2"), ("Ubuntu:22.04:LTS", "curl", "7.81.0-1ubuntu1.15"),
                 ("Ubuntu:23.10", "curl", "8.2.1-1ubuntu3"), ("Alpine:v3.19", "busybox", "1.36.1-r15"),
                 ("npm", "@babel/core", "7.1.0"), ("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1"),
                 ("Go", "github.com/gin-gonic/gin", "v1.9.0"), ("PyPI", "django", "3.2.0")]
        for eco, name, ver in cases:
            p = make_purl(eco, name, ver)
            self.assertEqual(parse_purl(p)[:3], (eco, name if eco != "PyPI" else "django", ver), p)

    def test_foreign_purls(self):
        self.assertEqual(parse_purl("pkg:deb/debian/libssl3@3.0.11?arch=amd64&distro=debian-12")[:2],
                         ("Debian:12", "libssl3"))
        self.assertEqual(parse_purl("pkg:rpm/redhat/openssl@1.1.1k-7.el8?distro=rhel-8.8")[:2], ("Red Hat:8", "openssl"))
        self.assertEqual(parse_purl("pkg:composer/symfony/http-kernel@v5.4.0")[:3],
                         ("Packagist", "symfony/http-kernel", "v5.4.0"))
        self.assertIsNone(parse_purl("bozuk"))


class SbomTest(unittest.TestCase):
    def write(self, doc, name):
        d = Path(tempfile.mkdtemp())
        p = d / name
        p.write_text(json.dumps(doc))
        return p

    def test_cyclonedx_nested_scope_direct(self):
        doc = {"bomFormat": "CycloneDX", "specVersion": "1.5",
               "metadata": {"component": {"bom-ref": "app", "name": "app"}},
               "components": [
                   {"bom-ref": "a", "type": "library", "name": "lodash", "version": "4.17.20",
                    "purl": "pkg:npm/lodash@4.17.20", "licenses": [{"license": {"id": "MIT"}}],
                    "components": [{"type": "library", "name": "inner", "purl": "pkg:npm/inner@1.0.0"}]},
                   {"bom-ref": "b", "type": "library", "name": "jest", "purl": "pkg:npm/jest@29.0.0", "scope": "excluded"},
                   {"type": "operating-system", "name": "debian"},
                   {"type": "library", "name": "noPurl", "version": "1"}],
               "dependencies": [{"ref": "app", "dependsOn": ["a"]}]}
        p = self.write(doc, "bom.json")
        self.assertEqual(detect_type(str(p)), "sbom")
        comps, notes = scan_sbom(p, "t")
        by = {c.name: c for c in comps}
        self.assertEqual(set(by), {"lodash", "inner", "jest", "noPurl"})
        self.assertEqual((by["lodash"].direct, by["lodash"].licenses), (True, ["MIT"]))
        self.assertEqual(by["jest"].scope, "dev")
        self.assertEqual(by["noPurl"].ecosystem, "generic")
        self.assertTrue(notes)

    def test_spdx_noassertion_and_root(self):
        doc = {"spdxVersion": "SPDX-2.3", "documentDescribes": ["SPDXRef-root"],
               "packages": [
                   {"SPDXID": "SPDXRef-root", "name": "myapp"},
                   {"SPDXID": "p1", "name": "requests", "versionInfo": "NOASSERTION",
                    "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:pypi/requests"}]},
                   {"SPDXID": "p2", "name": "curl", "versionInfo": "7.81.0-1ubuntu1.15", "licenseConcluded": "curl",
                    "externalRefs": [{"referenceType": "purl",
                                      "referenceLocator": "pkg:deb/ubuntu/curl@7.81.0-1ubuntu1.15?distro=ubuntu-22.04"}]}]}
        p = self.write(doc, "x.spdx.json")
        comps, _ = scan_sbom(p, "t")
        by = {c.name: c for c in comps}
        self.assertNotIn("myapp", by)
        self.assertIsNone(by["requests"].version)
        self.assertEqual((by["curl"].ecosystem, by["curl"].licenses), ("Ubuntu:22.04:LTS", ["curl"]))

    def test_not_sbom(self):
        p = self.write({"name": "x"}, "package.json")
        self.assertNotEqual(detect_type(str(p)), "sbom")
        with self.assertRaises(ValueError):
            scan_sbom(p)


if __name__ == "__main__":
    unittest.main()
