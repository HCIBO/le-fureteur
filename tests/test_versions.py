import unittest

from scakit.versions import (apk_cmp, composer_cmp, dpkg_cmp, gem_cmp, maven_cmp, nuget_cmp, pep440_cmp,
                             rpm_cmp, semver_cmp)


class Ordering(unittest.TestCase):
    def assertOrder(self, cmp, seq):
        for a, b in zip(seq, seq[1:]):
            if isinstance(a, tuple):
                a = a[-1]
            if isinstance(b, tuple):
                for x, y in zip(b, b[1:]):
                    self.assertEqual(cmp(x, y), 0, f"{x} == {y}")
                b0 = b[0]
            else:
                b0 = b
            self.assertEqual(cmp(a, b0), -1, f"{a} < {b0}")
            self.assertEqual(cmp(b0, a), 1, f"{b0} > {a}")

    def test_semver(self):
        self.assertOrder(semver_cmp, ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
                                      "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", ("1.0.0", "v1.0.0"),
                                      "1.0.1", "4.17.20", "4.17.21", "10.0.0"])
        self.assertEqual(semver_cmp("0.0.0-20210101-abcdef", "0.0.1"), -1)

    def test_pep440(self):
        self.assertOrder(pep440_cmp, ["1.0.dev1", "1.0a1", "1.0b2", "1.0rc1", ("1.0", "1.0.0"), "1.0.post1",
                                      "3.2.9", "3.2.10"])

    def test_maven(self):
        self.assertOrder(maven_cmp, ["1-alpha1", "1-alpha2", "1-beta", "1-milestone1", ("1-rc1", "1-cr1"),
                                     "1-snapshot", ("1", "1.0", "1.0.0", "1-ga", "1-final", "1.0.0.RELEASE"),
                                     "1-sp1", "1.0.1", "1.1"])
        self.assertOrder(maven_cmp, ["2.14.1", "2.15.0-rc1", "2.15.0", "2.16.0", "2.17.0"])
        self.assertOrder(maven_cmp, ["2.12.7", "2.12.7.1", "2.13.0"])
        self.assertOrder(maven_cmp, ["5.3.9", "5.3.20", "5.3.27"])
        self.assertEqual(maven_cmp("1.0-alpha-1", "1.0"), -1)
        self.assertEqual(maven_cmp("1.0.0-M1", "1.0.0-RC1"), -1)

    def test_nuget(self):
        self.assertOrder(nuget_cmp, ["1.0.0-alpha", ("1.0.0-Beta", "1.0.0-beta"), "1.0.0", "1.0.0.1",
                                     "12.0.3", "13.0.1"])

    def test_gem(self):
        self.assertOrder(gem_cmp, ["1.0.a", "1.0.b1", ("1.0", "1.0.0"), "6.1.7", "6.1.7.3", "7.0.0"])

    def test_composer(self):
        self.assertOrder(composer_cmp, ["1.0.0-dev", "1.0.0-alpha1", "1.0.0-beta", "1.0.0-RC1",
                                        ("1.0.0", "v1.0", "1.0.0.0"), "1.0.0-p1", "5.4.9", "5.4.10"])

    def test_dpkg(self):
        self.assertOrder(dpkg_cmp, ["1.0~rc1", "1.0", "1.0-1", "1.2.3-1", "1.2.3-2", "2.0", "1:0.9"])
        self.assertOrder(dpkg_cmp, ["2.36-9+deb12u3", "2.36-9+deb12u4"])
        self.assertOrder(dpkg_cmp, ["3.0.11-1~deb12u1", "3.0.11-1~deb12u2", "3.0.11-1"])
        self.assertOrder(dpkg_cmp, ["1.1.1n-0+deb11u4", "1.1.1n-0+deb11u5"])

    def test_rpm(self):
        self.assertOrder(rpm_cmp, ["1.0~rc1", "1.0", "1.0.1", "1.0.10"])
        self.assertOrder(rpm_cmp, ["2.28-225.el8", "2.28-225.el8_9"])
        self.assertOrder(rpm_cmp, ["0:1.1.1k-9.el8", "0:1.1.1k-12.el8_9", "1:1.0"])
        self.assertEqual(rpm_cmp("1.0.2k-19.el7", "1:1.0.2k-21.el7"), -1)
        self.assertEqual(rpm_cmp("1.0.2k-21.el7", "1:1.0.2k-19.el7"), 1)

    def test_apk(self):
        self.assertOrder(apk_cmp, ["1.2_rc1", ("1.2", "1.2-r0"), "1.2-r1", "1.2_p1", "1.2a", "1.2.1"])
        self.assertOrder(apk_cmp, ["3.0.8-r0", "3.0.10-r0", "3.1.0-r0"])


if __name__ == "__main__":
    unittest.main()
