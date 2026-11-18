import json
import tempfile
import unittest
from pathlib import Path

from scakit.collectors.whitebox import scan_directory
from scakit.licenses import decide, evaluate, load_policy, normalize
from scakit.models import Component
from scakit.supplychain import offline_checks, read_internal_list

from .helpers import FIX


class LicenseTest(unittest.TestCase):
    def test_normalize(self):
        cases = {"Apache License, Version 2.0": ["Apache-2.0"], "ASL 2.0": ["Apache-2.0"],
                 "GNU General Public License v2 (GPLv2)": ["GPL-2.0-only"], "MIT OR Apache-2.0": ["MIT", "Apache-2.0"],
                 "LGPLv2+ and GPLv2+": ["LGPL-2.0-or-later", "GPL-2.0-or-later"],
                 "https://www.apache.org/licenses/LICENSE-2.0.txt": ["Apache-2.0"], "BSD-3-Clause": ["BSD-3-Clause"]}
        for text, exp in cases.items():
            self.assertEqual(normalize(text), exp, text)
        self.assertTrue(normalize("Foo License")[0].startswith("LicenseRef-"))

    def test_policy(self):
        default = load_policy(Path("/yok"))
        self.assertEqual(decide(["MIT"], default)[0], "allowed")
        self.assertEqual(decide(["MIT OR GPL-3.0-only"], default)[0], "allowed")
        self.assertEqual(decide(["GPL-2.0-only"], default)[0], "review")
        self.assertEqual(decide(["AGPL-3.0-only"], default)[0], "denied")
        self.assertEqual(decide([], default)[0], "unknown")
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "p.json"
            p.write_text(json.dumps({"allowed": ["LGPL-2.1-only"], "denied": ["MIT"], "review": []}))
            custom = load_policy(p)
        self.assertEqual(decide(["LGPL-2.1-only"], custom)[0], "allowed")
        self.assertEqual(decide(["MIT"], custom)[0], "denied")
        rows = evaluate([Component("npm", "a", "1", licenses=["MIT"]), Component("Debian:12", "glibc", "2", licenses=["GPL"]),
                         Component("npm", "int", "1", licenses=["UNLICENSED"]),
                         Component("npm", "pub", "1", licenses=["AGPL-3.0"])], default)
        rows[0:0] = []
        comps = {r["component"].name: r["decision"] for r in rows}
        self.assertEqual(comps, {"a": "allowed", "int": "unknown", "pub": "denied"})


class SupplyChainTest(unittest.TestCase):
    def test_offline(self):
        comps, _ = scan_directory(FIX / "app" / "web")
        internal = read_internal_list(str(FIX / "internal-packages.csv"))
        self.assertEqual(internal, [("npm", "firma-odeme-sdk-xq7")])
        notes = offline_checks(comps, internal)
        kinds = sorted((k, loc.split("@")[0]) for k, loc, _ in notes)
        self.assertEqual(kinds, [("internal-package", "firma-odeme-sdk-xq7"), ("private-registry", "firma-odeme-sdk-xq7"),
                                 ("private-registry", "minimist")])
        self.assertEqual({c.name: c.registry for c in comps if c.name == "lodash" and c.version}, {"lodash": "registry.npmjs.org"})
        lic = load_policy(Path("/yok"))
        names = {r["component"].name for r in evaluate(comps, lic)}
        self.assertNotIn("firma-odeme-sdk-xq7", names)


if __name__ == "__main__":
    unittest.main()
