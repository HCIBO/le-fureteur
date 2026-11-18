from __future__ import annotations

import json
import re
from pathlib import Path

from .models import Component, base_ecosystem

OS_ECOS = {"Debian", "Ubuntu", "Alpine", "Red Hat", "Rocky Linux", "AlmaLinux", "Wolfi", "Chainguard", "SUSE"}

CATEGORY = {}
CANON = {}
for ids, cat in [
    (["MIT", "MIT-0", "Apache-2.0", "Apache-1.1", "BSD-2-Clause", "BSD-3-Clause", "BSD-4-Clause", "0BSD", "ISC",
      "Zlib", "Unlicense", "CC0-1.0", "BSL-1.0", "PSF-2.0", "Python-2.0", "WTFPL", "OpenSSL", "X11", "PostgreSQL",
      "NCSA", "Artistic-2.0", "Ruby", "BlueOak-1.0.0", "CC-BY-4.0", "CC-BY-3.0", "UPL-1.0", "Unicode-DFS-2016",
      "Unicode-3.0", "curl", "libpng", "IJG", "JSON", "LicenseRef-PublicDomain", "LicenseRef-BSD", "Beerware",
      "HPND", "MirOS", "AFL-2.1", "AFL-3.0", "Zope-2.1", "W3C", "OFL-1.1", "Python-2.0.1", "bzip2-1.0.6"],
     "permissive"),
    (["LGPL-2.0-only", "LGPL-2.0-or-later", "LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-3.0-only",
      "LGPL-3.0-or-later", "MPL-1.1", "MPL-2.0", "EPL-1.0", "EPL-2.0", "CDDL-1.0", "CDDL-1.1", "CPL-1.0",
      "MS-RL", "CC-BY-SA-4.0", "CC-BY-SA-3.0", "GPL-2.0-with-classpath-exception", "LGPL", "ErlPL-1.1",
      "LicenseRef-GPL-with-exception"], "weak-copyleft"),
    (["GPL-1.0-only", "GPL-1.0-or-later", "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later",
      "EUPL-1.1", "EUPL-1.2", "OSL-3.0", "QPL-1.0", "Sleepycat", "LicenseRef-GPL"], "strong-copyleft"),
    (["AGPL-1.0-only", "AGPL-3.0-only", "AGPL-3.0-or-later", "SSPL-1.0", "RPL-1.5", "LicenseRef-AGPL"],
     "network-copyleft"),
    (["BUSL-1.1", "Elastic-2.0", "CC-BY-NC-4.0", "CC-BY-NC-SA-4.0", "CC-BY-ND-4.0", "LicenseRef-Commons-Clause",
      "LicenseRef-Proprietary", "PolyForm-Noncommercial-1.0.0", "JSON-NoEvil"], "restrictive"),
]:
    for i in ids:
        CATEGORY[i.lower()] = cat
        CANON[i.lower()] = i

ALIASES = {
    "mit": "MIT", "mit license": "MIT", "the mit license": "MIT", "mit/x11": "MIT", "expat": "MIT",
    "apache 2": "Apache-2.0", "apache 2.0": "Apache-2.0", "apache2": "Apache-2.0", "apache license 2.0": "Apache-2.0",
    "apache license version 2.0": "Apache-2.0", "apache license v2.0": "Apache-2.0",
    "the apache software license version 2.0": "Apache-2.0", "the apache license version 2.0": "Apache-2.0",
    "apache software license": "Apache-2.0", "apache software license 2.0": "Apache-2.0", "asl 2.0": "Apache-2.0",
    "apache-2": "Apache-2.0", "apache": "Apache-2.0", "apache public license 2.0": "Apache-2.0",
    "bsd": "LicenseRef-BSD", "bsd license": "LicenseRef-BSD", "new bsd license": "BSD-3-Clause",
    "new bsd": "BSD-3-Clause", "bsd 3-clause": "BSD-3-Clause", "3-clause bsd license": "BSD-3-Clause",
    "bsd-3": "BSD-3-Clause", "revised bsd license": "BSD-3-Clause", "modified bsd license": "BSD-3-Clause",
    "the bsd license": "LicenseRef-BSD", "simplified bsd": "BSD-2-Clause", "bsd 2-clause": "BSD-2-Clause",
    "2-clause bsd license": "BSD-2-Clause", "isc license": "ISC", "isc license (iscl)": "ISC",
    "gpl": "LicenseRef-GPL", "gplv2": "GPL-2.0-only", "gplv2+": "GPL-2.0-or-later", "gpl-2": "GPL-2.0-only",
    "gpl-2.0": "GPL-2.0-only", "gpl v2": "GPL-2.0-only", "gnu gpl v2": "GPL-2.0-only",
    "gnu general public license v2": "GPL-2.0-only", "gnu general public license version 2": "GPL-2.0-only",
    "gplv3": "GPL-3.0-only", "gplv3+": "GPL-3.0-or-later", "gpl-3": "GPL-3.0-only", "gpl-3.0": "GPL-3.0-only",
    "gpl v3": "GPL-3.0-only", "gnu general public license v3": "GPL-3.0-only",
    "gnu general public license v3 (gplv3)": "GPL-3.0-only", "gnu general public license v2 (gplv2)": "GPL-2.0-only",
    "gnu general public license v3 or later (gplv3+)": "GPL-3.0-or-later",
    "gnu general public license v2 or later (gplv2+)": "GPL-2.0-or-later",
    "gnu general public license v3 or later": "GPL-3.0-or-later",
    "gnu general public license v2 or later": "GPL-2.0-or-later",
    "gnu affero general public license v3 or later": "AGPL-3.0-or-later",
    "gnu lesser general public license v3": "LGPL-3.0-only", "gnu lesser general public license v2": "LGPL-2.0-only",
    "gnu lesser general public license v3 or later": "LGPL-3.0-or-later",
    "gnu lesser general public license v2 or later": "LGPL-2.0-or-later",
    "gnu library or lesser general public license": "LGPL", "mozilla public license 1.1": "MPL-1.1",
    "the unlicense": "Unlicense", "isc license": "ISC",
    "gpl-2.0+": "GPL-2.0-or-later", "gpl-3.0+": "GPL-3.0-or-later", "gplv2 with exceptions": "LicenseRef-GPL-with-exception",
    "gpl2 with classpath exception": "GPL-2.0-with-classpath-exception",
    "gnu general public license version 2 with the classpath exception": "GPL-2.0-with-classpath-exception",
    "cddl + gplv2 with classpath exception": "CDDL-1.1",
    "lgpl": "LGPL", "lgplv2": "LGPL-2.0-only", "lgplv2+": "LGPL-2.0-or-later", "lgplv2.1": "LGPL-2.1-only",
    "lgplv2.1+": "LGPL-2.1-or-later", "lgplv3": "LGPL-3.0-only", "lgplv3+": "LGPL-3.0-or-later",
    "lgpl-2.1": "LGPL-2.1-only", "lgpl-3.0": "LGPL-3.0-only", "lgpl-2.1+": "LGPL-2.1-or-later",
    "gnu lesser general public license": "LGPL", "gnu lesser general public license v2.1": "LGPL-2.1-only",
    "gnu lesser general public license v3 (lgplv3)": "LGPL-3.0-only",
    "gnu library or lesser general public license (lgpl)": "LGPL",
    "lgplv2+ with exceptions": "LGPL-2.0-or-later",
    "agpl": "LicenseRef-AGPL", "agplv3": "AGPL-3.0-only", "agplv3+": "AGPL-3.0-or-later", "agpl-3.0": "AGPL-3.0-only",
    "gnu affero general public license v3": "AGPL-3.0-only",
    "gnu affero general public license v3 or later (agplv3+)": "AGPL-3.0-or-later",
    "mpl 2.0": "MPL-2.0", "mplv2.0": "MPL-2.0", "mozilla public license 2.0": "MPL-2.0",
    "mozilla public license 2.0 (mpl 2.0)": "MPL-2.0", "mpl-2": "MPL-2.0", "mpl 1.1": "MPL-1.1",
    "epl 1.0": "EPL-1.0", "eclipse public license 1.0": "EPL-1.0", "eclipse public license - v 1.0": "EPL-1.0",
    "eclipse public license 2.0": "EPL-2.0", "eclipse public license - v 2.0": "EPL-2.0", "epl 2.0": "EPL-2.0",
    "cddl": "CDDL-1.0", "cddl 1.1": "CDDL-1.1", "common development and distribution license": "CDDL-1.0",
    "unlicense": "Unlicense", "the unlicense": "Unlicense", "the unlicense (unlicense)": "Unlicense",
    "public domain": "LicenseRef-PublicDomain", "cc0": "CC0-1.0", "cc0 1.0": "CC0-1.0", "zlib": "Zlib",
    "zlib/libpng": "Zlib", "psf": "PSF-2.0", "python software foundation license": "PSF-2.0", "psfl": "PSF-2.0",
    "boost": "BSL-1.0", "boost software license 1.0": "BSL-1.0", "wtfpl": "WTFPL", "openssl": "OpenSSL",
    "sspl": "SSPL-1.0", "server side public license": "SSPL-1.0", "busl-1.1": "BUSL-1.1",
    "business source license 1.1": "BUSL-1.1", "elastic license 2.0": "Elastic-2.0",
    "commercial": "LicenseRef-Proprietary", "proprietary": "LicenseRef-Proprietary",
    "other/proprietary license": "LicenseRef-Proprietary", "eupl 1.2": "EUPL-1.2", "eupl-1.2": "EUPL-1.2",
    "artistic 2.0": "Artistic-2.0", "perl": "Artistic-1.0-Perl", "ruby": "Ruby", "bsd-like": "LicenseRef-BSD",
}


def _key(s: str) -> str:
    s = s.strip().lower().strip("[] ")
    if not s.startswith("("):
        s = re.sub(r"\s*\([^)]*\)?\s*$", "", s)
    s = s.strip("() ")
    s = re.sub(r"[,;]", "", s)
    s = re.sub(r"\s+", " ", s)
    return s


def normalize(text: str) -> list[str]:
    if not text:
        return []
    text = text.strip()
    if text.startswith("http"):
        if "apache.org/licenses/LICENSE-2.0" in text:
            return ["Apache-2.0"]
        if "opensource.org/licenses/MIT" in text or "mit-license" in text:
            return ["MIT"]
        return ["LicenseRef-" + text[:60]]
    k = _key(text)
    if k in ALIASES:
        return [ALIASES[k]]
    if k in CANON:
        return [CANON[k]]
    parts = [p for p in re.split(r"\s+(?:or|and|with|/)\s+|\s*\|\s*|\s*/\s*", text, flags=re.I) if p.strip()]
    if len(parts) > 1:
        out = []
        for p in parts:
            if _key(p) in ("exceptions", "classpath-exception-2.0", "llvm-exception"):
                continue
            for n in normalize(p):
                if n not in out:
                    out.append(n)
        return out
    return ["LicenseRef-" + text[:60]]


def category(spdx: str) -> str:
    return CATEGORY.get(spdx.lower(), "unknown")


RISK_ORDER = {"permissive": 0, "unknown": 1, "weak-copyleft": 2, "strong-copyleft": 3, "network-copyleft": 4,
              "restrictive": 5}
DEFAULT_POLICY = {"permissive": "allowed", "weak-copyleft": "review", "strong-copyleft": "review",
                  "network-copyleft": "denied", "restrictive": "denied", "unknown": "unknown"}


def load_policy(path: Path) -> dict:
    if path.exists():
        doc = json.loads(path.read_text())
        return {"allowed": {x.lower() for x in doc.get("allowed", [])},
                "denied": {x.lower() for x in doc.get("denied", [])},
                "review": {x.lower() for x in doc.get("review", [])}, "custom": True}
    return {"allowed": set(), "denied": set(), "review": set(), "custom": False}


def decide(licenses: list[str], policy: dict) -> tuple[str, str, list[str]]:
    ids = []
    for lic in licenses:
        for n in normalize(lic):
            if n not in ids:
                ids.append(n)
    if not ids:
        return "unknown", "unknown", []
    or_expr = any(" or " in lic.lower() or "/" in lic for lic in licenses)
    decisions = []
    for i in ids:
        cat = category(i)
        if i.lower() in policy["denied"]:
            d = "denied"
        elif i.lower() in policy["allowed"]:
            d = "allowed"
        elif i.lower() in policy["review"]:
            d = "review"
        else:
            d = DEFAULT_POLICY[cat]
        decisions.append((d, cat))
    rank = {"allowed": 0, "unknown": 1, "review": 2, "denied": 3}
    pick = min if or_expr else max
    d, cat = pick(decisions, key=lambda x: (rank[x[0]], RISK_ORDER[x[1]]))
    return d, cat, ids


def evaluate(components: list[Component], policy: dict) -> list[dict]:
    from .supplychain import PUBLIC_REGISTRIES
    rows = []
    for c in components:
        if base_ecosystem(c.ecosystem) in OS_ECOS or base_ecosystem(c.ecosystem) == "generic":
            continue
        if c.registry and c.registry not in PUBLIC_REGISTRIES:
            continue
        d, cat, ids = decide(c.licenses, policy)
        rows.append({"component": c, "decision": d, "category": cat, "spdx": ids})
    return rows
