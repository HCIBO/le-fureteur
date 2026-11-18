from __future__ import annotations

import csv
import time
from datetime import datetime, timezone
from urllib.parse import quote

from .models import Component, base_ecosystem

PUBLIC_REGISTRIES = {"registry.npmjs.org", "registry.yarnpkg.com", "registry.npmmirror.com", "pypi.org",
                     "files.pythonhosted.org", "pypi.python.org", "repo1.maven.org", "repo.maven.apache.org",
                     "api.nuget.org", "proxy.golang.org", "crates.io", "rubygems.org", "pub.dev", "pub.dartlang.org"}
DEPSDEV = {"npm": "npm", "PyPI": "pypi", "Maven": "maven", "Go": "go", "crates.io": "cargo", "NuGet": "nuget"}
STALE_DAYS = 730


def read_internal_list(path: str) -> list[tuple[str, str]]:
    out = []
    with open(path, newline="", encoding="utf-8-sig") as f:
        sample = f.read(2048)
        f.seek(0)
        delim = ";" if sample.count(";") >= sample.count(",") else ","
        for row in csv.reader(f, delimiter=delim):
            if not row or row[0].strip().lower() in ("ekosistem", "ecosystem") or len(row) < 2:
                continue
            eco = {"npm": "npm", "pypi": "PyPI", "maven": "Maven", "nuget": "NuGet"}.get(row[0].strip().lower(),
                                                                                         row[0].strip())
            name, scope = row[1].strip(), (row[2].strip() if len(row) > 2 else "")
            if eco == "npm" and scope.startswith("@") and not name.startswith("@"):
                name = f"{scope}/{name}"
            elif eco == "Maven" and scope and ":" not in name:
                name = f"{scope}:{name}"
            out.append((eco, name))
    return out


def offline_checks(components: list[Component], internal: list[tuple[str, str]] | None = None) -> list[tuple]:
    notes = []
    for c in components:
        if c.registry and c.registry not in PUBLIC_REGISTRIES:
            notes.append(("private-registry", f"{c.name}@{c.version}",
                          f"{base_ecosystem(c.ecosystem)} · {c.registry}"))
    names = {(base_ecosystem(c.ecosystem), c.name.lower()) for c in components}
    for eco, name in internal or []:
        if (eco, name.lower()) in names:
            notes.append(("internal-package", name, eco))
    return notes


def _get(session, url):
    for attempt in range(3):
        try:
            r = session.get(url, timeout=20)
        except Exception:
            time.sleep(1 + attempt)
            continue
        if r.status_code == 429:
            time.sleep(3 * (attempt + 1))
            continue
        return r
    return None


def public_status(session, eco: str, name: str) -> str:
    if eco == "npm":
        url = "https://registry.npmjs.org/" + quote(name, safe="@")
    elif eco == "PyPI":
        url = f"https://pypi.org/pypi/{quote(name)}/json"
    else:
        return "unknown"
    r = _get(session, url)
    if r is None:
        return "unknown"
    return "absent" if r.status_code == 404 else "present" if r.status_code == 200 else "unknown"


def enrich_online(components: list[Component], internal=None, log=print, delay: float = 0.15) -> list[tuple]:
    import requests

    s = requests.Session()
    s.headers["User-Agent"] = "scakit/0.1 (software composition analysis)"
    notes = []
    now = datetime.now(timezone.utc)
    done = 0
    for c in components:
        system = DEPSDEV.get(base_ecosystem(c.ecosystem))
        if not system or not c.version or (base_ecosystem(c.ecosystem) == "Maven" and ":" not in c.name):
            continue
        name = quote(c.name, safe="")
        ver = ("v" + c.version) if system == "go" and not c.version.startswith("v") else c.version
        if not c.licenses:
            r = _get(s, f"https://api.deps.dev/v3/systems/{system}/packages/{name}/versions/{quote(ver, safe='')}")
            if r is not None and r.status_code == 200:
                c.licenses = [x for x in r.json().get("licenses", []) if x and x != "non-standard"]
                c.extra["license_source"] = "deps.dev"
            time.sleep(delay)
        r = _get(s, f"https://api.deps.dev/v3/systems/{system}/packages/{name}")
        time.sleep(delay)
        if r is None or r.status_code != 200:
            continue
        versions = r.json().get("versions", [])
        dates = [v.get("publishedAt") for v in versions if v.get("publishedAt")]
        default = next((v for v in versions if v.get("isDefault")), None)
        if dates:
            latest = max(dates)
            c.extra["latest_release"] = latest[:10]
            age = (now - datetime.fromisoformat(latest.replace("Z", "+00:00"))).days
            if age > STALE_DAYS:
                notes.append(("stale-package", f"{c.name}@{c.version}", f"son sürüm {latest[:10]} ({age // 365} yıl)"))
        if default:
            c.extra["latest_version"] = default["versionKey"]["version"]
        cur = next((v for v in versions if v["versionKey"]["version"] == ver), None)
        if cur and cur.get("isDeprecated"):
            c.extra["deprecated"] = cur.get("deprecatedReason") or True
            notes.append(("deprecated-package", f"{c.name}@{c.version}", str(cur.get("deprecatedReason") or "")[:120]))
        done += 1
        if done % 25 == 0:
            log(f"  {done} packages enriched")
    check = {(base_ecosystem(c.ecosystem), c.name) for c in components if c.registry and c.registry not in PUBLIC_REGISTRIES}
    check |= set(internal or [])
    for eco, name in sorted(check):
        st = public_status(s, eco, name)
        time.sleep(delay)
        if st == "absent":
            notes.append(("dependency-confusion", name, f"{eco}: public registry'de bu ad boşta — saldırgan kaydedebilir"))
        elif st == "present":
            notes.append(("dependency-confusion", name, f"{eco}: public registry'de aynı adda paket var — "
                                                        "çözümleme sırası / scope yapılandırması doğrulanmalı"))
    s.close()
    log(f"  {done} packages enriched, {len(check)} names checked in public registries")
    return notes
