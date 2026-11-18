from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import unquote

from ..models import Component, Evidence

PURL_TO_ECO = {
    "npm": "npm", "pypi": "PyPI", "maven": "Maven", "golang": "Go", "nuget": "NuGet", "composer": "Packagist",
    "cargo": "crates.io", "gem": "RubyGems", "pub": "Pub", "swift": "SwiftURL", "cocoapods": "CocoaPods",
    "deb": "Debian", "apk": "Alpine", "rpm": "Red Hat",
}


def sniff(path: str | Path) -> str | None:
    try:
        head = Path(path).read_bytes()[:4096].decode("utf-8", "ignore")
    except OSError:
        return None
    if '"bomFormat"' in head and "CycloneDX" in head:
        return "cyclonedx"
    if '"spdxVersion"' in head:
        return "spdx"
    if "<bom" in head and "cyclonedx.org/schema/bom" in head:
        return "cyclonedx-xml"
    if re.search(r"^SPDXVersion:\s*SPDX-", head, re.M):
        return "spdx-tv"
    return None


def _cyclonedx_xml(text: str) -> dict:
    from ..safeio import UnsafeInput, xml_fromstring
    try:
        root = xml_fromstring(text)
    except UnsafeInput as ex:
        raise ValueError(f"SBOM XML: {ex}") from ex
    tag = lambda el: el.tag.rsplit("}", 1)[-1]

    def kid(el, name):
        return next((c for c in el if tag(c) == name), None)

    def text_of(el, name):
        c = kid(el, name)
        return (c.text or "").strip() if c is not None and c.text else None

    def comp(el):
        lic = []
        ls = kid(el, "licenses")
        for item in (ls if ls is not None else []):
            if tag(item) == "license":
                lid = text_of(item, "id") or text_of(item, "name")
                if lid:
                    lic.append({"license": {"id": lid}})
            elif tag(item) == "expression" and item.text:
                lic.append({"expression": item.text.strip()})
        sub = kid(el, "components")
        return {"type": el.get("type"), "bom-ref": el.get("bom-ref"), "name": text_of(el, "name"),
                "group": text_of(el, "group"), "version": text_of(el, "version"), "purl": text_of(el, "purl"),
                "scope": text_of(el, "scope"), "licenses": lic,
                "components": [comp(c) for c in sub if tag(c) == "component"] if sub is not None else []}
    comps = kid(root, "components")
    meta = kid(root, "metadata")
    mc = kid(meta, "component") if meta is not None else None
    deps = kid(root, "dependencies")
    return {"bomFormat": "CycloneDX",
            "metadata": {"component": {"bom-ref": mc.get("bom-ref")}} if mc is not None else {},
            "components": [comp(c) for c in comps if tag(c) == "component"] if comps is not None else [],
            "dependencies": [{"ref": d.get("ref"), "dependsOn": [x.get("ref") for x in d if tag(x) == "dependency"]}
                             for d in (deps if deps is not None else []) if tag(d) == "dependency"]}


def _spdx_tag_value(text: str) -> dict:
    packages, cur, describes = [], None, []
    for line in text.splitlines():
        key, sep, val = line.partition(":")
        if not sep:
            continue
        key, val = key.strip(), val.strip()
        if key == "PackageName":
            cur = {"name": val, "externalRefs": []}
            packages.append(cur)
        elif key == "DocumentDescribes" or (key == "Relationship" and " DESCRIBES " in val):
            describes.append(val.split()[-1])
        elif cur is None:
            continue
        elif key == "SPDXID":
            cur["SPDXID"] = val
        elif key == "PackageVersion":
            cur["versionInfo"] = val
        elif key in ("PackageLicenseConcluded", "PackageLicenseDeclared"):
            cur["licenseConcluded" if key.endswith("Concluded") else "licenseDeclared"] = val
        elif key == "ExternalRef":
            parts = val.split()
            if len(parts) >= 3 and parts[1] == "purl":
                cur["externalRefs"].append({"referenceType": "purl", "referenceLocator": parts[2]})
    return {"spdxVersion": "SPDX-2.x", "documentDescribes": describes, "packages": packages}


def parse_purl(purl: str) -> tuple[str, str, str | None, dict] | None:
    m = re.match(r"^pkg:([a-zA-Z0-9.+-]+)/([^?#]+?)(?:@([^?#]+))?(?:\?([^#]*))?(?:#.*)?$", purl.strip())
    if not m:
        return None
    ptype, path, version, qs = m.group(1).lower(), m.group(2), m.group(3), m.group(4) or ""
    quals = dict(p.split("=", 1) for p in qs.split("&") if "=" in p)
    quals = {k.lower(): unquote(v) for k, v in quals.items()}
    parts = [unquote(p) for p in path.split("/") if p]
    if not parts:
        return None
    eco = PURL_TO_ECO.get(ptype, "generic")
    name = parts[-1]
    ns = "/".join(parts[:-1])
    if ptype == "maven" and ns:
        name = f"{ns}:{name}"
    elif ptype in ("npm",) and ns:
        name = f"{ns}/{name}"
    elif ptype in ("golang", "composer", "swift") and ns:
        name = f"{ns}/{name}"
    elif ptype == "deb":
        vendor = parts[0].lower() if len(parts) > 1 else quals.get("distro", "debian").split("-")[0]
        eco = "Ubuntu" if vendor == "ubuntu" else "Debian"
        m2 = re.search(r"(\d+(?:\.\d+)?)", quals.get("distro", ""))
        if m2 and eco == "Debian":
            eco = f"Debian:{m2.group(1).split('.')[0]}"
        elif m2:
            rel = m2.group(1)
            yy, _, mm = rel.partition(".")
            eco = f"Ubuntu:{rel}:LTS" if mm == "04" and yy.isdigit() and int(yy) % 2 == 0 else f"Ubuntu:{rel}"
        name = parts[-1]
    elif ptype == "apk":
        rel = quals.get("distro", "")
        m2 = re.search(r"(\d+\.\d+)", rel)
        if m2:
            eco = f"Alpine:v{m2.group(1)}"
        name = parts[-1]
    elif ptype == "rpm":
        vendor = parts[0].lower() if len(parts) > 1 else quals.get("distro", "").split("-")[0].lower()
        eco = {"rocky": "Rocky Linux", "almalinux": "AlmaLinux"}.get(vendor, "Red Hat")
        m2 = re.search(r"(\d+)", quals.get("distro", ""))
        if m2:
            eco = f"{eco}:{m2.group(1)}"
        name = parts[-1]
    elif ns and eco == "generic":
        name = f"{ns}/{name}"
    return eco, name, unquote(version) if version else None, quals


def _licenses_cdx(c: dict) -> list[str]:
    out = []
    for item in c.get("licenses") or []:
        lic = item.get("license") or {}
        val = lic.get("id") or lic.get("name") or item.get("expression")
        if val:
            out.append(val)
    return out


NO_VALUE = {"", "NOASSERTION", "NONE", "UNKNOWN"}


def _component(eco, name, version, licenses, loc, target, scope="runtime", direct=None):
    version = None if version is None or str(version).strip().upper() in NO_VALUE else str(version).strip()
    return Component(eco, name, version, confidence="high" if version else "low", scope=scope, direct=direct,
                     licenses=licenses, evidence=[Evidence("sbom", loc, "", target)])


def parse_cyclonedx(doc: dict, loc: str, target: str) -> list[Component]:
    comps = []
    root = ((doc.get("metadata") or {}).get("component") or {}).get("bom-ref")
    direct_refs = set()
    for dep in doc.get("dependencies") or []:
        if root and dep.get("ref") == root:
            direct_refs = set(dep.get("dependsOn") or [])

    def walk(items):
        for c in items or []:
            yield c
            yield from walk(c.get("components"))

    for c in walk(doc.get("components")):
        if c.get("type") in ("operating-system", "file", "data", "device"):
            continue
        scope = "dev" if c.get("scope") == "excluded" else "runtime"
        direct = (c.get("bom-ref") in direct_refs) if direct_refs else None
        p = parse_purl(c["purl"]) if c.get("purl") else None
        if p:
            eco, name, version, _q = p
            comps.append(_component(eco, name, version or c.get("version"), _licenses_cdx(c), loc, target, scope, direct))
        elif c.get("name"):
            nm = f"{c['group']}:{c['name']}" if c.get("group") else c["name"]
            comps.append(_component("generic", nm, c.get("version"), _licenses_cdx(c), loc, target, scope, direct))
    return comps


def parse_spdx(doc: dict, loc: str, target: str) -> list[Component]:
    comps = []
    described = set(doc.get("documentDescribes") or [])
    for p in doc.get("packages") or []:
        if p.get("SPDXID") in described and not p.get("externalRefs"):
            continue
        purl = next((r.get("referenceLocator") for r in p.get("externalRefs") or []
                     if r.get("referenceType") == "purl"), None)
        lic = [x for x in (p.get("licenseConcluded"), p.get("licenseDeclared"))
               if x and x not in ("NOASSERTION", "NONE")][:1]
        parsed = parse_purl(purl) if purl else None
        if parsed:
            eco, name, version, _q = parsed
            comps.append(_component(eco, name, version or p.get("versionInfo"), lic, loc, target))
        elif p.get("name"):
            comps.append(_component("generic", p["name"], p.get("versionInfo"), lic, loc, target))
    return comps


def scan_sbom(path: str | Path, target: str = "") -> tuple[list[Component], list]:
    from ..safeio import LIMITS
    path = Path(path)
    if path.stat().st_size > LIMITS["json"]:
        raise ValueError("SBOM dosyası çok büyük")
    kind = sniff(path)
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        if kind == "cyclonedx-xml":
            doc, kind = _cyclonedx_xml(text), "cyclonedx"
        elif kind == "spdx-tv":
            doc, kind = _spdx_tag_value(text), "spdx"
        else:
            doc = json.loads(text)
    except json.JSONDecodeError as ex:
        raise ValueError(f"SBOM JSON olarak okunamadı: {ex}") from ex
    except Exception as ex:
        if isinstance(ex, ValueError):
            raise
        raise ValueError(f"SBOM okunamadı: {type(ex).__name__}") from ex
    if kind == "cyclonedx":
        comps = parse_cyclonedx(doc, path.name, target)
    elif kind == "spdx":
        comps = parse_spdx(doc, path.name, target)
    else:
        raise ValueError("Desteklenmeyen SBOM biçimi (CycloneDX JSON / XML veya SPDX JSON / tag-value bekleniyor)")
    notes = []
    generic = [c for c in comps if c.ecosystem == "generic"]
    if generic:
        notes.append(("no-osv-coverage", path.name, f"PURL'i olmayan {len(generic)} bileşen eşleştirilemedi"))
    return comps, notes
