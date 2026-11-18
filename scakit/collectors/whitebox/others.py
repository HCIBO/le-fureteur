from __future__ import annotations

import re
import xml.etree.ElementTree as ET

import yaml

from ..common import comp, load_json
from ...safeio import UnsafeInput, xml_fromstring

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib


def parse_go_mod(text: str, loc: str, target: str = ""):
    reqs, replaces = {}, {}
    block = None
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        indirect = "// indirect" in raw
        if not line:
            continue
        if line.endswith("(") and line.split()[0] in ("require", "replace", "exclude", "retract"):
            block = line.split()[0]
            continue
        if line == ")":
            block = None
            continue
        kind = block
        if not block:
            head = line.split(None, 1)
            if head[0] in ("require", "replace") and len(head) > 1:
                kind, line = head[0], head[1]
            else:
                continue
        if kind == "require":
            p = line.split()
            if len(p) >= 2:
                reqs[p[0]] = (p[1], indirect)
        elif kind == "replace" and "=>" in line:
            old, new = (x.split() for x in line.split("=>", 1))
            if len(new) >= 2:
                replaces[old[0]] = (new[0], new[1])
    out = []
    for mod, (ver, indirect) in reqs.items():
        name = mod
        if mod in replaces:
            name, ver = replaces[mod]
        out.append(comp("Go", name, ver.lstrip("v"), "manifest" if not indirect else "lockfile", loc,
                        detail="indirect" if indirect else "", target=target, direct=not indirect))
    return out


def parse_go_list(text: str, loc: str, target: str = ""):
    out = []
    for line in text.splitlines():
        p = line.split()
        gm = re.match(r"^\S.*:\s+go(\d+\.\d+(?:\.\d+)?)\s*$", line)
        if gm:
            out.append(comp("Go", "stdlib", gm.group(1), "command-output", loc, detail="go version -m",
                            target=target))
            continue
        if len(p) >= 3 and p[0] in ("dep", "=>"):
            out.append(comp("Go", p[1], p[2].lstrip("v"), "command-output", loc, detail="go version -m",
                            target=target))
        elif len(p) >= 2 and not line.startswith(("\t", " ")) and re.match(r"^v\d", p[1]):
            name, ver = p[0], p[1]
            if len(p) >= 5 and p[2] == "=>":
                name, ver = p[3], p[4]
            out.append(comp("Go", name, ver.lstrip("v"), "command-output", loc, detail="go list -m all",
                            target=target))
    return out


def _composer_entries(pkgs, loc, target, dev_names=(), default_scope="runtime"):
    out = []
    for p in pkgs or []:
        name, ver = p.get("name"), p.get("version")
        if not name or not ver or ver.startswith("dev-"):
            continue
        lic = p.get("license") if isinstance(p.get("license"), list) else None
        out.append(comp("Packagist", name, ver.lstrip("v"), "lockfile", loc, target=target, licenses=lic,
                        scope="dev" if name in dev_names else default_scope))
    return out


def parse_composer_lock(text: str, loc: str, target: str = ""):
    doc = load_json(text) or {}
    return _composer_entries(doc.get("packages"), loc, target) + \
        _composer_entries(doc.get("packages-dev"), loc, target, default_scope="dev")


def parse_composer_installed(text: str, loc: str, target: str = ""):
    doc = load_json(text)
    if isinstance(doc, list):
        return _composer_entries(doc, loc, target)
    if isinstance(doc, dict):
        return _composer_entries(doc.get("packages"), loc, target, set(doc.get("dev-package-names") or []))
    return []


def parse_nuget_lock(text: str, loc: str, target: str = ""):
    doc = load_json(text) or {}
    out = []
    for fw, deps in (doc.get("dependencies") or {}).items():
        for name, meta in (deps or {}).items():
            if meta.get("type") == "Project" or not meta.get("resolved"):
                continue
            out.append(comp("NuGet", name, meta["resolved"], "lockfile", loc, detail=fw, target=target,
                            direct=meta.get("type") == "Direct"))
    return out


def parse_packages_config(text: str, loc: str, target: str = ""):
    try:
        root = xml_fromstring(text)
    except (ET.ParseError, UnsafeInput):
        return []
    return [comp("NuGet", p.get("id"), p.get("version"), "lockfile", loc, target=target, direct=True,
                 scope="dev" if p.get("developmentDependency") == "true" else "runtime")
            for p in root.iter("package") if p.get("id") and p.get("version")]


def parse_assets_or_deps_json(text: str, loc: str, target: str = ""):
    doc = load_json(text) or {}
    out = []
    for key, meta in (doc.get("libraries") or {}).items():
        if (meta or {}).get("type") not in ("package", None) or "/" not in key:
            continue
        name, ver = key.split("/", 1)
        out.append(comp("NuGet", name, ver, "lockfile" if loc.endswith("assets.json") else "installed-package",
                        loc, target=target))
    return out


def parse_csproj(text: str, loc: str, target: str = "", central: dict | None = None):
    central = central or {}
    out = []
    try:
        root = xml_fromstring(text)
    except (ET.ParseError, UnsafeInput):
        return out
    for el in root.iter():
        tag = el.tag.split("}", 1)[-1] if isinstance(el.tag, str) else ""
        if tag != "PackageReference":
            continue
        name = el.get("Include") or el.get("Update")
        ver = el.get("Version") or el.findtext("Version") or central.get((name or "").lower())
        if not name:
            continue
        exact = ver and not re.search(r"[\[\](),*]", ver)
        out.append(comp("NuGet", name, ver if exact else None, "manifest", loc, target=target, direct=True,
                        confidence="medium" if exact else "low"))
    return out


def parse_central_packages(text: str) -> dict:
    try:
        root = xml_fromstring(text)
    except (ET.ParseError, UnsafeInput):
        return {}
    return {el.get("Include", "").lower(): el.get("Version") for el in root.iter()
            if isinstance(el.tag, str) and el.tag.endswith("PackageVersion") and el.get("Include")}


def parse_dotnet_list(text: str, loc: str, target: str = ""):
    out = []
    transitive = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("Transitive Package"):
            transitive = True
        elif s.startswith("Top-level Package"):
            transitive = False
        if s.startswith("> "):
            p = s[2:].split()
            if len(p) >= 2:
                out.append(comp("NuGet", p[0], p[-1], "command-output", loc, detail="dotnet list package",
                                target=target, direct=not transitive))
    return out


def parse_cargo_lock(text: str, loc: str, target: str = ""):
    try:
        doc = tomllib.loads(text)
    except Exception:
        return []
    return [comp("crates.io", p["name"], p["version"], "lockfile", loc, target=target)
            for p in doc.get("package", []) if p.get("source", "").startswith("registry+")]


_GEM_PLATFORM = re.compile(r"-(?:x86|x64|arm|aarch64|java|universal|mingw|mswin|darwin|linux|musl)[\w-]*$")


def parse_gemfile_lock(text: str, loc: str, target: str = ""):
    out = []
    section = None
    for line in text.splitlines():
        if line and not line.startswith(" "):
            section = line.strip()
            continue
        if section == "GEM":
            m = re.match(r"^ {4}([A-Za-z0-9_.\-]+) \(([^)]+)\)$", line)
            if m:
                ver = _GEM_PLATFORM.sub("", m.group(2))
                out.append(comp("RubyGems", m.group(1), ver, "lockfile", loc, target=target))
    return out


def parse_gemspec_filename(path: str, target: str = ""):
    m = re.match(r"^(.+)-(\d[\w.]*)\.gemspec$", path.rsplit("/", 1)[-1])
    if not m:
        return []
    return [comp("RubyGems", m.group(1), _GEM_PLATFORM.sub("", m.group(2)), "installed-package", path, target=target)]


def parse_pubspec_lock(text: str, loc: str, target: str = ""):
    try:
        doc = yaml.safe_load(text) or {}
    except yaml.YAMLError:
        return []
    out = []
    for name, meta in (doc.get("packages") or {}).items():
        meta = meta or {}
        if meta.get("source") not in ("hosted", None) or not meta.get("version"):
            continue
        dep = meta.get("dependency", "")
        out.append(comp("Pub", name, str(meta["version"]), "lockfile", loc, target=target,
                        direct=dep.startswith("direct"), scope="dev" if dep == "direct dev" else "runtime"))
    return out


def parse_podfile_lock(text: str, loc: str, target: str = ""):
    out, seen = [], set()
    in_pods = False
    for line in text.splitlines():
        if line.startswith("PODS:"):
            in_pods = True
            continue
        if in_pods and line and not line.startswith(" "):
            break
        m = re.match(r'^  - "?([^\s"(]+) \(([^)]+)\)"?:?$', line)
        if in_pods and m:
            name = m.group(1).split("/", 1)[0]
            if (name, m.group(2)) not in seen:
                seen.add((name, m.group(2)))
                out.append(comp("CocoaPods", name, m.group(2), "lockfile", loc, target=target))
    return out


def _swift_url(url: str) -> str:
    url = re.sub(r"^(https?://|git@|ssh://git@)", "", url.strip())
    url = url.replace(":", "/", 1) if url.startswith("github.com:") else url
    return re.sub(r"\.git$", "", url).rstrip("/")


def parse_package_resolved(text: str, loc: str, target: str = ""):
    doc = load_json(text) or {}
    pins = doc.get("pins") or (doc.get("object") or {}).get("pins") or []
    out = []
    for p in pins:
        url = p.get("location") or p.get("repositoryURL") or ""
        ver = (p.get("state") or {}).get("version")
        if url and ver:
            out.append(comp("SwiftURL", _swift_url(url), ver, "lockfile", loc, target=target))
    return out


def parse_cartfile_resolved(text: str, loc: str, target: str = ""):
    out = []
    for line in text.splitlines():
        m = re.match(r'^(github|git)\s+"([^"]+)"\s+"v?([^"]+)"', line.strip())
        if m:
            src = m.group(2)
            url = f"github.com/{src}" if m.group(1) == "github" and "/" in src and "://" not in src else _swift_url(src)
            out.append(comp("SwiftURL", url, m.group(3), "lockfile", loc, target=target, confidence="medium"))
    return out
