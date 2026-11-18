from __future__ import annotations

import re
from pathlib import Path

from ..common import comp, load_json

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

ECO = "PyPI"
_REQ = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(===|==|~=|>=|<=|!=|>|<)?\s*([^;#\s,]*)")


def parse_requirements(text: str, loc: str, target: str = "", _seen=None):
    out = []
    _seen = _seen or set()
    base = Path(loc).parent
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r ", "--requirement ", "-c ", "--constraint ")):
            inc = base / line.split(None, 1)[1].strip()
            if inc.is_file() and str(inc) not in _seen:
                _seen.add(str(inc))
                out += parse_requirements(inc.read_text(errors="replace"), str(inc), target, _seen)
            continue
        if line.startswith("-") or "://" in line or line.startswith((".", "/")):
            continue
        if " @ " in line:
            continue
        m = _REQ.match(line)
        if not m:
            continue
        name, op, ver = m.groups()
        exact = op in ("==", "===") and ver and "*" not in ver
        out.append(comp(ECO, name, ver if exact else None, "manifest" if not exact else "lockfile", loc,
                        detail=line, target=target, direct=True,
                        confidence="high" if exact else "low"))
    return out


def _toml(text):
    try:
        return tomllib.loads(text)
    except Exception:
        return None


def parse_poetry_lock(text: str, loc: str, target: str = ""):
    doc = _toml(text) or {}
    out = []
    for p in doc.get("package", []):
        if (p.get("source") or {}).get("type") in ("directory", "file"):
            continue
        cat = p.get("category", "main")
        out.append(comp(ECO, p["name"], p.get("version"), "lockfile", loc, target=target,
                        scope="dev" if cat == "dev" else "runtime"))
        url = (p.get("source") or {}).get("url")
        if url:
            from urllib.parse import urlparse
            out[-1].registry = urlparse(url).hostname
    return out


def parse_uv_or_pdm_lock(text: str, loc: str, target: str = ""):
    doc = _toml(text) or {}
    out = []
    for p in doc.get("package", []):
        src = p.get("source") or {}
        if any(k in src for k in ("editable", "virtual", "directory", "path")):
            continue
        if p.get("version"):
            out.append(comp(ECO, p["name"], p["version"], "lockfile", loc, target=target))
    return out


def parse_pipfile_lock(text: str, loc: str, target: str = ""):
    doc = load_json(text) or {}
    out = []
    for sect, scope in (("default", "runtime"), ("develop", "dev")):
        for name, meta in (doc.get(sect) or {}).items():
            ver = (meta or {}).get("version", "")
            if ver.startswith("=="):
                out.append(comp(ECO, name, ver[2:], "lockfile", loc, target=target, scope=scope))
    return out


def parse_metadata(text: str, loc: str, target: str = ""):
    name = ver = lic = None
    for line in text.splitlines():
        if not line.strip():
            break
        if line.startswith("Name:"):
            name = line[5:].strip()
        elif line.startswith("Version:"):
            ver = line[8:].strip()
        elif line.startswith("License-Expression:") or (line.startswith("License:") and lic is None):
            lic = line.split(":", 1)[1].strip()
        elif line.startswith("Classifier: License ::") and (lic is None or len(lic) > 60 or lic.upper() == "UNKNOWN"):
            lic = line.rsplit("::", 1)[1].strip()
    if not name or not ver:
        return []
    return [comp(ECO, name, ver, "installed-package", loc, target=target,
                 licenses=[lic] if lic and len(lic) < 80 and lic.upper() != "UNKNOWN" else None)]
