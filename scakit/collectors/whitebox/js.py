from __future__ import annotations

import re

import yaml

from ..common import comp, load_json

ECO = "npm"
_EXACT = re.compile(r"^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")


def _host(url) -> str | None:
    if not isinstance(url, str) or "://" not in url:
        return None
    from urllib.parse import urlparse
    return urlparse(url).hostname


def _name_from_key(key: str) -> str:
    return key.rsplit("node_modules/", 1)[-1]


def parse_package_lock(text: str, loc: str, target: str = ""):
    doc = load_json(text)
    if not isinstance(doc, dict):
        return []
    out = []
    pkgs = doc.get("packages")
    if isinstance(pkgs, dict):
        root = pkgs.get("", {})
        direct = set(root.get("dependencies", {})) | set(root.get("devDependencies", {})) | \
            set(root.get("optionalDependencies", {}))
        for key, meta in pkgs.items():
            if not key or "node_modules/" not in key or meta.get("link"):
                continue
            name = meta.get("name") or _name_from_key(key)
            ver = meta.get("version")
            if not ver or ver.startswith(("file:", "link:")):
                continue
            is_direct = key == f"node_modules/{name}" and name in direct
            parent = key.rsplit("/node_modules/", 1)[0] if key.count("node_modules/") > 1 else ""
            out.append(comp(ECO, name, ver, "lockfile", loc, detail=key, target=target, direct=is_direct,
                            scope="dev" if meta.get("dev") else "runtime",
                            licenses=[meta["license"]] if isinstance(meta.get("license"), str) else None,
                            parents=[_name_from_key(parent)] if parent else None))
            out[-1].registry = _host(meta.get("resolved"))
        return out

    def walk(deps: dict, depth: int, parent: str):
        for name, meta in (deps or {}).items():
            ver = meta.get("version", "")
            if ver and not ver.startswith(("file:", "git", "http")):
                out.append(comp(ECO, name, ver, "lockfile", loc, target=target, direct=depth == 0,
                                scope="dev" if meta.get("dev") else "runtime",
                                parents=[parent] if parent else None))
            walk(meta.get("dependencies"), depth + 1, name)

    walk(doc.get("dependencies"), 0, "")
    return out


def _yarn_spec_name(spec: str) -> str:
    spec = spec.strip().strip('"')
    at = spec.find("@", 1)
    return spec[:at] if at > 0 else spec


def parse_yarn_lock(text: str, loc: str, target: str = ""):
    out, last = [], []
    names = None
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" ") and line.rstrip().endswith(":"):
            header = line.rstrip()[:-1]
            if header.startswith("__metadata"):
                names = None
                continue
            specs = [s.strip() for s in header.split(",")]
            if any("@workspace:" in s or "@link:" in s or "@file:" in s for s in specs):
                names = None
                continue
            names = {_yarn_spec_name(s) for s in specs}
            continue
        m = re.match(r'^\s{2}version:?\s+"?([^"\s]+)"?\s*$', line)
        if m and names:
            for n in names:
                out.append(comp(ECO, n, m.group(1), "lockfile", loc, target=target))
            last = out[-len(names):]
            names = None
            continue
        r = re.match(r'^\s{2}resolved:?\s+"?([^"\s#]+)', line)
        if r and out:
            for c in last:
                c.registry = _host(r.group(1))
    return out


def _pnpm_key(key: str):
    key = key.lstrip("/")
    key = re.sub(r"\(.*$", "", key)
    if re.search(r"^(@[^/]+/)?[^/@]+@", key):
        name, _, ver = key.rpartition("@")
    else:
        name, _, ver = key.rpartition("/")
        ver = ver.split("_", 1)[0]
    return name, ver


def parse_pnpm_lock(text: str, loc: str, target: str = ""):
    try:
        doc = yaml.safe_load(text) or {}
    except yaml.YAMLError:
        return []
    direct = set()
    importers = doc.get("importers") or {".": doc}
    for imp in importers.values():
        for sect in ("dependencies", "devDependencies", "optionalDependencies"):
            direct |= set((imp or {}).get(sect) or {})
    out = []
    for key, meta in (doc.get("packages") or {}).items():
        name, ver = _pnpm_key(key)
        meta = meta or {}
        name = meta.get("name", name)
        ver = meta.get("version", ver)
        if not name or not ver or ver.startswith(("link:", "file:")):
            continue
        out.append(comp(ECO, name, ver, "lockfile", loc, detail=key, target=target, direct=name in direct,
                        scope="dev" if meta.get("dev") else "runtime"))
    return out


def parse_npm_ls(text: str, loc: str, target: str = ""):
    doc = load_json(text)
    if not isinstance(doc, dict):
        return []
    out = []

    def walk(deps, depth, parent):
        for name, meta in (deps or {}).items():
            if not isinstance(meta, dict):
                continue
            ver = meta.get("version")
            if ver:
                out.append(comp(ECO, name, ver, "command-output", loc, detail="npm ls", target=target,
                                direct=depth == 0, scope="dev" if meta.get("dev") else "runtime",
                                parents=[parent] if parent else None))
            walk(meta.get("dependencies"), depth + 1, name)

    walk(doc.get("dependencies"), 0, "")
    return out


def looks_like_npm_ls(doc) -> bool:
    if not isinstance(doc, dict) or "lockfileVersion" in doc or not isinstance(doc.get("dependencies"), dict):
        return False
    vals = list(doc["dependencies"].values())[:5]
    return bool(vals) and all(isinstance(v, dict) and ("version" in v or "missing" in v) for v in vals)


def parse_package_json(text: str, loc: str, target: str = ""):
    doc = load_json(text)
    if not isinstance(doc, dict):
        return []
    out = []
    for sect, scope in (("dependencies", "runtime"), ("devDependencies", "dev"), ("optionalDependencies", "runtime")):
        for name, spec in (doc.get(sect) or {}).items():
            if not isinstance(spec, str):
                continue
            exact = _EXACT.match(spec.strip())
            out.append(comp(ECO, name, spec.strip().lstrip("v") if exact else None, "manifest", loc,
                            detail=f"{sect}: {spec}", target=target, direct=True, scope=scope,
                            confidence="medium" if exact else "low"))
    return out


def parse_installed_package_json(text: str, loc: str, target: str = ""):
    doc = load_json(text)
    if not isinstance(doc, dict) or not doc.get("name") or not doc.get("version"):
        return []
    lic = doc.get("license")
    return [comp(ECO, doc["name"], doc["version"], "installed-package", loc, target=target,
                 licenses=[lic] if isinstance(lic, str) else None)]
