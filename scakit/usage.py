from __future__ import annotations

import os
import re
from pathlib import Path

from .models import Component, base_ecosystem, normalize_name

SKIP = {"node_modules", ".git", "vendor", "dist", "build", "target", ".venv", "venv", "__pycache__", "bin", "obj",
        "Pods", ".gradle", ".next", "coverage"}
EXT = {
    "js": (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte"),
    "py": (".py",),
    "jvm": (".java", ".kt", ".kts", ".scala", ".groovy"),
    "cs": (".cs", ".vb", ".fs"),
    "go": (".go",),
    "rb": (".rb",),
}
JS_IMPORT = re.compile(r"""(?:\bfrom\s*|\bimport\s*\(?\s*|\brequire\s*\(\s*)['"]([^'"\s]+)['"]""")
PY_IMPORT = re.compile(r"^[ \t]*(?:from[ \t]+([\w.]+)[ \t]+import|import[ \t]+([\w., \t]+))", re.M)
JVM_IMPORT = re.compile(r"^\s*import\s+(?:static\s+)?([\w.]+)", re.M)
CS_USING = re.compile(r"^\s*(?:global\s+)?using\s+(?:static\s+)?(?:\w+\s*=\s*)?([\w.]+)\s*;", re.M)
GO_IMPORT_BLOCK = re.compile(r"^import\s*\((.*?)\)", re.M | re.S)
GO_IMPORT_LINE = re.compile(r'^import\s+(?:(\w+|\.|_)\s+)?"([^"]+)"', re.M)
GO_SPEC = re.compile(r'^\s*(?:(\w+|\.|_)\s+)?"([^"]+)"', re.M)
RB_REQUIRE = re.compile(r"""^\s*require\s+['"]([\w\-/]+)['"]""", re.M)

PY_MODULE_DIST = {
    "yaml": "pyyaml", "pil": "pillow", "jwt": "pyjwt", "cv2": "opencv-python", "sklearn": "scikit-learn",
    "bs4": "beautifulsoup4", "dateutil": "python-dateutil", "crypto": "pycryptodome", "openssl": "pyopenssl",
    "jose": "python-jose", "magic": "python-magic", "dotenv": "python-dotenv", "multipart": "python-multipart",
    "attr": "attrs", "serial": "pyserial", "git": "gitpython", "docx": "python-docx", "pptx": "python-pptx",
    "ldap": "python-ldap", "mysqldb": "mysqlclient", "zmq": "pyzmq", "nacl": "pynacl", "pkg-resources": "setuptools",
    "google": "protobuf", "jinja2": "jinja2", "markupsafe": "markupsafe", "socks": "pysocks", "usb": "pyusb",
    "dns": "dnspython", "ruamel": "ruamel-yaml", "xmlsec": "xmlsec", "saml2": "pysaml2", "ntlm": "python-ntlm",
    "kafka": "kafka-python", "telegram": "python-telegram-bot", "slugify": "python-slugify",
}
NODE_BUILTIN = {"fs", "path", "os", "http", "https", "crypto", "url", "util", "stream", "events", "child_process",
                "net", "tls", "zlib", "buffer", "querystring", "assert", "dns", "readline", "cluster", "worker_threads"}


def _js_pkg(spec: str) -> str | None:
    if spec.startswith((".", "/", "~", "@/", "node:", "#")) or spec in NODE_BUILTIN:
        return None
    parts = spec.split("/")
    return "/".join(parts[:2]) if spec.startswith("@") and len(parts) > 1 else parts[0]


def collect_imports(root: str | Path, max_files: int = 50000) -> dict:
    res = {"npm": set(), "py": set(), "jvm": set(), "cs": set(), "go": set(), "rb": set(), "go_calls": {},
           "files": 0, "by_kind": {k: 0 for k in EXT}}
    n = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP and not d.startswith(".")]
        for fn in filenames:
            low = fn.lower()
            kind = next((k for k, exts in EXT.items() if low.endswith(exts)), None)
            if not kind or low.endswith((".min.js", ".d.ts")):
                continue
            n += 1
            if n > max_files:
                break
            res["by_kind"][kind] += 1
            try:
                text = (Path(dirpath) / fn).read_text(errors="replace")[:2_000_000]
            except OSError:
                continue
            if kind == "js":
                for spec in JS_IMPORT.findall(text):
                    p = _js_pkg(spec)
                    if p:
                        res["npm"].add(p)
            elif kind == "py":
                for frm, imp in PY_IMPORT.findall(text):
                    mods = [frm] if frm else [m.strip().split(" as ")[0] for m in imp.split(",")]
                    for m in mods:
                        if m and not m.startswith("."):
                            res["py"].add(m.split(".")[0].lower())
            elif kind == "jvm":
                res["jvm"] |= set(JVM_IMPORT.findall(text))
            elif kind == "cs":
                res["cs"] |= {u.lower() for u in CS_USING.findall(text)}
            elif kind == "go":
                aliases = {}
                specs = GO_IMPORT_LINE.findall(text)
                for block in GO_IMPORT_BLOCK.findall(text):
                    specs += GO_SPEC.findall(block)
                for alias, path in specs:
                    res["go"].add(path)
                    name = alias or path.rstrip("/").split("/")[-1]
                    name = re.sub(r"^v\d+$", path.rstrip("/").split("/")[-2] if "/" in path else name, name)
                    if name not in ("_", "."):
                        aliases[name.replace("-", "_").split(".")[0]] = path
                methods = set(re.findall(r"\.([A-Za-z_]\w*)\s*\(", text))
                for alias, path in aliases.items():
                    calls = set(re.findall(r"\b" + re.escape(alias) + r"\.([A-Za-z_]\w*)", text)) | methods
                    res["go_calls"].setdefault(path, set()).update(calls)
            elif kind == "rb":
                res["rb"] |= {r.split("/")[0] for r in RB_REQUIRE.findall(text)}
    res["files"] = n
    return res


def component_usage(c: Component, imp: dict) -> str | None:
    eco = base_ecosystem(c.ecosystem)
    name = c.name
    k = imp.get("by_kind", {})
    if eco == "npm" and k.get("js"):
        return "imported" if name in imp["npm"] else "not-imported"
    if eco == "PyPI" and k.get("py"):
        dist = normalize_name("PyPI", name)
        mods = {normalize_name("PyPI", PY_MODULE_DIST.get(m, m)) for m in imp["py"]}
        return "imported" if dist in mods else "not-imported"
    if eco == "Maven" and k.get("jvm") and ":" in name:
        group = name.split(":", 1)[0]
        return "imported" if any(i.startswith(group + ".") or i == group for i in imp["jvm"]) else "not-imported"
    if eco == "NuGet" and k.get("cs"):
        n = name.lower()
        return "imported" if any(u == n or u.startswith(n + ".") for u in imp["cs"]) else "not-imported"
    if eco == "Go" and k.get("go"):
        return "imported" if any(p == name or p.startswith(name + "/") for p in imp["go"]) else "not-imported"
    if eco == "RubyGems" and k.get("rb"):
        return "imported" if name.lower() in imp["rb"] or name.replace("-", "/") in imp["rb"] else "not-imported"
    return None


def annotate(components: list[Component], imp: dict) -> dict:
    stats = {"imported": 0, "not-imported": 0, "unknown": 0}
    for c in components:
        u = component_usage(c, imp)
        if u is None:
            stats["unknown"] += 1
            continue
        if c.usage != "imported":
            c.usage = u
        stats[u] += 1
    return stats


def go_reachability(vuln: dict, comp: Component, go_calls: dict) -> str:
    if not go_calls:
        return ""
    checked = False
    for aff in vuln.get("affected", []):
        for imp in (aff.get("ecosystem_specific") or {}).get("imports", []):
            path, symbols = imp.get("path", ""), imp.get("symbols") or []
            if not path or not (path == comp.name or path.startswith(comp.name + "/")) or not symbols:
                continue
            checked = True
            used = go_calls.get(path, set())
            if any(s.split(".")[-1] in used for s in symbols):
                return "called"
    return "not-called" if checked else ""
