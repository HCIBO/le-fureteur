from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from ..binary import asar_files, clean_version, pe_info, scan_native
from ..common import comp, load_json
from .signatures import analyze_sourcemap, scan_js
from ...safeio import LIMITS, UnsafeInput, read_file, safe_relpath, walk_files

INSTALLER_EXT = (".msi", ".exe", ".dmg", ".pkg", ".deb", ".rpm", ".appimage", ".msix", ".appx", ".cab")
MAX_BIN = 300 * 1024 * 1024
_FRAMEWORK_DLL = re.compile(r"^(System\.|Microsoft\.(?:CSharp|VisualBasic|Win32|NETCore|Extensions\.Internal)|"
                            r"mscorlib|netstandard|WindowsBase|PresentationCore|PresentationFramework|clr|coreclr|"
                            r"hostfxr|hostpolicy|api-ms-win|ucrtbase|vcruntime|msvcp)", re.I)


def _seven_zip() -> str | None:
    return shutil.which("7zz") or shutil.which("7z") or shutil.which("7za")


def _limits():
    import resource
    resource.setrlimit(resource.RLIMIT_FSIZE, (LIMITS["member"], LIMITS["member"]))
    resource.setrlimit(resource.RLIMIT_CPU, (600, 600))
    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def precheck_7z(exe: str, path: str) -> None:
    r = subprocess.run([exe, "l", "-slt", "-ba", "--", path], capture_output=True, timeout=120, preexec_fn=_limits)
    if r.returncode not in (0, 1):
        raise UnsafeInput("Kurulum dosyası listelenemedi")
    total, count = 0, 0
    for block in r.stdout.decode("utf-8", "replace").split("\n\n"):
        f = dict(line.split(" = ", 1) for line in block.splitlines() if " = " in line)
        if "Path" not in f:
            continue
        count += 1
        name = f["Path"]
        if safe_relpath(name) is None:
            raise UnsafeInput(f"Kurulum dosyasında güvensiz yol: {name[:120]}")
        attrs = f.get("Attributes", "")
        if f.get("Symbolic Link", "").strip() or f.get("Hard Link", "").strip() or \
                re.search(r"(^|\s)l[r-][w-][xsStT-]", attrs):
            raise UnsafeInput(f"Kurulum dosyası bağlantı içeriyor (güvenlik nedeniyle açılmadı): {name[:120]}")
        try:
            size = int(f.get("Size") or 0)
        except ValueError:
            size = 0
        if size > LIMITS["member"]:
            raise UnsafeInput(f"Kurulum dosyasında çok büyük dosya: {name[:120]}")
        total += size
    if count > LIMITS["entries"] or total > LIMITS["total"]:
        raise UnsafeInput("Kurulum dosyası açıldığında çok büyük / çok fazla dosya (arşiv bombası olabilir)")


def extract_installer(path: str, dest: Path, depth: int = 0) -> bool:
    exe = _seven_zip()
    if not exe:
        return False
    precheck_7z(exe, path)
    r = subprocess.run([exe, "x", "-y", f"-o{dest}", "--", path],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=600, preexec_fn=_limits)
    if r.returncode not in (0, 1):
        return False
    if depth < 2:
        for p in list(walk_files(dest)):
            if p.suffix.lower() in (".cab", ".pkg", ".xar") or p.name in ("Payload", "data.tar"):
                sub = p.parent / (p.name + "_x")
                sub.mkdir(exist_ok=True)
                extract_installer(str(p), sub, depth + 1)
    return True


def scan_binaries(root: Path, target: str, label: str = ""):
    comps, notes = [], []
    seen = set()
    pe_found = []

    def scan_text(name: str, data: bytes, loc: str):
        if name.endswith(".map"):
            doc = load_json(data.decode("utf-8", "replace"))
            if isinstance(doc, dict) and doc.get("sources"):
                for pkg, vers in analyze_sourcemap(doc).items():
                    for v in sorted(vers) or [None]:
                        add("npm", pkg, v, "sourcemap", loc)
        else:
            for pkg, v, snip in scan_js(data[:4_000_000].decode("utf-8", "replace")):
                add("npm", pkg, v, "signature", loc, detail=snip)

    def add(eco, name, ver, method, loc, detail="", confidence="medium"):
        key = (eco, name.lower(), ver)
        if key in seen:
            return
        seen.add(key)
        comps.append(comp(eco, name, ver, method, loc, detail=detail, target=target,
                          confidence=confidence if ver else "low"))

    for p in walk_files(root):
        if ".git" in p.parts or "node_modules" in p.relative_to(root).parts[:-1]:
            continue
        if True:
            fn = p.name
            low = fn.lower()
            loc = f"{label}{p.relative_to(root)}"
            try:
                size = p.stat().st_size
            except OSError:
                continue
            if size > MAX_BIN or size < 64:
                continue
            if low == "release" and (p.parent / "bin").is_dir():
                m = re.search(r'JAVA_VERSION="([^"]+)"', read_file(p, 1 << 20).decode("utf-8", "replace"))
                if m:
                    add("generic", "openjdk", m.group(1).replace("_", "."), "properties", loc, detail="gömülü JRE")
                continue
            if low.endswith((".js.map", ".license.txt")) and "node_modules" not in p.parts:
                scan_text(low, read_file(p), loc)
                continue
            if low.endswith(".asar"):
                for ap, data in asar_files(read_file(p)):
                    parts = ap.split("/")
                    if "node_modules" not in parts and ap.endswith((".js", ".map", ".LICENSE.txt", ".mjs")):
                        scan_text(ap, data, f"{loc}!/{ap}")
                    pkg_root = ap.endswith("/package.json") and (
                        (len(parts) >= 3 and parts[-3] == "node_modules") or
                        (len(parts) >= 4 and parts[-4] == "node_modules" and parts[-3].startswith("@")))
                    if pkg_root:
                        doc = load_json(data.decode("utf-8", "replace"))
                        if isinstance(doc, dict) and doc.get("name") and doc.get("version"):
                            add("npm", doc["name"], doc["version"], "installed-package", f"{loc}!/{ap}",
                                confidence="high")
                continue
            if not low.endswith((".dll", ".exe", ".so", ".dylib", ".node")) and ".so." not in low:
                if not (os.access(p, os.X_OK) and size > 4096 and "." not in fn):
                    continue
            try:
                data = read_file(p)
            except (OSError, UnsafeInput):
                continue
            for eco, name, ver, snip in scan_native(data):
                add(eco, name, ver, "binary-strings", loc, detail=snip,
                    confidence="low" if name == "sqlite" else "medium")
            info = pe_info(data)
            if info and info.get("managed") and low.endswith(".dll") and not low.endswith(".resources.dll"):
                pe_found.append((fn, loc, info))
    companies = [i.get("CompanyName", "") for _, _, i in pe_found if i.get("CompanyName")]
    vendor = max(set(companies), key=companies.count) if companies else ""
    if companies.count(vendor) < 3 or re.search(r"microsoft|\.net foundation|newtonsoft|james newton", vendor, re.I):
        vendor = ""
    for fn, loc, info in pe_found:
        stem = fn.rsplit(".", 1)[0]
        if _FRAMEWORK_DLL.match(stem) or (vendor and info.get("CompanyName") == vendor):
            continue
        ver = clean_version(info.get("ProductVersion") or info.get("FileVersion") or "")
        ver = re.sub(r"-[0-9a-f]{7,40}$", "", ver)
        if re.match(r"^\d+\.\d+\.\d+\.0$", ver):
            ver = ver[:-2]
        if re.match(r"^\d+\.\d+", ver):
            add("NuGet", stem, ver, "pe-version", loc, detail=f"{info.get('ProductName', '')} {ver}".strip())
    return comps, notes


def scan_desktop(path: str, target: str = "", include_dev: bool = False, log=None):
    from ..whitebox import scan_directory

    p = Path(path)
    label = p.name
    tgt = target or label
    notes = []
    with tempfile.TemporaryDirectory(prefix="scakit-desk-") as tmp:
        if p.is_dir():
            root = p
        else:
            root = Path(tmp) / "x"
            root.mkdir()
            if not extract_installer(str(p), root):
                notes.append(("unsupported-layer", label, "kurulum dosyası açılamadı (7-Zip yok veya desteklenmeyen "
                                                          "paketleyici); kurulu uygulama dizininin arşivini isteyin"))
                return [], notes
        comps, wb_notes = scan_directory(root, target=tgt, include_dev=include_dev)
        bcomps, bnotes = scan_binaries(root, tgt, f"{label}!/" if not p.is_dir() else "")
    comps += bcomps
    notes += [(k, f"{label}!/{loc}" if not p.is_dir() else loc, d) for k, loc, d in wb_notes] + bnotes
    if log:
        log(f"  {len(comps)} detections ({sum(1 for c in comps if c.version)} with version)")
    return comps, notes
