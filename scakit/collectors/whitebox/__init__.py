from __future__ import annotations

import fnmatch
import os
import re
import tarfile
import tempfile
import zipfile
from pathlib import Path

from . import js, jvm, others, ospkg, python

MAX_TEXT = 50 * 1024 * 1024
SKIP_DIRS = {".git", ".hg", ".svn", "__pycache__", ".idea", ".vscode", ".gradle", ".venv", "venv", ".tox",
             "bower_components", "Pods", "DerivedData", ".dart_tool", ".next", ".nuxt"}

NAME_PARSERS = [
    ("package-lock.json", js.parse_package_lock, "npm"),
    ("npm-shrinkwrap.json", js.parse_package_lock, "npm"),
    ("yarn.lock", js.parse_yarn_lock, "npm"),
    ("pnpm-lock.yaml", js.parse_pnpm_lock, "npm"),
    ("poetry.lock", python.parse_poetry_lock, "PyPI"),
    ("Pipfile.lock", python.parse_pipfile_lock, "PyPI"),
    ("uv.lock", python.parse_uv_or_pdm_lock, "PyPI"),
    ("pdm.lock", python.parse_uv_or_pdm_lock, "PyPI"),
    ("gradle.lockfile", jvm.parse_gradle_lockfile, "Maven"),
    ("*.lockfile", jvm.parse_gradle_lockfile, "Maven"),
    ("go.mod", others.parse_go_mod, "Go"),
    ("composer.lock", others.parse_composer_lock, "Packagist"),
    ("packages.lock.json", others.parse_nuget_lock, "NuGet"),
    ("packages.config", others.parse_packages_config, "NuGet"),
    ("project.assets.json", others.parse_assets_or_deps_json, "NuGet"),
    ("*.deps.json", others.parse_assets_or_deps_json, "NuGet"),
    ("Cargo.lock", others.parse_cargo_lock, "crates.io"),
    ("Gemfile.lock", others.parse_gemfile_lock, "RubyGems"),
    ("gems.locked", others.parse_gemfile_lock, "RubyGems"),
    ("pubspec.lock", others.parse_pubspec_lock, "Pub"),
    ("Podfile.lock", others.parse_podfile_lock, "CocoaPods"),
    ("Package.resolved", others.parse_package_resolved, "SwiftURL"),
    ("Cartfile.resolved", others.parse_cartfile_resolved, "SwiftURL"),
]
LOCK_ECOS = {"npm": "package.json", "PyPI": "requirements", "NuGet": "csproj"}
MANIFEST_PARSERS = [
    ("package.json", js.parse_package_json, "npm"),
    ("requirements*.txt", python.parse_requirements, "PyPI"),
    ("*requirements.txt", python.parse_requirements, "PyPI"),
    ("constraints.txt", python.parse_requirements, "PyPI"),
    ("pom.xml", jvm.parse_pom, "Maven"),
    ("*.csproj", None, "NuGet"),
    ("*.fsproj", None, "NuGet"),
    ("*.vbproj", None, "NuGet"),
]
ARCHIVE_EXT = (".jar", ".war", ".ear", ".aar")
ROOTFS_FILES = ("etc/os-release", "usr/lib/os-release", "var/lib/dpkg/status", "lib/apk/db/installed",
                "var/lib/rpm/rpmdb.sqlite", "var/lib/rpm/Packages", "usr/lib/sysimage/rpm/rpmdb.sqlite")


def _read(p: Path) -> str | None:
    try:
        if p.stat().st_size > MAX_TEXT:
            return None
        return p.read_text(errors="replace")
    except OSError:
        return None


def _sniff_text(text: str, name: str, loc: str, target: str, os_eco: str | None):
    head = text[:4000]
    if name.endswith(".json"):
        doc = js.load_json(text)
        if js.looks_like_npm_ls(doc):
            return js.parse_npm_ls(text, loc, target), "npm"
        return [], None
    if jvm.looks_like_maven_tree(text):
        return jvm.parse_maven_tree(text, loc, target), "Maven"
    if jvm.looks_like_gradle_deps(text):
        return jvm.parse_gradle_deps(text, loc, target), "Maven"
    if "Top-level Package" in head or re.search(r"^Project '.+' has the following package references", head, re.M):
        return others.parse_dotnet_list(text, loc, target), "NuGet"
    if re.search(r"^\S+: go\d+\.\d+", head, re.M) or re.search(r"^\s+dep\s+\S+\s+v\d", head, re.M):
        return others.parse_go_list(text, loc, target), "Go"
    if re.search(r"^[\w.\-/]+\.[a-z]{2,}/\S+ v\d+\.\d+\.\d+", head, re.M) and "go" in name.lower():
        return others.parse_go_list(text, loc, target), "Go"
    if re.search(r"^[A-Za-z0-9][A-Za-z0-9._-]*==\S+$", head, re.M):
        return python.parse_requirements(text, loc, target), "PyPI"
    if os_eco and re.search(r"^[\w.+\-]+\t\S+", head, re.M):
        return ospkg.parse_package_list(text, loc, os_eco, target), os_eco
    return [], None


def scan_directory(root: str | Path, target: str = "", os_eco: str | None = None, include_dev: bool = False,
                   log=None, extra=None):
    root = Path(root)
    comps, notes = [], []
    lock_dirs: dict[str, set[str]] = {}
    manifests: list[tuple[Path, object, str]] = []
    node_dirs: list[Path] = []
    central: dict = {}
    nested: list[Path] = []
    rootfs = {}

    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        if "node_modules" in dirnames:
            node_dirs.append(Path(dirpath) / "node_modules")
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and d != "node_modules"]
        for fn in filenames:
            p = Path(dirpath) / fn
            loc = str(p.relative_to(root)) if p != root else fn
            low = fn.lower()
            if low.endswith(ARCHIVE_EXT):
                try:
                    comps += jvm.scan_archive(p.read_bytes(), loc, target)
                except OSError:
                    pass
                continue
            if low.endswith(".apk") or low.endswith((".tar", ".tar.gz", ".tgz", ".ipa")):
                nested.append(p)
                continue
            if fn == "METADATA" and dirpath.endswith(".dist-info") or fn == "PKG-INFO" and dirpath.endswith(".egg-info"):
                t = _read(p)
                if t:
                    comps += python.parse_metadata(t, loc, target)
                continue
            if fn.endswith(".gemspec") and Path(dirpath).name == "specifications":
                comps += others.parse_gemspec_filename(loc, target)
                continue
            if fn == "installed.json" and Path(dirpath).name == "composer":
                t = _read(p)
                if t:
                    comps += others.parse_composer_installed(t, loc, target)
                    lock_dirs.setdefault("Packagist", set()).add(rel_dir)
                continue
            if fn == "Directory.Packages.props":
                t = _read(p)
                if t:
                    central.update(others.parse_central_packages(t))
                continue
            sloc = loc.replace("\\", "/")
            rf = next((k for k in ROOTFS_FILES if sloc == k or sloc.endswith("/" + k)), None)
            if rf:
                rootfs.setdefault(sloc[: len(sloc) - len(rf)], {})[rf] = p
                continue
            handled = False
            for pat, fn_parser, eco in NAME_PARSERS:
                if fnmatch.fnmatch(fn, pat):
                    t = _read(p)
                    if t is not None:
                        comps += fn_parser(t, loc, target)
                        lock_dirs.setdefault(eco, set()).add(rel_dir)
                    handled = True
                    break
            if handled:
                continue
            for pat, fn_parser, eco in MANIFEST_PARSERS:
                if fnmatch.fnmatch(fn, pat):
                    manifests.append((p, fn_parser, eco))
                    handled = True
                    break
            if handled:
                continue
            if low.endswith((".txt", ".log", ".json", ".out")) and fn not in ("package.json",):
                t = _read(p)
                if t:
                    found, eco = _sniff_text(t, low, loc, target, os_eco)
                    if found:
                        comps += found
                        lock_dirs.setdefault(eco.split(":")[0], set()).add(rel_dir)

    for p, fn_parser, eco in manifests:
        t = _read(p)
        if t is None:
            continue
        loc = str(p.relative_to(root))
        rel_dir = os.path.relpath(p.parent, root)
        if fn_parser is None:
            found = others.parse_csproj(t, loc, target, central)
        else:
            found = fn_parser(t, loc, target)
        if rel_dir not in lock_dirs.get(eco, set()) and found and eco != "Maven":
            notes.append(("missing-lockfile", loc, eco))
        if eco == "Maven" and "Maven" in lock_dirs:
            for c in found:
                c.version = None
        comps += found

    if node_dirs and "npm" not in lock_dirs:
        for nd in node_dirs:
            for p in _installed_npm_manifests(nd):
                t = _read(p)
                if t:
                    comps += js.parse_installed_package_json(t, str(p.relative_to(root)), target)

    for prefix, files in rootfs.items():
        eco = os_eco
        rel = files.get("etc/os-release") or files.get("usr/lib/os-release")
        if rel and not eco:
            eco = ospkg.os_ecosystem(_read(rel) or "")
        if "var/lib/dpkg/status" in files:
            comps += ospkg.parse_dpkg_status(_read(files["var/lib/dpkg/status"]) or "",
                                             prefix + "var/lib/dpkg/status", eco or "Debian", target)
        for rp in ("var/lib/rpm/rpmdb.sqlite", "usr/lib/sysimage/rpm/rpmdb.sqlite", "var/lib/rpm/Packages"):
            if rp in files:
                from .rpmdb import read_rpmdb
                try:
                    comps += ospkg.parse_rpm_packages(read_rpmdb(str(files[rp])), prefix + rp, eco or "Red Hat", target)
                except Exception as ex:
                    notes.append(("unsupported-layer", prefix + rp, f"RPM veritabanı okunamadı: {ex}"))
                break
        if "lib/apk/db/installed" in files:
            comps += ospkg.parse_apk_installed(_read(files["lib/apk/db/installed"]) or "",
                                               prefix + "lib/apk/db/installed", eco or "Alpine", target)

    if extra is not None:
        extra.extend(nested)
    if not include_dev:
        dev = [c for c in comps if c.scope == "dev"]
        if dev:
            notes.append(("dev-excluded", str(root), str(len(dev))))
        comps = [c for c in comps if c.scope != "dev"]
    annotate_lines(comps, root)
    return comps, notes


def _installed_npm_manifests(node_modules: Path):
    for dirpath, dirnames, filenames in os.walk(node_modules):
        d = Path(dirpath)
        is_pkg_root = (d.parent.name == "node_modules" and not d.name.startswith("@")) or (
            d.parent.name.startswith("@") and d.parent.parent.name == "node_modules")
        if is_pkg_root and "package.json" in filenames and not d.name.startswith("."):
            yield d / "package.json"
        if is_pkg_root:
            dirnames[:] = [x for x in dirnames if x == "node_modules"]
        elif d.name != "node_modules" and not d.name.startswith("@"):
            dirnames[:] = []


def extract_archive(path: Path, dest: Path) -> Path:
    from ...safeio import safe_extract
    return safe_extract(path, dest)


def scan_source_archive(path: str | Path, **kw):
    with tempfile.TemporaryDirectory(prefix="scakit-") as tmp:
        root = extract_archive(Path(path), Path(tmp))
        return scan_directory(root, **kw)


_TEXT_METHODS = {"lockfile", "manifest", "command-output", "properties"}


def _name_variants(c) -> list[str]:
    n = c.name
    out = [n]
    if ":" in n:
        out += [n.split(":", 1)[1], n.split(":", 1)[0]]
    if "/" in n and not n.startswith("@"):
        out.append(n.rsplit("/", 1)[-1])
    if c.ecosystem == "PyPI":
        base = re.sub(r"[-_.]+", "-", n).lower()
        out += [base, base.replace("-", "_"), base.replace("-", ".")]
    return [v for v in dict.fromkeys(out) if v]


def annotate_lines(comps, root) -> None:
    from ...safeio import UnsafeInput, read_file
    root = Path(root)
    cache: dict[str, list[str] | None] = {}
    for c in comps:
        for e in c.evidence:
            if e.line or e.method not in _TEXT_METHODS or "!" in e.location or "://" in e.location:
                continue
            if e.location not in cache:
                p = root / e.location
                try:
                    if p.is_file() and p.resolve().is_relative_to(root.resolve()):
                        cache[e.location] = read_file(p, 8 * 1024 * 1024).decode("utf-8", "replace").splitlines()
                    else:
                        cache[e.location] = None
                except (OSError, UnsafeInput):
                    cache[e.location] = None
            text = cache[e.location]
            if not text:
                continue
            variants = [v.lower() for v in _name_variants(c)]
            ver = (c.version or "").lower()
            best = None
            for i, ln in enumerate(text):
                low = ln.lower()
                if any(v in low for v in variants):
                    if ver and ver in low:
                        best = i
                        break
                    if best is None:
                        best = i
            if best is not None:
                e.line = best + 1
                e.snippet = text[best].strip()[:240]
