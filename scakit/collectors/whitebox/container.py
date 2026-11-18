from __future__ import annotations

import fnmatch
import json
import posixpath
import shutil
import tarfile
import tempfile
from pathlib import Path

INTERESTING_EXACT = {"etc/os-release", "usr/lib/os-release", "var/lib/dpkg/status", "lib/apk/db/installed",
                     "var/lib/rpm/rpmdb.sqlite", "var/lib/rpm/Packages", "usr/lib/sysimage/rpm/rpmdb.sqlite"}
INTERESTING_NAMES = {
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock",
    "uv.lock", "composer.lock", "packages.lock.json", "Cargo.lock", "Gemfile.lock", "go.mod", "pubspec.lock",
    "requirements.txt", "installed.json",
}
INTERESTING_GLOBS = ("*.jar", "*.war", "*.ear", "*.deps.json", "*.gemspec")
MAX_FILE = 400 * 1024 * 1024


def _interesting(path: str) -> bool:
    if path in INTERESTING_EXACT or path.startswith("var/lib/dpkg/status.d/"):
        return True
    base = posixpath.basename(path)
    if base in INTERESTING_NAMES:
        return base != "installed.json" or path.endswith("vendor/composer/installed.json")
    if base == "METADATA" and posixpath.dirname(path).endswith(".dist-info"):
        return True
    if base == "PKG-INFO" and posixpath.dirname(path).endswith(".egg-info"):
        return True
    if base == "package.json" and "/node_modules/" in "/" + path:
        parent = posixpath.dirname(path)
        gp = posixpath.dirname(parent)
        return posixpath.basename(gp) == "node_modules" or (
            posixpath.basename(gp).startswith("@") and posixpath.basename(posixpath.dirname(gp)) == "node_modules")
    if base.endswith(".gemspec"):
        return posixpath.basename(posixpath.dirname(path)) == "specifications"
    return any(fnmatch.fnmatch(base, g) for g in INTERESTING_GLOBS)


def _norm(name: str) -> str:
    return posixpath.normpath(name.lstrip("./").lstrip("/")) if name not in (".", "./") else ""


def _layer_list(tf: tarfile.TarFile):
    names = set(tf.getnames())

    def read_json(n):
        return json.load(tf.extractfile(n))

    if "manifest.json" in names:
        man = read_json("manifest.json")
        if isinstance(man, list) and man:
            cfg = read_json(man[0]["Config"]) if man[0].get("Config") in names else {}
            return [(layer, None) for layer in man[0].get("Layers", [])], man[0].get("RepoTags") or [], cfg
    if "index.json" in names:
        idx = read_json("index.json")

        def blob(digest):
            return "blobs/" + digest.replace(":", "/", 1)

        desc = idx["manifests"][0]
        tags = [m.get("annotations", {}).get("org.opencontainers.image.ref.name", "") for m in idx["manifests"]]
        doc = read_json(blob(desc["digest"]))
        while "manifests" in doc:
            pick = next((m for m in doc["manifests"] if (m.get("platform") or {}).get("architecture") == "amd64"),
                        doc["manifests"][0])
            if blob(pick["digest"]) not in names:
                pick = next((m for m in doc["manifests"] if blob(m["digest"]) in names), pick)
            doc = read_json(blob(pick["digest"]))
        cfg_path = blob((doc.get("config") or {}).get("digest", ""))
        cfg = read_json(cfg_path) if cfg_path in names else {}
        return [(blob(layer["digest"]), layer.get("mediaType")) for layer in doc.get("layers", [])], tags, cfg
    raise ValueError("docker save / OCI arşivi değil (manifest.json veya index.json yok)")


def _apply_layer(stream, dest: Path, present: set, notes: list, layer_name: str):
    base = dest.resolve()
    try:
        ltf = tarfile.open(fileobj=stream, mode="r|*")
    except tarfile.ReadError:
        notes.append(("unsupported-layer", layer_name, "zstd / bilinmeyen sıkıştırma"))
        return
    with ltf:
        for m in ltf:
            path = _norm(m.name)
            if not path:
                continue
            d, b = posixpath.split(path)
            if b == ".wh..wh..opq":
                for p in [x for x in present if x.startswith(d + "/")]:
                    present.discard(p)
                    (dest / p).unlink(missing_ok=True)
                continue
            if b.startswith(".wh."):
                victim = posixpath.join(d, b[4:])
                for p in [x for x in present if x == victim or x.startswith(victim + "/")]:
                    present.discard(p)
                    (dest / p).unlink(missing_ok=True)
                continue
            if not m.isfile() or not _interesting(path) or m.size > MAX_FILE:
                continue
            out = (dest / path).resolve()
            if not str(out).startswith(str(base)):
                continue
            f = ltf.extractfile(m)
            if f is None:
                continue
            out.parent.mkdir(parents=True, exist_ok=True)
            with open(out, "wb") as fh:
                shutil.copyfileobj(f, fh)
            present.add(path)


ENV_RUNTIMES = {
    "GOLANG_VERSION": ("Go", "stdlib"),
    "PYTHON_VERSION": ("generic", "cpython"),
    "NODE_VERSION": ("generic", "node.js"),
    "JAVA_VERSION": ("generic", "openjdk"),
    "RUBY_VERSION": ("generic", "ruby"),
    "PHP_VERSION": ("generic", "php"),
    "NGINX_VERSION": ("generic", "nginx"),
    "HTTPD_VERSION": ("generic", "apache-httpd"),
    "TOMCAT_VERSION": ("generic", "apache-tomcat"),
    "REDIS_VERSION": ("generic", "redis"),
    "POSTGRES_VERSION": ("generic", "postgresql"),
    "PG_VERSION": ("generic", "postgresql"),
}


def runtime_from_env(cfg: dict, image: str, target: str):
    from ..common import comp
    out = []
    for item in ((cfg.get("config") or {}).get("Env") or []):
        k, _, v = item.partition("=")
        if k in ENV_RUNTIMES and v:
            eco, name = ENV_RUNTIMES[k]
            ver = v.lstrip("v").split("+")[0]
            if k == "JAVA_VERSION":
                ver = ver.replace("jdk-", "").replace("jdk", "")
            out.append(comp(eco, name, ver, "image-config", f"{image}:/config Env", detail=item, target=target,
                            confidence="medium"))
    return out


def scan_image(path: str, target: str = "", include_dev: bool = False):
    from . import scan_directory

    notes: list = []
    name = Path(path).name
    with tempfile.TemporaryDirectory(prefix="scakit-img-") as tmp:
        root = Path(tmp) / "rootfs"
        root.mkdir()
        present: set[str] = set()
        with tarfile.open(path) as tf:
            layers, tags, cfg = _layer_list(tf)
            if tags and tags[0]:
                name = tags[0]
            all_names = set(tf.getnames())
            for layer, media in layers:
                if layer not in all_names:
                    notes.append(("unsupported-layer", layer, "arşivde yok"))
                    continue
                if media and "zstd" in media:
                    notes.append(("unsupported-layer", layer, "zstd"))
                    continue
                _apply_layer(tf.extractfile(layer), root, present, notes, layer)
        sd = root / "var/lib/dpkg/status.d"
        if sd.is_dir():
            parts = [p.read_text(errors="replace") for p in sorted(sd.iterdir()) if p.is_file() and "." not in p.name]
            status = root / "var/lib/dpkg/status"
            prev = status.read_text(errors="replace") if status.exists() else ""
            status.write_text(prev + "\n\n" + "\n\n".join(parts))
            shutil.rmtree(sd)
        comps, wb_notes = scan_directory(root, target=target or name, include_dev=include_dev)
    for c in comps:
        for e in c.evidence:
            e.location = f"{name}:/{e.location}"
    comps += runtime_from_env(cfg, name, target or name)
    notes += [(k, f"{name}:/{loc}", det) for k, loc, det in wb_notes]
    os_hit = any(c.ecosystem.split(":")[0] in ("Debian", "Ubuntu", "Alpine", "Red Hat", "Rocky Linux", "AlmaLinux")
                 for c in comps)
    if not os_hit:
        notes.append(("no-osv-coverage", name, "işletim sistemi paket veritabanı bulunamadı (scratch / distroless?)"))
    return comps, notes
