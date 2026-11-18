from __future__ import annotations

import contextvars
import io
import os
import re
import tarfile
import zipfile
from pathlib import Path

MB = 1024 * 1024
LIMITS = {
    "member": int(os.environ.get("SCAKIT_MAX_MEMBER_MB", 512)) * MB,
    "total": int(os.environ.get("SCAKIT_MAX_EXTRACT_MB", 8192)) * MB,
    "entries": int(os.environ.get("SCAKIT_MAX_ENTRIES", 200_000)),
    "xml": 20 * MB,
    "json": 512 * MB,
}


class UnsafeInput(ValueError):
    pass


_BUDGET = contextvars.ContextVar("scakit_extract_budget", default=None)


class budget:

    def __enter__(self):
        self._tok = _BUDGET.set([LIMITS["total"]])
        return self

    def __exit__(self, *exc):
        _BUDGET.reset(self._tok)


def _spend(n: int, name: str) -> None:
    if n > LIMITS["member"]:
        raise UnsafeInput(f"Arşivdeki dosya çok büyük: {name} ({n // MB} MB)")
    b = _BUDGET.get()
    if b is not None:
        b[0] -= n
        if b[0] < 0:
            raise UnsafeInput(f"Açılmış toplam boyut sınırı aşıldı ({LIMITS['total'] // MB} MB) — arşiv bombası olabilir")


class SafeZipFile(zipfile.ZipFile):

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        if len(self.filelist) > LIMITS["entries"]:
            raise UnsafeInput(f"Arşivde çok fazla dosya var ({len(self.filelist)})")

    def open(self, name, mode="r", pwd=None, *, force_zip64=False):
        if mode == "r":
            info = name if isinstance(name, zipfile.ZipInfo) else self.getinfo(name)
            if info.flag_bits & 0x1 and pwd is None:
                raise UnsafeInput("Arşiv parolayla şifrelenmiş; parolasız ZIP veya TAR olarak yeniden paketleyip yükleyin")
            _spend(info.file_size, info.filename)
        return super().open(name, mode, pwd, force_zip64=force_zip64)


def tar_read(tf: tarfile.TarFile, m: tarfile.TarInfo) -> bytes | None:
    if not m.isfile():
        return None
    _spend(m.size, m.name)
    f = tf.extractfile(m)
    return f.read(m.size) if f else None


def safe_relpath(name: str) -> str | None:
    n = name.replace("\\", "/")
    if n.startswith("/") or re.match(r"^[A-Za-z]:", n) or "\x00" in n:
        return None
    parts = [p for p in n.split("/") if p not in ("", ".")]
    if not parts or ".." in parts:
        return None
    return "/".join(parts)


def inside(path: Path, root: Path) -> bool:
    try:
        return path.resolve().is_relative_to(root.resolve())
    except (OSError, ValueError):
        return False


def safe_extract(path: Path, dest: Path) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()

    def write(rel: str, reader, size: int):
        out = root / rel
        if not inside(out.parent if out.parent.exists() else root, root):
            return
        out.parent.mkdir(parents=True, exist_ok=True)
        if out.is_symlink() or not inside(out, root):
            return
        with open(out, "wb") as dst:
            left = size
            while left > 0:
                chunk = reader.read(min(left, 1 << 20))
                if not chunk:
                    break
                dst.write(chunk)
                left -= len(chunk)

    if zipfile.is_zipfile(path):
        with SafeZipFile(path) as zf:
            for m in zf.infolist():
                rel = safe_relpath(m.filename)
                if rel is None or m.is_dir() or ((m.external_attr >> 16) & 0o170000) == 0o120000:
                    continue
                with zf.open(m) as src:
                    write(rel, src, m.file_size)
    else:
        with tarfile.open(path) as tf:
            n = 0
            for m in tf:
                n += 1
                if n > LIMITS["entries"]:
                    raise UnsafeInput("Arşivde çok fazla dosya var")
                rel = safe_relpath(m.name)
                if rel is None or not m.isfile():
                    continue
                _spend(m.size, m.name)
                f = tf.extractfile(m)
                if f:
                    write(rel, f, m.size)
    return dest


def walk_files(root: Path):
    root = Path(root)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if not (Path(dirpath) / d).is_symlink()]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.is_symlink() or not p.is_file():
                continue
            yield p


def read_file(p: Path, limit: int | None = None) -> bytes:
    if p.is_symlink():
        raise UnsafeInput(f"Sembolik bağlantı okunmaz: {p.name}")
    limit = limit or LIMITS["member"]
    fd = os.open(p, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as f:
        data = f.read(limit + 1)
    if len(data) > limit:
        raise UnsafeInput(f"Dosya çok büyük: {p.name}")
    return data


_DTD = re.compile(rb"<!\s*(DOCTYPE|ENTITY)", re.I)


def xml_fromstring(data: bytes | str):
    import xml.etree.ElementTree as ET
    raw = data.encode("utf-8", "replace") if isinstance(data, str) else data
    if len(raw) > LIMITS["xml"]:
        raise UnsafeInput("XML dosyası çok büyük")
    if _DTD.search(raw[:65536]) or _DTD.search(raw):
        raise UnsafeInput("XML belge tipi / varlık tanımı içeriyor (güvenlik nedeniyle işlenmedi)")
    return ET.fromstring(raw)


_FORMULA = ("=", "+", "-", "@", "\t", "\r", "＝", "＋", "－", "＠")


def csv_cell(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s.startswith(_FORMULA) else s


def safe_url(u: str | None) -> str | None:
    if not u:
        return None
    u = u.strip()
    return u if re.match(r"^https?://", u, re.I) and not any(c in u for c in "\x00\r\n\"'<>") else None


def bytes_io(data: bytes) -> io.BytesIO:
    return io.BytesIO(data)
