from __future__ import annotations

import json
import re
import struct

NATIVE_PATTERNS = [
    (re.compile(rb"OpenSSL (\d+\.\d+\.\d+[a-z]{0,2})(?:-[\w.]+)?\s+\d{1,2} [A-Z][a-z]{2} \d{4}"), "openssl"),
    (re.compile(rb"(?:deflate|inflate) (\d+\.\d+\.\d+(?:\.\d+)?) Copyright"), "zlib"),
    (re.compile(rb"libcurl/(\d+\.\d+\.\d+)"), "curl"),
    (re.compile(rb"libpng version (\d+\.\d+\.\d+)"), "libpng"),
    (re.compile(rb"libjpeg-turbo version (\d+\.\d+\.\d+)"), "libjpeg-turbo"),
    (re.compile(rb"mbed TLS (\d+\.\d+\.\d+)"), "mbedtls"),
    (re.compile(rb"Lavc(\d+\.\d+\.\d+)"), "ffmpeg-libavcodec"),
    (re.compile(rb"(\d+\.\d+\.\d+) community"), "sqlcipher"),
    (re.compile(rb"(\d+\.\d+\.\d+) \((?:stable|beta|dev)\) \("), "dart-sdk"),
    (re.compile(rb"Electron/(\d+\.\d+\.\d+)"), "electron"),
]
SQLITE_VER = re.compile(rb"\x00(3\.[1-4]\d\.\d{1,2})\x00")
NPM_NATIVE = {"electron"}


def scan_native(data: bytes) -> list[tuple[str, str, str, str]]:
    out, seen = [], set()
    for rx, name in NATIVE_PATTERNS:
        m = rx.search(data)
        if m:
            ver = m.group(1).decode()
            if (name, ver) not in seen:
                seen.add((name, ver))
                out.append(("npm" if name in NPM_NATIVE else "generic", name, ver,
                            m.group(0)[:80].decode("ascii", "replace")))
    if b"SQLite format 3" in data:
        m = SQLITE_VER.search(data)
        if m:
            out.append(("generic", "sqlite", m.group(1).decode(), "sqlite version string"))
    return out


def pe_info(data: bytes) -> dict | None:
    if data[:2] != b"MZ" or len(data) < 0x40:
        return None
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if pe + 24 > len(data) or data[pe:pe + 4] != b"PE\x00\x00":
        return None
    opt = pe + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    dd = opt + (96 if magic == 0x10B else 112)
    managed = False
    if dd + 15 * 8 <= len(data):
        rva, size = struct.unpack_from("<II", data, dd + 14 * 8)
        managed = rva != 0 and size != 0
    info = {"managed": managed}
    for key in ("ProductName", "ProductVersion", "FileVersion", "OriginalFilename", "CompanyName", "FileDescription"):
        k = key.encode("utf-16-le") + b"\x00\x00"
        i = data.find(k)
        if i < 0:
            continue
        j = i + len(k)
        while j % 4:
            j += 1
        end = data.find(b"\x00\x00", j)
        while end > 0 and (end - j) % 2:
            end = data.find(b"\x00\x00", end + 1)
        if end > j:
            val = data[j:end].decode("utf-16-le", "replace").strip()
            if val and len(val) < 200:
                info[key] = val
    return info


def clean_version(v: str) -> str:
    v = v.split("+", 1)[0].strip()
    v = re.sub(r"\s.*$", "", v)
    return v.replace(",", ".")


def macho_encrypted(data: bytes) -> bool | None:
    def thin(off):
        magic = data[off:off + 4]
        if magic == b"\xcf\xfa\xed\xfe":
            hdr = 32
        elif magic == b"\xce\xfa\xed\xfe":
            hdr = 28
        else:
            return None
        ncmds = struct.unpack_from("<I", data, off + 16)[0]
        p = off + hdr
        for _ in range(min(ncmds, 512)):
            if p + 8 > len(data):
                break
            cmd, size = struct.unpack_from("<II", data, p)
            if cmd in (0x21, 0x2C) and p + 20 <= len(data):
                return struct.unpack_from("<I", data, p + 16)[0] != 0
            if size < 8:
                break
            p += size
        return False

    if data[:4] in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
        n = struct.unpack_from(">I", data, 4)[0]
        res = None
        for i in range(min(n, 8)):
            off = struct.unpack_from(">I", data, 8 + i * 20 + 8)[0]
            r = thin(off)
            res = r if res is None else (res or r)
        return res
    return thin(0)


def asar_files(data: bytes):
    if len(data) < 16:
        return
    header_size = struct.unpack_from("<I", data, 4)[0]
    json_len = struct.unpack_from("<I", data, 12)[0]
    try:
        header = json.loads(data[16:16 + json_len])
    except ValueError:
        return
    base = 8 + header_size

    def walk(node, prefix):
        for name, ent in (node.get("files") or {}).items():
            path = f"{prefix}/{name}" if prefix else name
            if "files" in ent:
                yield from walk(ent, path)
            elif not ent.get("unpacked") and "offset" in ent:
                off = base + int(ent["offset"])
                yield path, data[off:off + int(ent.get("size", 0))]

    yield from walk(header, "")
