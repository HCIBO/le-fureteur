from __future__ import annotations

import sqlite3
import struct

TAG_NAME, TAG_VERSION, TAG_RELEASE, TAG_EPOCH, TAG_LICENSE, TAG_SOURCERPM = 1000, 1001, 1002, 1003, 1014, 1044
T_INT32, T_STRING, T_STRING_ARRAY, T_I18N = 4, 6, 8, 9


def parse_header(blob: bytes) -> dict:
    if len(blob) < 8:
        return {}
    il, dl = struct.unpack_from(">II", blob, 0)
    if il > 100000 or 8 + il * 16 + dl > len(blob) + 16:
        return {}
    store = 8 + il * 16
    out = {}
    for i in range(il):
        tag, typ, off, cnt = struct.unpack_from(">iiii", blob, 8 + i * 16)
        if tag not in (TAG_NAME, TAG_VERSION, TAG_RELEASE, TAG_EPOCH, TAG_LICENSE, TAG_SOURCERPM):
            continue
        p = store + off
        if typ == T_INT32 and cnt >= 1:
            out[tag] = struct.unpack_from(">i", blob, p)[0]
        elif typ in (T_STRING, T_STRING_ARRAY, T_I18N):
            end = blob.find(b"\x00", p)
            out[tag] = blob[p:end if end >= 0 else None].decode("utf-8", "replace")
    return out


def _headers_sqlite(path: str):
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        for (blob,) in con.execute("SELECT blob FROM Packages"):
            yield bytes(blob)
    finally:
        con.close()


def _headers_bdb(data: bytes):
    if len(data) < 512:
        return
    magic_le = struct.unpack_from("<I", data, 12)[0]
    if magic_le == 0x061561:
        e = "<"
    elif struct.unpack_from(">I", data, 12)[0] == 0x061561:
        e = ">"
    else:
        return
    pagesize = struct.unpack_from(e + "I", data, 20)[0]
    if pagesize not in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536):
        return
    npages = len(data) // pagesize

    def page(n):
        return data[n * pagesize:(n + 1) * pagesize]

    def overflow(pgno, total):
        buf, seen = bytearray(), set()
        while pgno and pgno < npages and pgno not in seen and len(buf) < total:
            seen.add(pgno)
            pg = page(pgno)
            nxt = struct.unpack_from(e + "I", pg, 16)[0]
            used = struct.unpack_from(e + "H", pg, 22)[0]
            buf += pg[26:26 + used]
            pgno = nxt
        return bytes(buf[:total])

    for n in range(1, npages):
        pg = page(n)
        if len(pg) < 26 or pg[25] not in (2, 13):
            continue
        entries = struct.unpack_from(e + "H", pg, 20)[0]
        offs = [struct.unpack_from(e + "H", pg, 26 + 2 * i)[0] for i in range(entries)]
        for i in range(1, entries, 2):
            off = offs[i]
            if off >= pagesize:
                continue
            kind = pg[off]
            if kind == 3:
                pgno, tlen = struct.unpack_from(e + "II", pg, off + 4)
                yield overflow(pgno, tlen)
            elif kind == 1:
                end = offs[i - 1] if i - 1 >= 0 and offs[i - 1] > off else pagesize
                yield pg[off + 1:end]


def read_rpmdb(path: str) -> list[dict]:
    with open(path, "rb") as f:
        head = f.read(16)
    if head.startswith(b"SQLite format 3"):
        blobs = _headers_sqlite(path)
    else:
        with open(path, "rb") as f:
            blobs = list(_headers_bdb(f.read()))
    out, seen = [], set()
    for blob in blobs:
        h = parse_header(blob)
        name, ver, rel = h.get(TAG_NAME), h.get(TAG_VERSION), h.get(TAG_RELEASE)
        if not name or not ver or name == "gpg-pubkey":
            continue
        full = f"{h[TAG_EPOCH]}:{ver}-{rel}" if h.get(TAG_EPOCH) else f"{ver}-{rel}"
        if (name, full) in seen:
            continue
        seen.add((name, full))
        src = h.get(TAG_SOURCERPM, "")
        src_name = src.rsplit("-", 2)[0] if src.endswith(".src.rpm") else ""
        out.append({"name": name, "version": full, "source": src_name, "license": h.get(TAG_LICENSE, "")})
    return out
