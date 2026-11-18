import io
import json
import struct
import zipfile

FIX = __import__("pathlib").Path(__file__).parent / "fixtures"


def osv(vid, eco, name, ranges=None, versions=None, severity=None, aliases=None, withdrawn=None, upstream=None,
        db_sev=None):
    aff = {"package": {"ecosystem": eco, "name": name}}
    if ranges is not None:
        aff["ranges"] = ranges
    if versions is not None:
        aff["versions"] = versions
    v = {"id": vid, "modified": "2024-01-01T00:00:00Z", "affected": [aff], "summary": f"{name} test vuln"}
    if severity:
        v["severity"] = [{"type": "CVSS_V3", "score": severity}]
    if aliases:
        v["aliases"] = aliases
    if upstream:
        v["upstream"] = upstream
    if withdrawn:
        v["withdrawn"] = withdrawn
    if db_sev:
        v["database_specific"] = {"severity": db_sev}
    return v


def eco_range(*events, typ="ECOSYSTEM"):
    return [{"type": typ, "events": [dict([e]) for e in events]}]


def osv_zip(vulns) -> bytes:
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        for v in vulns:
            z.writestr(v["id"] + ".json", json.dumps(v))
    return b.getvalue()


def make_dex(strings) -> bytes:
    header = bytearray(0x70)
    header[0:8] = b"dex\n035\x00"
    n = len(strings)
    ids_off = 0x70
    data_off = ids_off + 4 * n
    ids, data = bytearray(), bytearray()
    for s in strings:
        enc = s.encode("utf-8")
        ids += struct.pack("<I", data_off + len(data))
        size, buf = len(s), bytearray()
        while True:
            byte = size & 0x7F
            size >>= 7
            buf.append(byte | (0x80 if size else 0))
            if not size:
                break
        data += buf + enc + b"\x00"
    struct.pack_into("<II", header, 0x38, n, ids_off)
    return bytes(header + ids + data)
