from __future__ import annotations

import base64
import gzip
import io
import json
import re
import zlib
from pathlib import Path
from urllib.parse import urldefrag, urljoin, urlparse

from ...safeio import UnsafeInput

MAX_ENTRIES = 20_000
MAX_BODY = 16 * 1024 * 1024
MAX_FILE = 1024 * 1024 * 1024
SECRET_REQ_HEADERS = {"cookie", "authorization", "proxy-authorization", "x-api-key", "x-auth-token", "x-csrf-token",
                      "x-xsrf-token", "api-key", "apikey", "x-amz-security-token"}
SECRET_RESP_HEADERS = {"set-cookie", "set-cookie2", "authorization", "www-authenticate"}


def sniff(path: Path) -> str | None:
    try:
        with open(path, "rb") as f:
            head = f.read(8192)
    except OSError:
        return None
    text = head.lstrip(b"\xef\xbb\xbf").lstrip()
    if text.startswith(b"{") and b'"log"' in head and (b'"entries"' in head or b'"creator"' in head or b'"version"' in head):
        return "har"
    if b"<items" in head and b"burpVersion" in head:
        return "burp"
    return None


class _Chain(io.RawIOBase):
    def __init__(self, first: bytes, rest):
        self.first, self.rest = first, rest

    def readable(self):
        return True

    def readinto(self, b):
        if self.first:
            n = min(len(b), len(self.first))
            b[:n] = self.first[:n]
            self.first = self.first[n:]
            return n
        data = self.rest.read(len(b))
        b[:len(data)] = data
        return len(data)


def _burp_items(path: Path):
    import xml.etree.ElementTree as ET
    f = open(path, "rb")
    try:
        head = f.read(65536)
        if re.search(rb"<!ENTITY", head, re.I):
            raise UnsafeInput("XML varlık (ENTITY) tanımı içeriyor; güvenlik nedeniyle işlenmedi")
        m = re.search(rb"<!DOCTYPE[^\[>]*(\[.*?\])?\s*>", head, re.S | re.I)
        if m:
            head = head[:m.start()] + head[m.end():]
        if re.search(rb"<!DOCTYPE|<!ENTITY", head, re.I):
            raise UnsafeInput("XML belge tipi tanımı işlenemedi")
        stream = io.BufferedReader(_Chain(head, f))
        n = 0
        for _ev, el in ET.iterparse(stream, events=("end",)):
            if el.tag != "item":
                continue
            n += 1
            if n > MAX_ENTRIES:
                raise UnsafeInput("Trafik kaydında çok fazla istek var")
            url = (el.findtext("url") or "").strip()
            resp = el.find("response")
            raw = b""
            if resp is not None and resp.text:
                raw = base64.b64decode(resp.text) if resp.get("base64") == "true" else resp.text.encode("utf-8", "replace")
            el.clear()
            if url and raw:
                yield url, raw
    finally:
        f.close()


def _parse_raw_response(raw: bytes) -> tuple[int, dict, bytes]:
    head, _, body = raw.partition(b"\r\n\r\n")
    if not _:
        head, _, body = raw.partition(b"\n\n")
    lines = head.decode("iso-8859-1").splitlines()
    status = 0
    if lines:
        parts = lines[0].split()
        status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    headers: dict[str, str] = {}
    for ln in lines[1:]:
        k, sep, v = ln.partition(":")
        if sep:
            headers[k.strip()] = v.strip()
    low = {k.lower(): v for k, v in headers.items()}
    if "chunked" in low.get("transfer-encoding", "").lower():
        body = _dechunk(body)
    enc = low.get("content-encoding", "").lower()
    try:
        if enc == "gzip":
            body = gzip.decompress(body)[:MAX_BODY]
        elif enc == "deflate":
            body = zlib.decompress(body)[:MAX_BODY]
        elif enc == "br":
            try:
                import brotli
                body = brotli.decompress(body)[:MAX_BODY]
            except ImportError:
                body = b""
    except Exception:
        body = b""
    return status, headers, body[:MAX_BODY]


def _dechunk(b: bytes) -> bytes:
    out, i = bytearray(), 0
    while i < len(b) and len(out) < MAX_BODY:
        j = b.find(b"\r\n", i)
        if j < 0:
            break
        try:
            size = int(b[i:j].split(b";")[0], 16)
        except ValueError:
            break
        if size == 0:
            break
        out += b[j + 2:j + 2 + size]
        i = j + 2 + size + 2
    return bytes(out)


def _load_har(path: Path) -> dict:
    if path.stat().st_size > MAX_FILE:
        raise UnsafeInput("HAR dosyası çok büyük")
    with open(path, "rb") as f:
        doc = json.loads(f.read().decode("utf-8-sig", "replace"))
    entries = (doc.get("log") or {}).get("entries")
    if not isinstance(entries, list):
        raise UnsafeInput("Geçerli bir HAR dosyası değil")
    if len(entries) > MAX_ENTRIES:
        raise UnsafeInput("Trafik kaydında çok fazla istek var")
    return doc


def _har_body(content: dict) -> bytes:
    text = content.get("text")
    if not isinstance(text, str):
        return b""
    if content.get("encoding") == "base64":
        try:
            return base64.b64decode(text)[:MAX_BODY]
        except Exception:
            return b""
    return text.encode("utf-8", "replace")[:MAX_BODY]


def load(path: str | Path) -> list[dict]:
    path = Path(path)
    kind = sniff(path)
    out = []
    if kind == "har":
        for e in _load_har(path)["log"]["entries"]:
            req, resp = e.get("request") or {}, e.get("response") or {}
            url = req.get("url")
            if not isinstance(url, str) or not url.startswith(("http://", "https://")):
                continue
            headers = {h.get("name", ""): h.get("value", "") for h in resp.get("headers") or [] if isinstance(h, dict)}
            out.append({"url": url, "status": int(resp.get("status") or 0), "headers": headers,
                        "body": _har_body(resp.get("content") or {})})
    elif kind == "burp":
        for url, raw in _burp_items(path):
            st, headers, body = _parse_raw_response(raw)
            out.append({"url": url, "status": st, "headers": headers, "body": body})
    else:
        raise UnsafeInput("Dosya HAR veya Burp XML biçiminde değil")
    return out


def sanitize_upload(path: Path) -> bool:
    kind = sniff(path)
    if kind is None:
        return False
    if kind == "burp":
        entries = []
        for r in load(path):
            entries.append({"request": {"method": "GET", "url": r["url"], "headers": []},
                            "response": {"status": r["status"],
                                         "headers": [{"name": k, "value": v} for k, v in r["headers"].items()
                                                     if k.lower() not in SECRET_RESP_HEADERS],
                                         "content": {"mimeType": r["headers"].get("Content-Type", ""),
                                                     "encoding": "base64", "text": base64.b64encode(r["body"]).decode()}}})
        doc = {"log": {"version": "1.2", "creator": {"name": "Le Fureteur (Burp içe aktarma)"}, "entries": entries}}
    else:
        doc = _load_har(path)
        for e in doc["log"]["entries"]:
            req = e.get("request") or {}
            req["headers"] = [h for h in req.get("headers") or [] if isinstance(h, dict)
                              and str(h.get("name", "")).lower() not in SECRET_REQ_HEADERS]
            req["cookies"] = []
            req.pop("postData", None)
            resp = e.get("response") or {}
            resp["headers"] = [h for h in resp.get("headers") or [] if isinstance(h, dict)
                               and str(h.get("name", "")).lower() not in SECRET_RESP_HEADERS]
            resp["cookies"] = []
    path.write_text(json.dumps(doc), encoding="utf-8")
    return True


def scan_traffic(path: str, target: str = "", evidence_dir=None, log=None):
    from requests.structures import CaseInsensitiveDict

    from .web import WebScanner
    log = log or (lambda m: None)
    entries = load(path)
    store: dict[str, dict] = {}
    for e in entries:
        u = urldefrag(e["url"])[0]
        if u not in store or (store[u]["status"] != 200 and e["status"] == 200):
            store[u] = e
    html = [u for u, e in store.items() if e["status"] == 200 and
            "html" in {k.lower(): v for k, v in e["headers"].items()}.get("content-type", "").lower()]
    with_body = sum(1 for e in store.values() if e["body"])
    if not store:
        return [], ["Trafik kaydında incelenecek yanıt yok"]
    hosts = {urlparse(u).hostname for u in html} or {urlparse(next(iter(store))).hostname}
    log(f"  traffic recording: {len(store)} URLs, {len(html)} HTML pages, {with_body} with a response body")

    class _Resp:
        def __init__(self, url, e):
            self.url, self.status_code = url, e["status"]
            self.headers = CaseInsensitiveDict(e["headers"])
            m = re.search(r"charset=([\w-]+)", self.headers.get("content-type", ""), re.I)
            self.encoding = m.group(1) if m else "utf-8"

    class OfflineScanner(WebScanner):
        def in_scope(self, url):
            return urldefrag(url)[0] in store or urlparse(url).hostname in hosts

        def get(self, url, max_bytes=None, external=False, _retry=True):
            u = urldefrag(url)[0]
            for _ in range(6):
                e = store.get(u)
                if e is None:
                    return None
                loc = {k.lower(): v for k, v in e["headers"].items()}.get("location")
                if 300 <= e["status"] < 400 and loc:
                    u = urldefrag(urljoin(u, loc))[0]
                    continue
                self.requests += 1
                from .web import detect_waf
                vendor = detect_waf(e["status"], e["headers"], e["body"])
                if vendor:
                    self.waf_hits[vendor] = self.waf_hits.get(vendor, 0) + 1
                self.req_log.append({"url": u, "status": e["status"], "bytes": len(e["body"]), "source": "trafik kaydı"})
                return _Resp(u, e), e["body"][:max_bytes] if max_bytes else e["body"]
            return None

    sc = OfflineScanner(html[0] if html else next(iter(store)), target or next(iter(hosts)),
                        Path(evidence_dir) if evidence_dir else None, max_pages=max(1, len(html)), delay=0, probe=False,
                        headers=None, verify_tls=True, log=log)
    sc.seeds = html
    comps, notes = sc.run()
    if store and with_body < len(store) * 0.3:
        notes.append("Trafik kaydındaki yanıtların çoğunda içerik yok; HAR'ı \"içerikle birlikte\" (Save all as HAR with "
                     "content) kaydedin veya Burp'te yanıtları da dahil edin.")
    return comps, notes
