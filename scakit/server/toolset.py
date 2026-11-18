from __future__ import annotations

import base64
import socket
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from . import ratelimit, settings_store
from .db import get_db
from .deps import client_ip, current_user
from .guard import BlockedAddress, TargetError, _bad_ip, check_web_target, outbound_guard
from .models import Note, Organization, User
from .security import audit

router = APIRouter(prefix="/api/tools")
MAX_RESPONSE = 1024 * 1024
MAX_BODY = 256 * 1024
METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
_FORBIDDEN_HEADERS = {"content-length", "transfer-encoding", "connection", "upgrade", "te", "trailer",
                      "proxy-authorization", "proxy-connection", "keep-alive"}


def _net_access(db: Session, user: User) -> list[str] | None:
    if not settings_store.get_bool(db, "toolset_enabled"):
        raise HTTPException(403, "Ağ araçları yönetici tarafından kapatılmış")
    if user.role == "customer":
        if not settings_store.get_bool(db, "toolset_customers"):
            raise HTTPException(403, "Ağ araçları müşteri kullanıcılarına kapalı")
        org = db.get(Organization, user.organization_id) if user.organization_id else None
        return org.allowed_domains if org else []
    return None


def _limit(db: Session, user: User) -> None:
    try:
        per_min = int(settings_store.get(db, "toolset_rate_per_minute") or 20)
    except ValueError:
        per_min = 20
    ok, wait = ratelimit.hit(f"tools:{user.id}", per_min)
    if not ok:
        raise HTTPException(429, f"Çok fazla istek; {wait} sn sonra tekrar deneyin")


def _check_url(url: str, user: User, allowed: list[str] | None) -> str:
    try:
        return check_web_target(url, role="customer" if allowed is not None else user.role,
                                allowed_domains=allowed or [], allow_internal=False)
    except TargetError as ex:
        if "İç ağ" in str(ex):
            raise HTTPException(400, "İç ağ / ayrılmış adres engellendi")
        raise HTTPException(400, str(ex))
    except OSError:
        raise HTTPException(400, "Alan adı çözümlenemedi")


class HttpIn(BaseModel):
    method: str = "GET"
    url: str = Field(min_length=8, max_length=4000)
    headers: list[tuple[str, str]] = Field(default=[], max_length=50)
    body: str = Field(default="", max_length=MAX_BODY)
    follow_redirects: bool = False
    timeout: int = Field(default=15, ge=1, le=30)
    verify_tls: bool = True


@router.post("/http")
def http_request(body: HttpIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    import requests
    allowed = _net_access(db, user)
    _limit(db, user)
    method = body.method.upper()
    if method not in METHODS:
        raise HTTPException(400, "Desteklenmeyen yöntem")
    url = _check_url(body.url, user, allowed)
    headers = {}
    for k, v in body.headers:
        k, v = k.strip(), v.strip()
        if not k:
            continue
        if any(c in k + v for c in "\r\n\0") or not k.isascii() or len(k) > 200 or len(v) > 8000:
            raise HTTPException(400, f"Geçersiz başlık: {k[:40]}")
        if k.lower() in _FORBIDDEN_HEADERS:
            raise HTTPException(400, f"Bu başlık ayarlanamaz: {k}")
        headers[k] = v
    headers.setdefault("User-Agent", "LeFureteur-Toolset/1.0")
    audit(db, user, "tools.http", "url", "", f"{method} {url}"[:500], client_ip(request))

    hops = []
    started = time.perf_counter()
    try:
        with outbound_guard(True), requests.Session() as s:
            s.trust_env = False
            cur, m, data = url, method, body.body.encode() if body.body else None
            for _ in range(6):
                r = s.request(m, cur, headers=headers, data=data, timeout=body.timeout, allow_redirects=False,
                              stream=True, verify=body.verify_tls)
                if body.follow_redirects and r.is_redirect and r.headers.get("location"):
                    nxt = requests.compat.urljoin(cur, r.headers["location"])
                    hops.append({"status": r.status_code, "url": cur, "location": nxt})
                    r.close()
                    cur = _check_url(nxt, user, allowed)
                    if r.status_code in (301, 302, 303) and m != "HEAD":
                        m, data = "GET", None
                    continue
                break
            chunks, size, truncated = [], 0, False
            if method != "HEAD":
                for chunk in r.iter_content(16384):
                    size += len(chunk)
                    if size > MAX_RESPONSE:
                        chunks.append(chunk[: MAX_RESPONSE - (size - len(chunk))])
                        truncated = True
                        break
                    chunks.append(chunk)
            raw = b"".join(chunks)
            peer = None
            try:
                peer = r.raw._connection.sock.getpeername()[0]
            except Exception:
                pass
            r.close()
    except requests.exceptions.SSLError:
        raise HTTPException(502, "TLS sertifikası doğrulanamadı (gerekirse \"TLS doğrula\" seçeneğini kapatın)")
    except requests.exceptions.Timeout:
        raise HTTPException(504, f"Zaman aşımı ({body.timeout} sn)")
    except requests.exceptions.ConnectionError as ex:
        cause = ex
        while cause is not None and not isinstance(cause, BlockedAddress):
            cause = cause.__cause__ or cause.__context__
        raise HTTPException(400 if cause else 502, str(cause) if cause else "Bağlantı kurulamadı")
    except requests.exceptions.RequestException as ex:
        raise HTTPException(400, f"İstek hatası: {type(ex).__name__}")
    elapsed = round((time.perf_counter() - started) * 1000)
    ctype = r.headers.get("content-type", "")
    try:
        text = raw.decode(r.encoding or "utf-8") if raw else ""
        binary = "\0" in text[:4096]
    except (UnicodeDecodeError, LookupError):
        text, binary = "", True
    return {"status": r.status_code, "reason": r.reason, "url": r.url, "ip": peer, "elapsed_ms": elapsed,
            "http_version": {10: "HTTP/1.0", 11: "HTTP/1.1"}.get(getattr(r.raw, "version", 11), "HTTP/1.1"),
            "headers": list(r.headers.items()), "content_type": ctype, "size": len(raw), "truncated": truncated,
            "body": "" if binary else text, "body_b64": base64.b64encode(raw[:65536]).decode() if binary else "",
            "binary": binary, "redirects": hops}


class PingIn(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(default=443, ge=1, le=65535)
    count: int = Field(default=4, ge=1, le=10)


@router.post("/ping")
def tcp_ping(body: PingIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    allowed = _net_access(db, user)
    _limit(db, user)
    host = body.host.strip().lower().rstrip(".")
    if "://" in host:
        from urllib.parse import urlparse
        host = urlparse(host).hostname or ""
    _check_url(f"https://{host}/" if ":" not in host else f"https://[{host}]/", user, allowed)
    audit(db, user, "tools.ping", "host", "", f"{host}:{body.port}", client_ip(request))
    try:
        infos = socket.getaddrinfo(host, body.port, 0, socket.SOCK_STREAM)
    except socket.gaierror:
        raise HTTPException(400, "Alan adı çözümlenemedi")
    ips = list(dict.fromkeys(i[4][0] for i in infos))
    if any(_bad_ip(ip) for ip in ips):
        raise HTTPException(400, "İç ağ / ayrılmış adres engellendi")
    target = ips[0]
    fam = socket.AF_INET6 if ":" in target else socket.AF_INET
    results = []
    for i in range(body.count):
        t0 = time.perf_counter()
        try:
            with socket.socket(fam, socket.SOCK_STREAM) as sock:
                sock.settimeout(3)
                sock.connect((target, body.port))
            results.append({"seq": i + 1, "ok": True, "ms": round((time.perf_counter() - t0) * 1000, 1)})
        except socket.timeout:
            results.append({"seq": i + 1, "ok": False, "error": "timeout"})
        except OSError as ex:
            results.append({"seq": i + 1, "ok": False, "error": "refused" if isinstance(ex, ConnectionRefusedError) else "error"})
        if i + 1 < body.count:
            time.sleep(0.3)
    oks = [r["ms"] for r in results if r["ok"]]
    return {"host": host, "port": body.port, "ip": target, "addresses": ips, "results": results,
            "sent": len(results), "received": len(oks), "loss": round(100 * (1 - len(oks) / len(results))),
            "min": min(oks) if oks else None, "avg": round(sum(oks) / len(oks), 1) if oks else None,
            "max": max(oks) if oks else None}


@router.get("/status")
def tools_status(user: User = Depends(current_user), db: Session = Depends(get_db)):
    try:
        allowed = _net_access(db, user)
        return {"network": True, "allowed_domains": allowed, "rate_per_minute": settings_store.get(db, "toolset_rate_per_minute")}
    except HTTPException as ex:
        return {"network": False, "reason": ex.detail}


class NoteIn(BaseModel):
    title: str = Field(default="", max_length=200)
    body: str = Field(default="", max_length=100_000)
    pinned: bool = False


def note_out(n: Note) -> dict:
    def iso(d):
        return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).isoformat() if d else None
    return {"id": n.id, "title": n.title, "body": n.body, "pinned": n.pinned, "created_at": iso(n.created_at),
            "updated_at": iso(n.updated_at)}


def _note(db: Session, user: User, note_id: int) -> Note:
    n = db.get(Note, note_id)
    if n is None or n.user_id != user.id:
        raise HTTPException(404, "Not bulunamadı")
    return n


@router.get("/notes")
def list_notes(user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.query(Note).filter_by(user_id=user.id).order_by(Note.pinned.desc(), Note.updated_at.desc()).limit(500)
    return [note_out(n) for n in rows]


@router.post("/notes")
def create_note(body: NoteIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if db.query(Note).filter_by(user_id=user.id).count() >= 500:
        raise HTTPException(400, "Not sınırına ulaştınız (500)")
    n = Note(user_id=user.id, title=body.title.strip(), body=body.body, pinned=body.pinned)
    db.add(n)
    db.commit()
    return note_out(n)


@router.put("/notes/{note_id}")
def update_note(note_id: int, body: NoteIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    n = _note(db, user, note_id)
    n.title, n.body, n.pinned, n.updated_at = body.title.strip(), body.body, body.pinned, datetime.now(timezone.utc)
    db.commit()
    return note_out(n)


@router.delete("/notes/{note_id}")
def delete_note(note_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    db.delete(_note(db, user, note_id))
    db.commit()
    return {"ok": True}
