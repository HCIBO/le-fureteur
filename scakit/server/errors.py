from __future__ import annotations

import re
import socket


def humanize(ex: BaseException) -> dict:
    text = f"{type(ex).__name__}: {ex}"
    host = None
    m = re.search(r"host='([^']+)'", text)
    if m:
        host = m.group(1)
    try:
        import requests
        if isinstance(ex, requests.HTTPError) and ex.response is not None:
            return {"kind": "http", "status": ex.response.status_code, "host": host}
    except ImportError:
        pass
    from ..safeio import UnsafeInput
    from .guard import BlockedAddress, TargetError
    chain = []
    e = ex
    while e is not None and len(chain) < 6:
        chain.append(e)
        e = e.__cause__ or e.__context__
    for e in chain:
        if isinstance(e, (BlockedAddress, TargetError)) or "engellendi" in str(e):
            return {"kind": "blocked", "host": host, "detail": str(e)[:200]}
        if isinstance(e, UnsafeInput):
            return {"kind": "unsafe", "detail": str(e)[:300]}
    low = text.lower()
    if isinstance(ex, socket.gaierror) or "nameresolution" in low or "name or service not known" in low \
            or "failed to resolve" in low or "getaddrinfo" in low:
        return {"kind": "dns", "host": host}
    if "timed out" in low or "timeout" in low:
        return {"kind": "timeout", "host": host}
    if "connection refused" in low or "refused" in low:
        return {"kind": "refused", "host": host}
    if "ssl" in low or "certificate" in low:
        return {"kind": "tls", "host": host}
    m = re.search(r"HTTP (\d{3})", text)
    if m:
        return {"kind": "http", "status": int(m.group(1)), "host": host}
    if "401" in text or "403" in text or "unauthor" in low:
        return {"kind": "auth", "host": host}
    return {"kind": "other", "detail": str(ex)[:300]}


def human_text(ex: BaseException) -> str:
    h = humanize(ex)
    k = h["kind"]
    if isinstance(ex, (ConnectionRefusedError,)) or k == "refused":
        return "Sunucu bağlantıyı reddetti (adres / port doğru mu?)"
    return {"dns": "Sunucu adı çözümlenemedi (DNS)", "timeout": "Sunucu yanıt vermedi (zaman aşımı)",
            "tls": "TLS / sertifika hatası", "auth": "Kimlik doğrulama reddedildi (kullanıcı adı / parola)",
            "http": f"Karşı sistem HTTP {h.get('status')} döndürdü", "blocked": "İç ağ / ayrılmış adres engellendi",
            }.get(k, f"Bağlantı kurulamadı: {h.get('detail', '')[:160]}")
