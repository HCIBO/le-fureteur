from __future__ import annotations

import base64
import json
import re
from urllib.parse import urlparse

from .guard import TargetError, check_web_target
from .security import decrypt, encrypt

TYPES = ("none", "basic", "bearer", "header", "cookie", "form")
SECRET_FIELDS = {"password", "token", "value", "cookie"}
FORBIDDEN_HEADERS = {"host", "content-length", "transfer-encoding", "connection", "upgrade", "te", "trailer",
                     "proxy-authorization", "expect"}
_HNAME = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$")
_FIELD = re.compile(r"^[A-Za-z0-9_.\-\[\]:]{1,100}$")


class AuthError(ValueError):
    pass


def _clean(v, name: str, maxlen: int = 4096, required: bool = True) -> str:
    v = "" if v is None else str(v)
    if any(c in v for c in "\r\n\0"):
        raise AuthError(f"{name}: satır sonu / boş karakter içeremez")
    if required and not v.strip():
        raise AuthError(f"{name} gerekli")
    if len(v) > maxlen:
        raise AuthError(f"{name} çok uzun")
    return v


def load(enc: str | None) -> dict:
    return json.loads(decrypt(enc)) if enc else {"type": "none"}


def dump(auth: dict) -> str | None:
    return None if auth.get("type", "none") == "none" else encrypt(json.dumps(auth))


def validate(data: dict, old: dict, target_url: str, *, role: str, allowed_domains: list[str],
             allow_internal: bool) -> dict:
    kind = (data or {}).get("type", "none")
    if kind not in TYPES:
        raise AuthError("Geçersiz kimlik doğrulama türü")
    if kind == "none":
        return {"type": "none"}
    keep = old if old.get("type") == kind else {}

    def secret(field, label):
        v = data.get(field)
        if v in (None, "") and keep.get(field):
            return keep[field]
        return _clean(v, label)

    if kind == "basic":
        return {"type": kind, "username": _clean(data.get("username"), "Kullanıcı adı", 256),
                "password": secret("password", "Parola")}
    if kind == "bearer":
        return {"type": kind, "token": secret("token", "Token")}
    if kind == "header":
        name = _clean(data.get("name"), "Başlık adı", 64)
        if not _HNAME.match(name) or name.lower() in FORBIDDEN_HEADERS:
            raise AuthError("Geçersiz veya izin verilmeyen başlık adı")
        return {"type": kind, "name": name, "value": secret("value", "Başlık değeri")}
    if kind == "cookie":
        return {"type": kind, "cookie": secret("cookie", "Çerez")}
    host = urlparse(target_url).hostname
    out = {"type": "form", "format": "json" if data.get("format") == "json" else "form"}
    for f in ("login_url", "action_url"):
        u = _clean(data.get(f), f, 2048, required=(f == "login_url"))
        if u:
            try:
                u = check_web_target(u, role=role, allowed_domains=allowed_domains, allow_internal=allow_internal)
            except TargetError as ex:
                raise AuthError(str(ex)) from ex
            if urlparse(u).hostname != host:
                raise AuthError("Giriş adresi hedefle aynı makinede olmalı")
        out[f] = u
    for f, label in (("username_field", "Kullanıcı adı alanı"), ("password_field", "Parola alanı")):
        v = _clean(data.get(f), label, 100)
        if not _FIELD.match(v):
            raise AuthError(f"{label} geçersiz")
        out[f] = v
    if data.get("csrf_field"):
        v = _clean(data["csrf_field"], "CSRF alanı", 100)
        if not _FIELD.match(v):
            raise AuthError("CSRF alanı geçersiz")
        out["csrf_field"] = v
    out["username"] = _clean(data.get("username"), "Kullanıcı adı", 256)
    out["password"] = secret("password", "Parola")
    for f in ("success_text", "failure_text"):
        if data.get(f):
            out[f] = _clean(data[f], f, 500)
    return out


def masked(auth: dict) -> dict:
    return {k: (bool(v) if k in SECRET_FIELDS else v) for k, v in auth.items()}


def to_scan(auth: dict) -> tuple[list[str], dict | None]:
    kind = auth.get("type", "none")
    if kind == "basic":
        cred = base64.b64encode(f"{auth['username']}:{auth['password']}".encode()).decode()
        return [f"Authorization: Basic {cred}"], None
    if kind == "bearer":
        return [f"Authorization: Bearer {auth['token']}"], None
    if kind == "header":
        return [f"{auth['name']}: {auth['value']}"], None
    if kind == "cookie":
        return [f"Cookie: {auth['cookie']}"], None
    if kind == "form":
        return [], {k: v for k, v in auth.items() if k != "type"}
    return [], None
