from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from urllib.parse import urlencode

from sqlalchemy.orm import Session

from . import settings_store
from .config import get_config

COOKIE = "lf_oidc"
_CACHE: dict = {}
ALLOWED_ALGS = ("RS256", "RS384", "RS512", "ES256", "ES384")


class OIDCError(Exception):
    pass


def enabled(db: Session) -> bool:
    return settings_store.get_bool(db, "oidc_enabled") and bool(settings_store.get(db, "oidc_issuer")) \
        and bool(settings_store.get(db, "oidc_client_id"))


def _http_get(url: str) -> dict:
    import requests
    r = requests.get(url, timeout=10)
    r.raise_for_status()
    return r.json()


def _http_post(url: str, data: dict) -> dict:
    import requests
    r = requests.post(url, data=data, timeout=15, headers={"Accept": "application/json"})
    if r.status_code >= 400:
        raise OIDCError(f"Kimlik sağlayıcı token isteğini reddetti (HTTP {r.status_code})")
    return r.json()


def discovery(db: Session) -> dict:
    issuer = settings_store.get(db, "oidc_issuer").rstrip("/")
    hit = _CACHE.get(("disc", issuer))
    if hit and hit[0] > time.time():
        return hit[1]
    doc = _http_get(f"{issuer}/.well-known/openid-configuration")
    if doc.get("issuer", "").rstrip("/") != issuer:
        raise OIDCError("Kimlik sağlayıcının issuer değeri ayarla eşleşmiyor")
    _CACHE[("disc", issuer)] = (time.time() + 3600, doc)
    return doc


def _jwks(uri: str, refresh: bool = False) -> dict:
    hit = _CACHE.get(("jwks", uri))
    if hit and hit[0] > time.time() and not refresh:
        return hit[1]
    doc = _http_get(uri)
    _CACHE[("jwks", uri)] = (time.time() + 3600, doc)
    return doc


def _sign(payload: dict) -> str:
    raw = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    mac = hmac.new(get_config().secret_key.encode(), f"oidc:{raw}".encode(), hashlib.sha256).hexdigest()
    return f"{raw}.{mac}"


def _unsign(value: str | None) -> dict:
    if not value or "." not in value:
        raise OIDCError("SSO oturumu bulunamadı; girişi baştan başlatın")
    raw, mac = value.rsplit(".", 1)
    good = hmac.new(get_config().secret_key.encode(), f"oidc:{raw}".encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac, good):
        raise OIDCError("SSO oturumu doğrulanamadı")
    data = json.loads(base64.urlsafe_b64decode(raw))
    if data.get("exp", 0) < time.time():
        raise OIDCError("SSO oturumunun süresi doldu; girişi baştan başlatın")
    return data


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def redirect_uri(db: Session, base_url: str) -> str:
    base = (settings_store.get(db, "public_url") or base_url).rstrip("/")
    return f"{base}/api/auth/oidc/callback"


def start(db: Session, base_url: str) -> tuple[str, str]:
    d = discovery(db)
    state, nonce, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(24), secrets.token_urlsafe(48)
    challenge = _b64u(hashlib.sha256(verifier.encode()).digest())
    q = {"response_type": "code", "client_id": settings_store.get(db, "oidc_client_id"),
         "redirect_uri": redirect_uri(db, base_url), "scope": "openid email profile", "state": state,
         "nonce": nonce, "code_challenge": challenge, "code_challenge_method": "S256"}
    cookie = _sign({"state": state, "nonce": nonce, "verifier": verifier, "exp": time.time() + 600})
    return f"{d['authorization_endpoint']}?{urlencode(q)}", cookie


def _public_key(jwk: dict):
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    if jwk.get("kty") == "RSA":
        return rsa.RSAPublicNumbers(int.from_bytes(_b64d(jwk["e"]), "big"),
                                    int.from_bytes(_b64d(jwk["n"]), "big")).public_key()
    if jwk.get("kty") == "EC":
        curve = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1()}[jwk["crv"]]
        return ec.EllipticCurvePublicNumbers(int.from_bytes(_b64d(jwk["x"]), "big"),
                                             int.from_bytes(_b64d(jwk["y"]), "big"), curve).public_key()
    raise OIDCError("Desteklenmeyen anahtar türü")


def verify_id_token(db: Session, token: str, nonce: str) -> dict:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    try:
        h64, p64, s64 = token.split(".")
        header, claims, sig = json.loads(_b64d(h64)), json.loads(_b64d(p64)), _b64d(s64)
    except (ValueError, json.JSONDecodeError) as ex:
        raise OIDCError("id_token biçimi geçersiz") from ex
    alg = header.get("alg")
    if alg not in ALLOWED_ALGS:
        raise OIDCError(f"İzin verilmeyen imza algoritması: {alg}")
    d = discovery(db)
    keys = _jwks(d["jwks_uri"]).get("keys", [])
    jwk = next((k for k in keys if k.get("kid") == header.get("kid")), None)
    if jwk is None:
        keys = _jwks(d["jwks_uri"], refresh=True).get("keys", [])
        jwk = next((k for k in keys if k.get("kid") == header.get("kid")), None)
    if jwk is None:
        raise OIDCError("İmza anahtarı bulunamadı")
    key = _public_key(jwk)
    h = {"256": hashes.SHA256(), "384": hashes.SHA384(), "512": hashes.SHA512()}[alg[2:]]
    signed = f"{h64}.{p64}".encode()
    try:
        if alg.startswith("RS"):
            if jwk.get("kty") != "RSA":
                raise OIDCError("Anahtar türü algoritmayla uyuşmuyor")
            key.verify(sig, signed, padding.PKCS1v15(), h)
        else:
            if jwk.get("kty") != "EC":
                raise OIDCError("Anahtar türü algoritmayla uyuşmuyor")
            n = len(sig) // 2
            der = encode_dss_signature(int.from_bytes(sig[:n], "big"), int.from_bytes(sig[n:], "big"))
            key.verify(der, signed, ec.ECDSA(h))
    except InvalidSignature as ex:
        raise OIDCError("id_token imzası geçersiz") from ex
    now = time.time()
    issuer = settings_store.get(db, "oidc_issuer").rstrip("/")
    client_id = settings_store.get(db, "oidc_client_id")
    aud = claims.get("aud")
    auds = aud if isinstance(aud, list) else [aud]
    if str(claims.get("iss", "")).rstrip("/") != issuer:
        raise OIDCError("id_token issuer değeri hatalı")
    if client_id not in auds or (len(auds) > 1 and claims.get("azp") not in (None, client_id)):
        raise OIDCError("id_token bu uygulama için verilmemiş (aud)")
    if not isinstance(claims.get("exp"), (int, float)) or claims["exp"] < now - 60:
        raise OIDCError("id_token süresi dolmuş")
    if isinstance(claims.get("iat"), (int, float)) and claims["iat"] > now + 300:
        raise OIDCError("id_token zamanı geçersiz")
    if not hmac.compare_digest(str(claims.get("nonce", "")), nonce):
        raise OIDCError("id_token nonce değeri eşleşmiyor")
    if "email_verified" in claims and claims["email_verified"] is not True:
        raise OIDCError("Kimlik sağlayıcıda e-posta adresi doğrulanmamış")
    return claims


def finish(db: Session, code: str, state: str, cookie: str | None, base_url: str) -> str:
    sess = _unsign(cookie)
    if not state or not hmac.compare_digest(state, sess["state"]):
        raise OIDCError("SSO durum (state) doğrulaması başarısız")
    d = discovery(db)
    tok = _http_post(d["token_endpoint"], {
        "grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri(db, base_url),
        "client_id": settings_store.get(db, "oidc_client_id"),
        "client_secret": settings_store.get(db, "oidc_client_secret"), "code_verifier": sess["verifier"]})
    if not tok.get("id_token"):
        raise OIDCError("Kimlik sağlayıcı id_token döndürmedi")
    claims = verify_id_token(db, tok["id_token"], sess["nonce"])
    email = claims.get("email") or claims.get("preferred_username") or claims.get("upn") or ""
    if "@" not in email:
        raise OIDCError("Kimlik sağlayıcı e-posta bilgisi göndermedi")
    return email.strip().lower()
