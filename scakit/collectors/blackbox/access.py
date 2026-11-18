from __future__ import annotations

import re
from urllib.parse import urlparse

_GEO = re.compile(r"not (?:be )?available in your (?:country|region|location)|unavailable in your (?:country|region)|"
                  r"access from your (?:country|region|location)|error 1009|blocked in your (?:country|region)|"
                  r"geo-?(?:block|restrict)|ülkenizde(?:n)? (?:kullanılamaz|erişilemez)|"
                  r"service is not available in your area|this content is not available in your", re.I)
_IPBLOCK = re.compile(r"error 10(?:06|07|08|20)\b|has banned (?:you|your ip)|your ip(?: address)? (?:has been|is) "
                      r"(?:blocked|banned|blacklisted)|ip (?:address )?(?:blocked|not allowed|not whitelisted)|"
                      r"request blocked by (?:security|firewall) policy|ip adresiniz engellendi", re.I)
_MAINT = re.compile(r"under maintenance|scheduled maintenance|we.?ll be back soon|bakım çalışması|"
                    r"maintenance mode|temporarily unavailable", re.I)
_CAPTCHA = (("recaptcha", re.compile(r"google\.com/recaptcha|recaptcha\.net|grecaptcha|RecaptchaChallenge", re.I)),
            ("hcaptcha", re.compile(r"hcaptcha\.com", re.I)),
            ("turnstile", re.compile(r"challenges\.cloudflare\.com/turnstile|cf-turnstile", re.I)),
            ("arkose", re.compile(r"arkoselabs\.com|funcaptcha", re.I)),
            ("geetest", re.compile(r"geetest", re.I)))
_LOGIN_PATH = re.compile(r"/(?:login|log-in|signin|sign-in|sign_in|sso|saml|oauth2?|openid-connect|adfs|cas/login|"
                         r"auth/realms|account/login|users?/sign_in|wp-login\.php|giris|oturum-ac)(?:[/?.#]|$)", re.I)
_IDP_HOST = re.compile(r"(?:^|\.)(?:login\.microsoftonline\.com|login\.windows\.net|accounts\.google\.com|okta\.com|"
                       r"oktapreview\.com|auth0\.com|onelogin\.com|pingidentity\.com|pingone\.com|duosecurity\.com|"
                       r"b2clogin\.com|keycloak[\w.-]*|sso[\w.-]*)$", re.I)


def classify_error(exc: BaseException) -> str:
    name, text = type(exc).__name__, str(exc).lower()
    if name == "BlockedAddress" or "iç ağ" in text or "engellendi" in text:
        return "internal_blocked"
    if "certificate required" in text or "alert certificate" in text or "tlsv13 alert certificate required" in text \
            or "peer certificate" in text and "required" in text or "bad certificate" in text:
        return "mtls"
    if "ssl" in text or "certificate" in text or "tls" in text or name in ("SSLError",):
        return "tls_error"
    if "name or service not known" in text or "nodename nor servname" in text or "getaddrinfo" in text \
            or "could not resolve" in text or "temporary failure in name resolution" in text or "çözümlenemedi" in text:
        return "dns"
    if "timed out" in text or "timeout" in text or name in ("ReadTimeout", "ConnectTimeout", "Timeout"):
        return "timeout"
    if "refused" in text:
        return "refused"
    if "reset" in text or "remotedisconnected" in text.replace(" ", "") or "connection aborted" in text \
            or "empty reply" in text:
        return "reset"
    return "reset"


def captcha_kind(text: str) -> str | None:
    for kind, rx in _CAPTCHA:
        if rx.search(text):
            return kind
    return None


def classify_response(status: int, headers, body: bytes, final_url: str, start_host: str | None) -> tuple[str, str] | None:
    h = {k.lower(): v for k, v in headers.items()}
    final = urlparse(str(final_url))
    if status == 401 and (auth := h.get("www-authenticate", "")):
        return "http_auth", auth.split()[0][:30] if auth.split() else "Basic"
    host = final.hostname or ""
    if start_host and host != start_host and _IDP_HOST.search(host):
        return "login_required", host
    if _LOGIN_PATH.search(final.path or "") and status < 400:
        return "login_required", final.path[:80]
    text = body[:65536].decode("utf-8", "replace") if body else ""
    if status == 451:
        return "geo_block", "HTTP 451"
    if status in (403, 401, 404, 200) and text and len(body) < 300_000:
        if _GEO.search(text):
            return "geo_block", _GEO.search(text).group(0)[:80]
        if status != 200 and _IPBLOCK.search(text):
            return "ip_block", _IPBLOCK.search(text).group(0)[:80]
    if status == 503 and text and _MAINT.search(text):
        return "unavailable", _MAINT.search(text).group(0)[:80]
    return None


def same_site(a: str | None, b: str | None) -> bool:
    if not a or not b:
        return False
    sa, sb = a.removeprefix("www."), b.removeprefix("www.")
    return sa == sb or sb.endswith("." + sa) or sa.endswith("." + sb)


PRIORITY = ("internal_blocked", "mtls", "geo_block", "ip_block", "http_auth", "login_required", "dns", "tls_error",
            "refused", "timeout", "reset", "unavailable", "captcha")
