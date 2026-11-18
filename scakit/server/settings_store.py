from __future__ import annotations

from sqlalchemy.orm import Session

from .models import Setting
from .security import decrypt, encrypt

SCHEMA = {
    "nvd_api_key": ("", True, "NVD API anahtarı (NVD indirmesini hızlandırır)"),
    "vulndb_path": ("", False, "Zafiyet veritabanı dosyası (boşsa varsayılan konum)"),
    "allow_internal_targets": ("0", False, "İç ağ / özel IP adreslerinin taranmasına izin ver (1/0)"),
    "default_report_lang": ("en", False, "Rapor, bildirim ve Jira dili"),
    "web_default_delay": ("1", False, "Web taraması istekler arası bekleme (sn)"),
    "web_default_max_pages": ("30", False, "Web taraması en fazla sayfa"),
    "timezone": ("Europe/Istanbul", False, "Zamanlamalar için saat dilimi"),
    "job_timeout_minutes": ("120", False, "Bir tarama / iş en fazla kaç dakika sürebilir"),
    "job_memory_mb": ("4096", False, "Bir tarama / iş en fazla kaç MB bellek kullanabilir"),
    "retention_scans_per_target": ("20", False, "Hedef başına saklanacak en fazla tarama (0 = sınırsız)"),
    "retention_scan_days": ("0", False, "Şu günden eski taramaları sil (0 = kapalı)"),
    "audit_retention_days": ("730", False, "Denetim kaydı saklama süresi, gün (0 = sınırsız)"),
    "oidc_enabled": ("0", False, "Kurumsal giriş (SSO / OpenID Connect) açık (1/0)"),
    "oidc_issuer": ("", False, "Issuer adresi (ör. https://login.microsoftonline.com/<kiracı>/v2.0)"),
    "oidc_client_id": ("", False, "Client ID"),
    "oidc_client_secret": ("", True, "Client secret"),
    "oidc_button_label": ("", False, "Giriş düğmesi metni (boşsa \"Kurumsal hesapla giriş\")"),
    "approval_required": ("1", False, "Risk kabulü / yanlış pozitif / etkilenmiyor kararları onaya tabi (1/0)"),
    "public_url": ("", False, "Arayüzün adresi (bildirimlerdeki bağlantılar için, ör. https://fureteur.firma.local)"),
    "maintenance_mode": ("0", False, "Bakım modu: yalnızca yöneticiler giriş yapabilir ve işlem yapabilir (1/0)"),
    "maintenance_message": ("", False, "Bakım modunda kullanıcılara gösterilecek mesaj"),
    "login_max_failures": ("10", False, "Aynı IP + e-posta için izin verilen başarısız giriş sayısı"),
    "login_window_minutes": ("15", False, "Başarısız giriş sayacının süresi / kilit süresi (dakika)"),
    "api_rate_per_minute": ("600", False, "Kullanıcı / IP başına dakikada en fazla API isteği (0 = sınırsız)"),
    "toolset_enabled": ("1", False, "Araç setinin ağ araçları (HTTP istemcisi, ping) açık (1/0)"),
    "toolset_customers": ("0", False, "Müşteri kullanıcıları ağ araçlarını kullanabilir (yalnızca izinli alan adları) (1/0)"),
    "toolset_rate_per_minute": ("20", False, "Kullanıcı başına dakikada en fazla ağ aracı isteği"),
    "egress_proxies": ("", True, "Çıkış noktaları: Ad=proxy adresi, noktalı virgülle ayrılır (ör. TR=socks5://kullanici:parola@1.2.3.4:1080; DE=http://5.6.7.8:3128)"),
    "queue_concurrency": ("0", False, "Worker başına aynı anda çalışacak tarama sayısı (0 = worker başlatma ayarı)"),
    "queue_gap_seconds": ("0", False, "Bir tarama bittikten sonra sıradakine geçmeden önce beklenecek süre (sn)"),
    "smtp_host": ("", False, "SMTP sunucusu"),
    "smtp_port": ("587", False, "SMTP portu"),
    "smtp_security": ("starttls", False, "SMTP güvenliği: starttls | ssl | none"),
    "smtp_user": ("", False, "SMTP kullanıcı adı"),
    "smtp_password": ("", True, "SMTP parolası"),
    "smtp_from": ("", False, "Gönderen adresi"),
    "jira_url": ("", False, "Jira adresi (ör. https://firma.atlassian.net)"),
    "jira_auth": ("cloud", False, "Jira kimlik doğrulama: cloud (e-posta + API token) | server (kişisel erişim token'ı)"),
    "jira_user": ("", False, "Jira kullanıcı e-postası (Cloud)"),
    "jira_token": ("", True, "Jira API token / kişisel erişim token'ı"),
    "jira_project_key": ("", False, "Varsayılan Jira proje anahtarı (ör. SEC)"),
    "jira_issue_type": ("Bug", False, "Kayıt türü (Bug, Task, Vulnerability ...)"),
    "jira_labels": ("le-fureteur,sca", False, "Etiketler (virgülle)"),
    "jira_auto_min_severity": ("", False, "Taramada yeni bulgular için otomatik kayıt: boş=kapalı, CRITICAL, HIGH, MEDIUM, LOW"),
    "jira_comment_on_fix": ("1", False, "Bulgu düzeldiğinde / yeniden açıldığında Jira kaydına yorum yaz (1/0)"),
}

GROUPS = {
    "Genel": ["vulndb_path", "allow_internal_targets", "default_report_lang", "web_default_delay",
              "web_default_max_pages", "timezone", "public_url", "approval_required", "job_timeout_minutes", "job_memory_mb",
              "nvd_api_key"],
    "Güvenlik ve erişim": ["maintenance_mode", "maintenance_message", "login_max_failures", "login_window_minutes",
                           "api_rate_per_minute"],
    "Araç seti": ["toolset_enabled", "toolset_customers", "toolset_rate_per_minute"],
    "Tarama kuyruğu": ["queue_concurrency", "queue_gap_seconds"],
    "Çıkış noktaları": ["egress_proxies"],
    "SSO": ["oidc_enabled", "oidc_issuer", "oidc_client_id", "oidc_client_secret", "oidc_button_label"],
    "Saklama": ["retention_scans_per_target", "retention_scan_days", "audit_retention_days"],
    "E-posta (SMTP)": ["smtp_host", "smtp_port", "smtp_security", "smtp_user", "smtp_password", "smtp_from"],
    "Jira": ["jira_url", "jira_auth", "jira_user", "jira_token", "jira_project_key", "jira_issue_type", "jira_labels",
             "jira_auto_min_severity", "jira_comment_on_fix"],
}


def get(db: Session, key: str) -> str:
    row = db.get(Setting, key)
    if row is None:
        return SCHEMA.get(key, ("",))[0]
    return decrypt(row.value) if row.secret else row.value


def get_bool(db: Session, key: str) -> bool:
    return get(db, key).strip().lower() in ("1", "true", "yes", "on")


def get_int(db: Session, key: str, minimum: int = 0) -> int:
    try:
        return max(minimum, int(get(db, key)))
    except ValueError:
        return max(minimum, int(SCHEMA[key][0]))


_cache: dict[str, tuple[float, str]] = {}


def cached(key: str, ttl: float = 5.0) -> str:
    import time
    now = time.monotonic()
    hit = _cache.get(key)
    if hit and now - hit[0] < ttl:
        return hit[1]
    from .db import SessionLocal
    db = SessionLocal()
    try:
        val = get(db, key)
    finally:
        db.close()
    _cache[key] = (now, val)
    return val


def invalidate() -> None:
    _cache.clear()


def set_value(db: Session, key: str, value: str) -> None:
    if key not in SCHEMA:
        raise KeyError(key)
    secret = SCHEMA[key][1]
    row = db.get(Setting, key) or Setting(key=key, secret=secret)
    row.value = encrypt(value) if secret and value else value
    row.secret = secret
    db.merge(row)
    db.commit()
    invalidate()


def public_view(db: Session) -> list[dict]:
    out = []
    group_of = {k: g for g, keys in GROUPS.items() for k in keys}
    for key, (default, secret, desc) in SCHEMA.items():
        val = get(db, key)
        out.append({"key": key, "description": desc, "secret": secret, "group": group_of.get(key, "Genel"),
                    "value": "" if secret else val, "is_set": bool(val) if secret else None})
    return out


_BOOL = {"allow_internal_targets", "oidc_enabled", "approval_required", "jira_comment_on_fix", "maintenance_mode",
         "toolset_enabled", "toolset_customers"}
_INT = {"web_default_max_pages": (1, 200), "job_timeout_minutes": (5, 1440), "job_memory_mb": (256, 131072),
        "retention_scans_per_target": (0, 10000), "retention_scan_days": (0, 3650), "audit_retention_days": (0, 3650),
        "smtp_port": (1, 65535), "login_max_failures": (1, 100), "login_window_minutes": (1, 1440),
        "api_rate_per_minute": (0, 100000), "toolset_rate_per_minute": (1, 600),
        "queue_concurrency": (0, 32), "queue_gap_seconds": (0, 3600)}
_FLOAT = {"web_default_delay": (0.2, 10.0)}
_ENUM = {"smtp_security": ("starttls", "ssl", "none"), "jira_auth": ("cloud", "server"),
         "default_report_lang": ("tr", "en", "fr", "de"), "jira_auto_min_severity": ("", "CRITICAL", "HIGH", "MEDIUM", "LOW")}
_URL = {"public_url", "jira_url", "oidc_issuer"}
_EMAIL = {"smtp_from", "jira_user"}
_MULTILINE = {"maintenance_message"}


class SettingError(ValueError):
    pass


def validate(key: str, value) -> str:
    import re
    from urllib.parse import urlparse
    v = "" if value is None else str(value)
    if key not in _MULTILINE and any(c in v for c in "\r\n\0"):
        raise SettingError("Bu alan tek satır olmalı")
    if len(v) > (500 if key in _MULTILINE else 2000):
        raise SettingError("Değer çok uzun")
    v = v.strip() if not SCHEMA[key][1] else v
    if key in _BOOL:
        return "1" if v.lower() in ("1", "true", "yes", "on") else "0"
    if key in _INT and v != "":
        lo, hi = _INT[key]
        if not re.fullmatch(r"-?\d+", v) or not lo <= int(v) <= hi:
            raise SettingError("Geçerli aralıkta bir tam sayı girin")
        return str(int(v))
    if key in _FLOAT and v != "":
        lo, hi = _FLOAT[key]
        try:
            f = float(v.replace(",", "."))
        except ValueError:
            raise SettingError("Geçerli aralıkta bir sayı girin") from None
        if not lo <= f <= hi:
            raise SettingError("Geçerli aralıkta bir sayı girin")
        return str(f)
    if key == "egress_proxies" and v.strip():
        parse_proxies(v)
        return v.strip()
    if key in _ENUM and v not in _ENUM[key]:
        raise SettingError("Geçersiz seçim")
    if key == "timezone" and v:
        from zoneinfo import ZoneInfo
        try:
            ZoneInfo(v)
        except Exception:
            raise SettingError("Geçersiz saat dilimi (ör. Europe/Istanbul)") from None
    if key in _URL and v:
        p = urlparse(v)
        if p.scheme not in ("http", "https") or not p.hostname or p.username or p.password:
            raise SettingError("Geçerli bir http(s) adresi girin")
        if key == "oidc_issuer" and p.scheme != "https" and p.hostname not in ("localhost", "127.0.0.1"):
            raise SettingError("Kimlik sağlayıcı adresi https olmalı")
        return v.rstrip("/")
    if key in _EMAIL and v and not re.fullmatch(r"[^@\s<>\"]+@[^@\s<>\"]+\.[A-Za-z]{2,}", v):
        raise SettingError("Geçerli bir e-posta adresi girin")
    if key == "smtp_host" and v and not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", v):
        raise SettingError("Geçersiz sunucu adı")
    if key == "jira_project_key" and v and not re.fullmatch(r"[A-Z][A-Z0-9_]{0,49}", v.upper()):
        raise SettingError("Geçersiz Jira proje anahtarı")
    return v.upper() if key == "jira_project_key" else v


def parse_proxies(v: str) -> list[tuple[str, str]]:
    import re
    from urllib.parse import urlparse
    out, names = [], set()
    for part in [x.strip() for x in v.split(";") if x.strip()][:20]:
        name, sep, url = part.partition("=")
        name, url = name.strip(), url.strip()
        p = urlparse(url)
        if not sep or not re.fullmatch(r"[A-Za-z0-9_-]{1,30}", name) or name.lower() in ("auto", "direct") \
                or p.scheme not in ("http", "https", "socks5", "socks5h") or not p.hostname or name in names:
            raise SettingError("Çıkış noktası biçimi: Ad=socks5://kullanici:parola@sunucu:port; Ad2=http://sunucu:port")
        try:
            p.port
        except ValueError:
            raise SettingError("Çıkış noktası biçimi: Ad=socks5://kullanici:parola@sunucu:port; Ad2=http://sunucu:port") from None
        names.add(name)
        out.append((name, url))
    return out


def proxies(db: Session) -> list[tuple[str, str]]:
    try:
        return parse_proxies(get(db, "egress_proxies") or "")
    except SettingError:
        return []
