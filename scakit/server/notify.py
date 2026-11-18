from __future__ import annotations

import hashlib
import hmac
import json
import re
import smtplib
import ssl
from datetime import datetime, timezone
from email.message import EmailMessage
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from .. import PRODUCT_NAME
from ..matcher import SEVERITY_RANK
from . import settings_store
from .models import NotificationChannel
from .security import decrypt, encrypt

KINDS = ("slack", "teams", "email", "webhook")
EVENT_LABEL = {
    "scan_done": "Tarama tamamlandı",
    "scan_failed": "Tarama başarısız",
    "new_findings": "Yeni bulgu (eşik ve üzeri)",
    "kev": "Aktif sömürülen (KEV) yeni bulgu",
    "db_update_failed": "Zafiyet veritabanı güncellemesi başarısız",
}
SEV_TR = {"CRITICAL": "Kritik", "HIGH": "Yüksek", "MEDIUM": "Orta", "LOW": "Düşük", "UNKNOWN": "Bilinmiyor"}


class NotifyError(Exception):
    pass


def get_config(ch: NotificationChannel) -> dict:
    return json.loads(decrypt(ch.config_enc)) if ch.config_enc else {}


def set_config(ch: NotificationChannel, cfg: dict) -> None:
    ch.config_enc = encrypt(json.dumps(cfg))


def validate_config(kind: str, cfg: dict) -> dict:
    if kind not in KINDS:
        raise NotifyError(f"Geçersiz kanal türü: {kind}")
    if kind == "email":
        to = [a.strip() for a in cfg.get("to", []) if a.strip()]
        if not to or any("@" not in a for a in to):
            raise NotifyError("En az bir geçerli e-posta adresi gerekli")
        return {"to": to}
    url = str(cfg.get("url", "")).strip()
    p = urlparse(url)
    if p.scheme not in ("https", "http") or not p.hostname:
        raise NotifyError("Geçerli bir webhook adresi (https://...) gerekli")
    out = {"url": url}
    if kind == "webhook" and cfg.get("secret"):
        out["secret"] = str(cfg["secret"])
    return out


def masked(ch: NotificationChannel) -> dict:
    cfg = get_config(ch)
    if ch.kind == "email":
        return {"to": cfg.get("to", [])}
    p = urlparse(cfg.get("url", ""))
    return {"url": f"{p.scheme}://{p.hostname}/…" if p.hostname else "", "has_secret": bool(cfg.get("secret"))}


def _link(db: Session, path: str) -> str:
    base = settings_store.get(db, "public_url").rstrip("/")
    return f"{base}{path}" if base else ""


def build_scan_message(db: Session, event: str, scan, new_rows=(), error: str = "") -> dict:
    t = scan.target
    title = {"scan_done": "Tarama tamamlandı", "scan_failed": "Tarama başarısız",
             "new_findings": "Yeni bulgular", "kev": "Aktif sömürülen zafiyet (KEV) bulundu"}[event]
    head = f"{title}: {t.project.organization.name} / {t.project.name} / {t.name} (#{scan.id})"
    lines = []
    s = scan.summary or {}
    if event == "scan_failed":
        lines.append(f"Hata: {error or '-'}")
    else:
        sev = s.get("severity", {})
        lines.append(f"{s.get('components', 0)} bileşen, {s.get('findings', 0)} açık bulgu "
                     f"(Kritik {sev.get('CRITICAL', 0)}, Yüksek {sev.get('HIGH', 0)}, Orta {sev.get('MEDIUM', 0)}, "
                     f"Düşük {sev.get('LOW', 0)}), KEV {s.get('kev', 0)}")
        lines.append(f"Değişim: {s.get('new', 0)} yeni, {s.get('fixed', 0)} kapandı, {s.get('reopened', 0)} yeniden açıldı")
        w = s.get("waf") or {}
        if w.get("severe"):
            lines.append(f"UYARI: {w.get('vendor')} WAF / bot koruması {w.get('blocked')}/{w.get('requests')} isteği engelledi; "
                         "sonuç eksik. Çözüm: siteyi tarayıcıda / Burp'te gezip HAR veya Burp kaydını yükleyin.")
    items = []
    for f in list(new_rows)[:10]:
        cve = next((a for a in (f.aliases or []) if a.startswith("CVE-")), f.vuln_id)
        items.append(f"[{SEV_TR.get(f.severity, f.severity)}{' · KEV' if f.kev else ''}] {cve} — {f.component} "
                     f"{f.version}" + (f" → {f.upgrade_to}" if f.upgrade_to else ""))
    if len(new_rows) > 10:
        items.append(f"… ve {len(new_rows) - 10} bulgu daha")
    return {"event": event, "title": head, "lines": lines, "items": items,
            "url": _link(db, f"/scans/{scan.id}"),
            "data": {"scan_id": scan.id, "target": t.name, "project": t.project.name,
                     "organization": t.project.organization.name, "summary": s, "error": error,
                     "findings": [{"id": f.id, "vuln_id": f.vuln_id, "aliases": f.aliases, "severity": f.severity,
                                   "kev": f.kev, "component": f.component, "version": f.version,
                                   "upgrade_to": f.upgrade_to} for f in new_rows]}}


def build_simple_message(db: Session, event: str, title: str, lines: list[str], path: str = "") -> dict:
    return {"event": event, "title": title, "lines": lines, "items": [], "url": _link(db, path) if path else "",
            "data": {}}


def _text(msg: dict) -> str:
    out = [msg["title"], *msg["lines"]]
    if msg["items"]:
        out += [""] + [f"• {i}" for i in msg["items"]]
    if msg["url"]:
        out += ["", msg["url"]]
    return "\n".join(out)


def _slack_esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _slack(msg: dict) -> dict:
    body = "\n".join(_slack_esc(x) for x in msg["lines"] + ([""] + [f"• {i}" for i in msg["items"]] if msg["items"] else []))
    blocks = [{"type": "header", "text": {"type": "plain_text", "text": msg["title"][:150]}},
              {"type": "section", "text": {"type": "mrkdwn", "text": body[:2900] or "-"}}]
    if msg["url"]:
        blocks.append({"type": "actions", "elements": [{"type": "button", "text": {"type": "plain_text",
                                                                                   "text": f"{PRODUCT_NAME}'de aç"},
                                                        "url": msg["url"]}]})
    return {"text": msg["title"], "blocks": blocks}


def _teams(msg: dict) -> dict:
    def plain(s: str) -> str:
        return s.replace("[", "(").replace("]", ")")
    body = [{"type": "TextBlock", "text": plain(msg["title"]), "weight": "Bolder", "size": "Medium", "wrap": True}]
    body += [{"type": "TextBlock", "text": plain(ln), "wrap": True} for ln in msg["lines"]]
    body += [{"type": "TextBlock", "text": f"• {plain(i)}", "wrap": True, "spacing": "Small"} for i in msg["items"]]
    card = {"type": "AdaptiveCard", "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "version": "1.4", "body": body}
    if msg["url"]:
        card["actions"] = [{"type": "Action.OpenUrl", "title": f"{PRODUCT_NAME}'de aç", "url": msg["url"]}]
    return {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive",
                                                 "content": card}]}


def _http_post(url: str, body: bytes, headers: dict) -> None:
    import requests
    r = requests.post(url, data=body, headers=headers, timeout=15)
    if r.status_code >= 300:
        raise NotifyError(f"HTTP {r.status_code}: {r.text[:200]}")


def _send_email(db: Session, to: list[str], subject: str, text: str) -> None:
    host = settings_store.get(db, "smtp_host")
    if not host:
        raise NotifyError("SMTP sunucusu ayarlı değil (Ayarlar → E-posta)")
    port = int(settings_store.get(db, "smtp_port") or 587)
    sec = settings_store.get(db, "smtp_security")
    m = EmailMessage()
    m["From"] = settings_store.get(db, "smtp_from") or settings_store.get(db, "smtp_user")
    m["To"] = ", ".join(to)
    m["Subject"] = " ".join(subject.split())[:200]
    m.set_content(text)
    ctx = ssl.create_default_context()
    smtp = smtplib.SMTP_SSL(host, port, timeout=20, context=ctx) if sec == "ssl" else smtplib.SMTP(host, port, timeout=20)
    try:
        if sec == "starttls":
            smtp.starttls(context=ctx)
        user = settings_store.get(db, "smtp_user")
        if user:
            smtp.login(user, settings_store.get(db, "smtp_password"))
        smtp.send_message(m)
    finally:
        try:
            smtp.quit()
        except Exception:
            pass


def send(db: Session, ch: NotificationChannel, msg: dict) -> None:
    cfg = get_config(ch)
    if ch.kind == "email":
        _send_email(db, cfg["to"], f"[{PRODUCT_NAME}] {msg['title']}", _text(msg))
    else:
        if ch.kind == "slack":
            payload = _slack(msg)
        elif ch.kind == "teams":
            payload = _teams(msg)
        else:
            payload = {"event": msg["event"], "title": msg["title"], "lines": msg["lines"], "url": msg["url"],
                       **msg["data"], "sent_at": datetime.now(timezone.utc).isoformat()}
        body = json.dumps(payload, ensure_ascii=False).encode()
        headers = {"Content-Type": "application/json", "User-Agent": "scakit"}
        if ch.kind == "webhook" and cfg.get("secret"):
            headers["X-Scakit-Signature"] = "sha256=" + hmac.new(cfg["secret"].encode(), body, hashlib.sha256).hexdigest()
        _http_post(cfg["url"], body, headers)


def safe_error(ex: BaseException) -> str:
    from .errors import human_text
    if isinstance(ex, NotifyError):
        return re.sub(r"https?://\S+", "<adres>", str(ex))[:300]
    return human_text(ex)


def _record(db: Session, ch: NotificationChannel, err: str = "") -> None:
    ch.last_status = err or "ok"
    ch.last_sent_at = datetime.now(timezone.utc)
    db.commit()


def dispatch(db: Session, event: str, msg_factory, organization_id: int | None, log=print,
             new_rows=None, on_result=None) -> int:
    sent = 0
    q = db.query(NotificationChannel).filter(NotificationChannel.enabled.is_(True))
    for ch in q.all():
        if event not in (ch.events or []):
            continue
        if ch.organization_id and organization_id and ch.organization_id != organization_id:
            continue
        rows = None
        if new_rows is not None:
            thr = SEVERITY_RANK.get(ch.min_severity, 0)
            rows = [r for r in new_rows if SEVERITY_RANK.get(r.severity, 0) >= thr or r.kev or r.malicious]
            if event == "kev":
                rows = [r for r in new_rows if r.kev]
            if not rows:
                continue
        try:
            send(db, ch, msg_factory(rows or []))
            _record(db, ch)
            sent += 1
            if on_result:
                on_result(ch, True)
        except Exception as ex:
            _record(db, ch, safe_error(ex))
            log(f"  ! bildirim gönderilemedi ({ch.name}): {type(ex).__name__}")
            if on_result:
                on_result(ch, False, ex)
    return sent
