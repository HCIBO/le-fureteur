from __future__ import annotations

from sqlalchemy.orm import Session

from .. import PRODUCT_NAME
from ..matcher import SEVERITY_RANK
from ..messages import translate
from . import settings_store
from .models import ROLES, Finding, JiraInstance, Project, Target

SEV_TR = {"CRITICAL": "Kritik", "HIGH": "Yüksek", "MEDIUM": "Orta", "LOW": "Düşük", "UNKNOWN": "Bilinmiyor"}
AUTO_CAP = 50


class JiraError(Exception):
    pass


LEGACY_KEYS = ("url", "auth", "user", "token", "project_key", "issue_type", "labels", "auto_min_severity", "comment_on_fix")


def migrate_legacy(db: Session) -> None:
    from .security import encrypt
    vals = {k: settings_store.get(db, f"jira_{k}").strip() for k in LEGACY_KEYS}
    if not vals["url"]:
        return
    inst = db.query(JiraInstance).filter_by(name="Jira").first() or JiraInstance(name="Jira", roles=list(ROLES))
    inst.url, inst.auth, inst.user = vals["url"].rstrip("/"), vals["auth"] or "cloud", vals["user"]
    if vals["token"]:
        inst.token_enc = encrypt(vals["token"])
    inst.project_key, inst.issue_type = vals["project_key"], vals["issue_type"] or "Bug"
    inst.labels, inst.auto_min_severity = vals["labels"], vals["auto_min_severity"].upper()
    inst.comment_on_fix = vals["comment_on_fix"] in ("1", "true", "yes")
    db.add(inst)
    for k in LEGACY_KEYS:
        settings_store.set_value(db, f"jira_{k}", "")
    db.commit()
    settings_store.invalidate()


def instances(db: Session, enabled_only: bool = True) -> list[JiraInstance]:
    migrate_legacy(db)
    q = db.query(JiraInstance).order_by(JiraInstance.id)
    if enabled_only:
        q = q.filter(JiraInstance.enabled.is_(True))
    return q.all()


def config(inst: JiraInstance) -> dict:
    from .security import decrypt
    return {"url": inst.url.rstrip("/"), "auth": inst.auth, "user": inst.user,
            "token": decrypt(inst.token_enc) if inst.token_enc else "", "project_key": inst.project_key,
            "issue_type": inst.issue_type, "labels": inst.labels, "auto_min_severity": inst.auto_min_severity,
            "comment_on_fix": "1" if inst.comment_on_fix else "0"}


def ready(inst: JiraInstance) -> bool:
    return bool(inst.enabled and inst.url and inst.token_enc and (inst.auth == "server" or inst.user))


def can_use(inst: JiraInstance, user, org_id: int | None) -> bool:
    if not ready(inst) or getattr(user, "via_token", False) and user.role != "admin":
        return False
    if user.role == "customer":
        if org_id is not None and org_id != user.organization_id:
            return False
        org_id = user.organization_id
    if org_id is not None and inst.org_ids and org_id not in inst.org_ids:
        return False
    if user.role == "admin":
        return True
    if user.role not in (inst.roles or []):
        return False
    if inst.user_ids and user.id not in inst.user_ids:
        return False
    return True


def usable(db: Session, user, org_id: int | None = None) -> list[JiraInstance]:
    return [i for i in instances(db) if can_use(i, user, org_id)]


def configured(db: Session) -> bool:
    return any(ready(i) for i in instances(db))


def pick(db: Session, user, f: Finding, instance_id: int | None) -> JiraInstance:
    org_id = db.get(Project, f.project_id).organization_id
    ok = usable(db, user, org_id)
    if instance_id is not None:
        inst = next((i for i in ok if i.id == instance_id), None)
        if inst is None:
            raise JiraError("Bu Jira bağlantısını kullanma yetkiniz yok")
        return inst
    proj = db.get(Project, f.project_id)
    inst = next((i for i in ok if i.id == proj.jira_instance_id), None)
    if inst:
        return inst
    if len(ok) == 1:
        return ok[0]
    if not ok:
        raise JiraError("Kullanabileceğiniz bir Jira bağlantısı yok (yönetici: Ayarlar → Jira)")
    raise JiraError("Birden fazla Jira bağlantısı var; hangisine ekleneceğini seçin")


def _request(method: str, url: str, cfg: dict, json_body=None):
    import requests
    headers = {"Accept": "application/json", "User-Agent": "scakit"}
    auth = None
    if cfg["auth"] == "server":
        headers["Authorization"] = f"Bearer {cfg['token']}"
    else:
        auth = (cfg["user"], cfg["token"])
    return requests.request(method, url, json=json_body, headers=headers, auth=auth, timeout=20)


def _call(inst: JiraInstance, method: str, path: str, body=None) -> dict:
    if not ready(inst):
        raise JiraError(f"'{inst.name}' Jira bağlantısı eksik ayarlı veya kapalı")
    cfg = config(inst)
    try:
        r = _request(method, f"{cfg['url']}{path}", cfg, body)
    except Exception as ex:
        raise JiraError(f"Jira'ya bağlanılamadı: {type(ex).__name__}") from ex
    if r.status_code >= 300:
        detail = r.text[:400]
        try:
            j = r.json()
            detail = "; ".join(j.get("errorMessages", []) + [f"{k}: {v}" for k, v in j.get("errors", {}).items()]) or detail
        except Exception:
            pass
        raise JiraError(f"Jira HTTP {r.status_code}: {detail}")
    return r.json() if r.content else {}


def test_connection(inst: JiraInstance) -> dict:
    me = _call(inst, "GET", "/rest/api/2/myself")
    out = {"user": me.get("displayName") or me.get("name") or me.get("emailAddress", "")}
    if inst.project_key:
        p = _call(inst, "GET", f"/rest/api/2/project/{inst.project_key}")
        out["project"] = f"{p.get('key')} — {p.get('name')}"
    return out


def message_lang(db: Session) -> str:
    return settings_store.get(db, "default_report_lang") or "en"


def _w(s) -> str:
    s = str(s if s is not None else "").replace("\r", " ").replace("\n", " ")
    for ch in "\\{}[]|*_+^~-#!":
        s = s.replace(ch, "\\" + ch)
    return s


def _description(db: Session, f: Finding, target: Target) -> str:
    cves = [a for a in (f.aliases or []) if a.startswith("CVE-")]
    base = settings_store.get(db, "public_url").rstrip("/")
    lang = message_lang(db)

    def L(s: str) -> str:
        return translate(s, lang)
    pct = f"{f.epss * 100:.1f}" if f.epss is not None else ""
    epss = (f" | EPSS %{pct}" if lang == "tr" else f" | EPSS {pct}%") if pct else ""
    lines = [
        f"h3. {L('Zafiyet')}",
        f"*{L('Kimlik')}:* {f.vuln_id}" + (f" ({', '.join(cves)})" if cves else ""),
        f"*{L('Şiddet')}:* {L(SEV_TR.get(f.severity, f.severity))}" + (f" (CVSS {f.cvss})" if f.cvss is not None else "")
        + epss + (f" | *CISA KEV: {L('aktif sömürülüyor')}*" if f.kev else ""),
        f"*{L('Bileşen')}:* {_w(f.component)} {_w(f.version)} ({_w(f.ecosystem)})",
        f"*PURL:* {f.purl}" if f.purl else "",
        f"*{L('Hedef')}:* {_w(target.project.organization.name)} / {_w(target.project.name)} / {_w(target.name)}",
        f"*{L('Önerilen sürüm')}:* {f.upgrade_to}" if f.upgrade_to else
        (f"*{L('Düzeltilmiş sürümler')}:* {', '.join(f.fixed_versions)}" if f.fixed_versions
         else f"*{L('Düzeltme')}:* {L('henüz yok')}"),
        "", f"h3. {L('Açıklama')}", _w(f.summary or "-"), "", f"h3. {L('Konum / kanıt')}",
    ]
    lines += [f"* {_w(e.get('method'))}: {_w(e.get('location', ''))}" for e in (f.evidence or [])[:10]] or ["-"]
    lines += ["", f"h3. {L('Bağlantılar')}", f"* https://osv.dev/vulnerability/{f.vuln_id}"]
    lines += [f"* https://nvd.nist.gov/vuln/detail/{c}" for c in cves[:3]]
    if base:
        lines.append(f"* {PRODUCT_NAME}: {base}/findings?target_id={target.id}&q={f.vuln_id}")
    lines += ["", "_" + L(f"{PRODUCT_NAME} tarafından oluşturuldu.") + "_"]
    return "\n".join(ln for ln in lines if ln is not None)


def create_issue(db: Session, f: Finding, inst: JiraInstance) -> tuple[str, str]:
    if f.jira_key:
        return f.jira_key, f.jira_url or ""
    cfg = config(inst)
    target = db.get(Target, f.target_id)
    project: Project = target.project
    key = (project.jira_project_key or cfg["project_key"]).strip()
    if not key:
        raise JiraError(f"'{inst.name}' için Jira proje anahtarı tanımlı değil (Ayarlar → Jira veya proje ayarları)")
    cve = next((a for a in (f.aliases or []) if a.startswith("CVE-")), f.vuln_id)
    labels = [x.strip().replace(" ", "-") for x in cfg["labels"].split(",") if x.strip()]
    labels += [f"severity-{f.severity.lower()}", f"scakit-f{f.id}"] + (["kev"] if f.kev else [])
    body = {"fields": {
        "project": {"key": key},
        "issuetype": {"name": cfg["issue_type"] or "Bug"},
        "summary": f"[{PRODUCT_NAME}] {cve} — {f.component} {f.version} ({target.name})"[:250],
        "description": _description(db, f, target),
        "labels": labels,
    }}
    res = _call(inst, "POST", "/rest/api/2/issue", body)
    f.jira_key = res.get("key")
    f.jira_url = f"{cfg['url']}/browse/{f.jira_key}"
    f.jira_instance_id = inst.id
    db.commit()
    return f.jira_key, f.jira_url


def instance_of(db: Session, f: Finding) -> JiraInstance | None:
    if f.jira_instance_id:
        return db.get(JiraInstance, f.jira_instance_id)
    ins = instances(db)
    return ins[0] if len(ins) == 1 else None


def comment(db: Session, f: Finding, text: str) -> None:
    inst = instance_of(db, f) if f.jira_key else None
    if inst:
        _call(inst, "POST", f"/rest/api/2/issue/{f.jira_key}/comment", {"body": text})


def auto_instance(db: Session, project: Project) -> JiraInstance | None:
    ins = [i for i in instances(db) if ready(i) and (not i.org_ids or project.organization_id in i.org_ids)]
    return next((i for i in ins if i.id == project.jira_instance_id), None) or \
        next((i for i in ins if i.auto_min_severity.upper() in SEVERITY_RANK), None)


def after_scan(db: Session, scan, changes: dict, log=print) -> None:
    project = scan.target.project
    inst = auto_instance(db, project)
    thr = (inst.auto_min_severity if inst else "").upper()
    if inst and thr in SEVERITY_RANK:
        want = [r for r in changes.get("new", []) if r.status == "open"
                and (SEVERITY_RANK.get(r.severity, 0) >= SEVERITY_RANK[thr] or r.kev)]
        made = 0
        for r in want[:AUTO_CAP]:
            try:
                create_issue(db, r, inst)
                made += 1
            except JiraError as ex:
                log(f"  ! could not create Jira issue ({r.vuln_id}): {translate(str(ex), 'en')}")
                break
        if made:
            log(f"Jira ({inst.name}): {made} issues created" + (f" ({len(want) - AUTO_CAP} findings skipped due to the limit)"
                                                             if len(want) > AUTO_CAP else ""))
    lang = message_lang(db)
    for kind, text in (("fixed", translate(f"{PRODUCT_NAME}: tarama #{scan.id} ile bileşen artık görülmüyor, bulgu "
                                           "*Düzeltildi* olarak işaretlendi.", lang)),
                       ("reopened", translate(f"{PRODUCT_NAME}: tarama #{scan.id} ile bulgu yeniden görüldü ve "
                                              "*yeniden açıldı*.", lang))):
        for r in changes.get(kind, []):
            ri = instance_of(db, r) if r.jira_key else None
            if ri and ri.comment_on_fix:
                try:
                    comment(db, r, text)
                except JiraError as ex:
                    log(f"  ! could not add Jira comment ({r.jira_key}): {translate(str(ex), 'en')}")
