from __future__ import annotations

import json
import shutil
import os
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from ..analysis import Canceled, ingest, match_engagement
from ..engagement import Engagement
from ..vulndb.db import VulnDB
from . import settings_store
from .config import get_config
from .guard import check_web_target
from .models import Comment, Finding, Job, Scan, User

ACTIVE = ("open", "in_progress")
REPORT_NAMES = {"tr": ("rapor", "bulgular"), "en": ("report", "findings"), "fr": ("rapport", "constats"),
                "de": ("bericht", "befunde")}
SUPPRESSING = {"accepted_risk": "accepted-risk", "false_positive": "false-positive", "not_affected": "not-affected"}


class JobContext:

    def __init__(self, db: Session, job: Job):
        self.db, self.job = db, job

    def log(self, msg: str) -> None:
        self.job.log = (self.job.log + msg + "\n")[-200_000:]
        self.db.commit()

    def event(self, code: str, level: str = "info", **params) -> None:
        from datetime import datetime, timezone
        ev = {"at": datetime.now(timezone.utc).isoformat(), "code": code, "level": level, "params": params}
        self.job.events = [*(self.job.events or []), ev][-500:]
        self.db.commit()

    def progress(self, pct: int) -> None:
        self.job.progress = pct
        self.db.commit()

    def canceled(self) -> bool:
        self.db.refresh(self.job, ["status"])
        return self.job.status == "canceled"


def vulndb(db: Session) -> VulnDB:
    path = settings_store.get(db, "vulndb_path").strip()
    return VulnDB(path or None)


def run_scan(db: Session, job: Job, ctx: JobContext) -> None:
    scan = db.query(Scan).filter_by(job_id=job.id).one()
    target = scan.target
    project = target.project
    org = project.organization
    creator = db.get(User, scan.created_by) if scan.created_by else None
    work = get_config().scans_dir / str(scan.id)
    if work.exists():
        shutil.rmtree(work, ignore_errors=True)
    eng = Engagement.create(work / "eng", f"{project.name} — {target.name}", org.name, project.report_lang)
    scan.workdir = str(work)
    db.commit()
    if project.license_policy:
        (eng.path / "license_policy.json").write_text(json.dumps(project.license_policy))

    ctx.log(f"Tarama başladı: {target.name} ({target.kind})")
    waf_info: dict = {}
    access_info: dict = {}
    ctx.event("scan_started", target=target.name, kind=target.kind, url=target.url or None,
              files=[f["name"] for f in target.files] if target.kind == "upload" else None)
    ctx.progress(5)
    names = {str(get_config().uploads_dir / str(target.id) / f["stored"]): f["name"] for f in target.files}

    def on_input(stage, inp, **kw):
        ctx.event(f"input_{stage}", "warn" if stage == "error" else "info",
                  name=names.get(inp, inp.split("/")[-1] if not inp.startswith("http") else inp), **kw)
    opts = target.options or {}
    if target.kind == "web":
        role = creator.role if creator else "customer"
        check_web_target(target.url, role=role, allowed_domains=org.allowed_domains,
                         allow_internal=settings_store.get_bool(db, "allow_internal_targets"))
        from . import webauth
        from .guard import outbound_guard
        auth = webauth.load(target.auth_enc)
        headers, login = webauth.to_scan(auth)
        web = {"delay": float(opts.get("delay", settings_store.get(db, "web_default_delay"))),
               "max_pages": int(opts.get("max_pages", settings_store.get(db, "web_default_max_pages"))),
               "probe": bool(opts.get("probe", True)), "verify_tls": bool(opts.get("verify_tls", True)),
               "headers": headers + ([f"User-Agent: {opts['user_agent']}"] if opts.get("user_agent") else []),
               "login": login, "browser_tls": opts.get("browser_tls") or None,
               "external_assets": bool(opts.get("external_assets", True)),
               "egress": {"mode": opts.get("egress") or "auto", "proxies": settings_store.proxies(db)}}

        def on_waf(info):
            waf_info.update(info)
            ctx.event("waf_detected", level="warn", vendor=info["vendor"], blocked=info["blocked"],
                      requests=info["requests"], severe=info["severe"])
        web["on_waf"] = on_waf

        def on_access(info):
            access_info.update(info)
            if info.get("severe"):
                ctx.event("access_issue", level="warn", issue=info["issue"], detail=str(info.get("detail", ""))[:120])
        web["on_access"] = on_access
        if web["browser_tls"]:
            ctx.event("browser_tls", profile=web["browser_tls"])
        if auth.get("type", "none") != "none":
            ctx.log(f"Kimlik doğrulama: {auth['type']}")
            ctx.event("auth", type=auth["type"])
        allow_internal = settings_store.get_bool(db, "allow_internal_targets") and role != "customer"
        with outbound_guard(enabled=not allow_internal):
            ingest(eng, [target.url], kind="web", target=target.name, web=web, log=ctx.log,
                   should_cancel=ctx.canceled, on_input=on_input)
    else:
        files = [str(get_config().uploads_dir / str(target.id) / f["stored"]) for f in target.files]
        if not files:
            raise ValueError("Hedefe yüklenmiş dosya yok")
        ingest(eng, files, kind="auto", target=target.name, os_eco=opts.get("os") or None,
               dev=bool(opts.get("dev")), log=ctx.log, should_cancel=ctx.canceled, on_input=on_input)
    if ctx.canceled():
        raise Canceled()
    ctx.progress(60)

    rules = [{"id": f.vuln_id, "component": f"{f.component}@{f.version}", "kind": SUPPRESSING[f.status],
              "reason": f.status_reason or "-", "by": "", "date": (f.last_seen_at or f.first_seen_at).date().isoformat()}
             for f in db.query(Finding).filter(Finding.target_id == target.id,
                                               Finding.status.in_(SUPPRESSING)).all()]
    findings, notes = match_engagement(eng, vulndb(db), extra_rules=rules)
    ctx.log(f"Eşleştirme: {len(eng.inventory.components)} bileşen, {len(findings)} bulgu "
            f"(+{len(notes.get('suppressed', []))} ayrılmış)")
    ctx.event("matched", components=len(eng.inventory.components), findings=len(findings),
              suppressed=len(notes.get("suppressed", [])))
    ctx.progress(80)

    stats, changes = sync_findings(db, scan, eng, findings, notes.get("suppressed", []))
    sev = {}
    for f in findings:
        sev[f.severity] = sev.get(f.severity, 0) + 1
    scan.summary = {"components": len(eng.inventory.components), "findings": len(findings), "severity": sev,
                    "kev": sum(f.kev for f in findings), **stats}
    if target.kind == "web" and access_info:
        scan.summary["access"] = access_info
    _input_diagnostics(scan, target, eng)
    if target.kind == "web" and waf_info:
        scan.summary["waf"] = waf_info
        if waf_info.get("severe") and opts.get("waf_assist") and scan.created_by:
            from . import collab
            collab.notify(db, [scan.created_by], "waf_assist", {"target": target.name, "scan_id": scan.id,
                                                                "vendor": waf_info.get("vendor")}, f"/scans/{scan.id}")
            ctx.event("waf_assist", level="warn", vendor=waf_info.get("vendor"))
    import hashlib
    src = target.url if target.kind == "web" else ",".join(sorted(f.get("sha256", "") for f in target.files))
    scan.summary["input_sha"] = hashlib.sha256(f"{target.kind}|{src}|{json.dumps(opts, sort_keys=True)}".encode()).hexdigest()[:16]
    keys = sorted(str(k) for k in eng.inventory.components) + sorted(f"{f.component_key}|{f.vuln_id}" for f in findings)
    scan.summary["result_sha"] = hashlib.sha256("\n".join(keys).encode()).hexdigest()[:16]
    db.commit()
    ctx.log(f"Bulgular: {stats['new']} yeni, {stats['fixed']} kapandı, {stats['reopened']} yeniden açıldı")
    ctx.event("synced", **stats)
    written = build_reports(eng, ctx.log, project.report_langs)
    ctx.event("reports", files=[p.name for p in written])
    ctx.progress(95)
    after_scan_integrations(db, scan, changes, ctx.log, ctx.event)
    ctx.progress(100)
    ctx.event("scan_finished", "success", findings=len(findings))


def after_scan_integrations(db: Session, scan: Scan, changes: dict, log, event=None) -> None:
    from . import jira, notify
    from .errors import humanize
    event = event or (lambda *a, **k: None)
    before = {r.id for r in changes["new"] if r.jira_key}
    try:
        jira.after_scan(db, scan, changes, log)
        made = sum(1 for r in changes["new"] if r.jira_key and r.id not in before)
        if made:
            event("jira_created", "success", count=made)
    except Exception as ex:
        event("jira_failed", "warn", **humanize(ex))
        log(f"  ! Jira adımı başarısız: {ex}")
    org_id = scan.target.project.organization_id
    new_active = [r for r in changes["new"] + changes["reopened"] if r.status in ACTIVE]

    def on_result(ch, ok, ex=None):
        if ok:
            event("notify_sent", "success", channel=ch.name, channel_kind=ch.kind)
        else:
            event("notify_failed", "warn", channel=ch.name, channel_kind=ch.kind, **humanize(ex))
    try:
        notify.dispatch(db, "scan_done", lambda _r: notify.build_scan_message(db, "scan_done", scan, new_active),
                        org_id, log, on_result=on_result)
        if new_active:
            notify.dispatch(db, "new_findings", lambda rows: notify.build_scan_message(db, "new_findings", scan, rows),
                            org_id, log, new_rows=new_active, on_result=on_result)
            notify.dispatch(db, "kev", lambda rows: notify.build_scan_message(db, "kev", scan, rows),
                            org_id, log, new_rows=new_active, on_result=on_result)
    except Exception as ex:
        log(f"  ! Bildirim adımı başarısız: {ex}")


def _evidence(comp) -> list[dict]:
    if comp is None:
        return []
    return [{"method": e.method, "location": e.location, "detail": e.detail[:300], "target": e.target,
             "line": e.line, "snippet": e.snippet} for e in comp.evidence[:25]]


def sync_findings(db: Session, scan: Scan, eng: Engagement, findings, suppressed) -> dict:
    from ..models import Finding as CoreFinding
    target = scan.target
    comps = eng.inventory.components
    now = datetime.now(timezone.utc)
    existing = {(f.component_key, f.vuln_id): f for f in db.query(Finding).filter_by(target_id=target.id)}
    seen = set()
    stats = {"new": 0, "fixed": 0, "reopened": 0}
    changes = {"new": [], "fixed": [], "reopened": []}
    all_items = [(f, False) for f in findings] + [(CoreFinding.from_dict({k: v for k, v in s.items()
                                                                          if k != "suppression"}), True)
                                                   for s in suppressed]
    for f, _is_sup in all_items:
        key = (f.component_key, f.vuln_id)
        seen.add(key)
        comp = comps.get(f.component_key)
        row = existing.get(key)
        if row is None:
            row = Finding(target_id=target.id, project_id=target.project_id, component_key=f.component_key,
                          vuln_id=f.vuln_id, first_seen_scan=scan.id, first_seen_at=now, status="open")
            db.add(row)
            stats["new"] += 1
            changes["new"].append(row)
        elif row.status == "fixed":
            row.status, row.resolved_at, row.resolved_scan = "open", None, None
            row.status_reason = f"Tarama #{scan.id} ile yeniden görüldü"
            row.reopened_scan = scan.id
            stats["reopened"] += 1
            db.add(Comment(finding_id=row.id, kind="scan_reopened", meta={"scan": scan.id},
                           text=f"Tarama #{scan.id} ile yeniden görüldü"))
            changes["reopened"].append(row)
        eco, name, ver = (f.component_key.split("|") + ["", "", ""])[:3]
        row.ecosystem, row.component, row.version = eco, (comp.name if comp else name), ver
        row.purl, row.severity, row.cvss, row.epss = f.component_purl, f.severity, f.cvss_score, f.epss
        row.kev, row.malicious, row.summary = f.kev, f.malicious, f.summary
        row.aliases, row.fixed_versions, row.upgrade_to = f.aliases, f.fixed_versions, f.upgrade_to
        row.confidence, row.source, row.reachability = f.confidence, f.source, f.reachability
        row.evidence = _evidence(comp)
        row.last_seen_scan, row.last_seen_at = scan.id, now
    for key, row in existing.items():
        if key not in seen and row.status in ACTIVE:
            row.status, row.resolved_at, row.resolved_scan = "fixed", now, scan.id
            row.status_reason = f"Tarama #{scan.id} ile artık görülmüyor"
            stats["fixed"] += 1
            db.add(Comment(finding_id=row.id, kind="scan_fixed", meta={"scan": scan.id},
                           text=f"Tarama #{scan.id} ile artık görülmüyor"))
            changes["fixed"].append(row)
    db.commit()
    return stats, changes


def build_reports(eng: Engagement, log, extra_langs=None, main_lang: str | None = None) -> list[Path]:
    from ..report import data as rdata
    from ..report import render
    findings, fdoc = eng.load_findings()
    main = main_lang if main_lang in REPORT_NAMES else eng.meta.get("lang", "tr")
    langs = [main, *[x for x in (extra_langs or []) if x != main and x in REPORT_NAMES]]
    d = rdata.build(eng, findings, fdoc)
    out = eng.path / "reports"
    out.mkdir(exist_ok=True)
    written = []
    for name, fn in (("sbom.cdx.json", lambda p: p.write_text(render.to_cyclonedx(d), encoding="utf-8")),
                     ("sbom.spdx.json", lambda p: p.write_text(render.to_spdx(d), encoding="utf-8"))):
        fn(out / name)
        written.append(out / name)
    for lang in langs:
        rep, fnd = REPORT_NAMES[lang]
        (out / f"{rep}_{lang}.html").write_text(render.to_html(d, lang), encoding="utf-8")
        (out / f"{fnd}_{lang}.csv").write_text(render.to_csv(d, lang), encoding="utf-8-sig")
        written += [out / f"{rep}_{lang}.html", out / f"{fnd}_{lang}.csv"]
        try:
            from ..report import document
            document.to_pdf(d, lang, out / f"{rep}_{lang}.pdf")
            document.to_docx(d, lang, out / f"{rep}_{lang}.docx")
            written += [out / f"{rep}_{lang}.pdf", out / f"{rep}_{lang}.docx"]
        except ImportError as ex:
            log(f"  ! PDF/Word rapor üretilemedi ({ex.name} kurulu değil)")
    log(f"Raporlar üretildi: {', '.join(p.name for p in written)}")
    return written


def run_db_update(db: Session, job: Job, ctx: JobContext) -> None:
    from ..vulndb.db import update_from_dir, update_online
    key = settings_store.get(db, "nvd_api_key")
    if key:
        os.environ["NVD_API_KEY"] = key
    vdb = vulndb(db)
    src = (job.params or {}).get("from_dir")
    ctx.log("Zafiyet veritabanı güncelleniyor" + (f" ({src} klasöründen)" if src else " (internetten)"))
    if src:
        update_from_dir(vdb, src, ctx.log)
    else:
        update_online(vdb, log=ctx.log, nvd=not (job.params or {}).get("no_nvd"))
    st = vdb.stats()
    ctx.log(f"Tamamlandı: OSV {st['vulns']} kayıt, EPSS {st['epss']}, KEV {st['kev']}")


def run_report(db: Session, job: Job, ctx: JobContext) -> None:
    scan = db.get(Scan, job.params["scan_id"])
    eng = Engagement(Path(scan.workdir) / "eng")
    rules = [{"id": f.vuln_id, "component": f"{f.component}@{f.version}", "kind": SUPPRESSING[f.status],
              "reason": f.status_reason or "-", "by": "", "date": f.last_seen_at.date().isoformat()}
             for f in db.query(Finding).filter(Finding.target_id == scan.target_id,
                                               Finding.status.in_(SUPPRESSING)).all()]
    match_engagement(eng, vulndb(db), extra_rules=rules)
    proj = scan.target.project
    build_reports(eng, ctx.log, proj.report_langs, proj.report_lang)


def run_selfscan(db: Session, job: Job, ctx: JobContext) -> None:
    from . import sysinfo
    ctx.log("scakit bileşenleri kendi zafiyet veritabanıyla taranıyor (Python, arayüz, işletim sistemi)")
    res = sysinfo.selfscan(db)
    ctx.log(f"Tamamlandı: {sum(res['components'].values())} bileşen, {res['vulnerable']} bileşende zafiyet")
    job.params = {**(job.params or {}), "result": res}
    db.commit()


HANDLERS = {"scan": run_scan, "db_update": run_db_update, "report": run_report, "selfscan": run_selfscan}


INPUT_NOTE_KINDS = {"missing-lockfile", "obfuscated", "packed", "no-osv-coverage", "unsupported-layer"}


def _input_diagnostics(scan, target, eng) -> None:
    notes, seen = [], set()
    for o in getattr(eng.inventory, "observations", []):
        if o.kind in INPUT_NOTE_KINDS and (o.kind, o.detail[:60]) not in seen and len(notes) < 25:
            seen.add((o.kind, o.detail[:60]))
            notes.append({"kind": o.kind, "location": o.location[-200:], "detail": o.detail[:200]})
    if notes:
        scan.summary["input_notes"] = notes
    if target.kind == "upload" and not eng.inventory.components:
        names = [f.get("name", "") for f in (target.files or [])]
        scan.summary["access"] = {"issue": "empty_input", "severe": True, "detail": ", ".join(names)[:200],
                                  "type": (target.options or {}).get("type", "")}
