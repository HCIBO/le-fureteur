from __future__ import annotations

import hashlib
import json
import re
import shutil
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, Response, UploadFile
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from .. import PRODUCT_NAME, __version__
from . import settings_store
from .config import get_config
from .db import get_db
from .deps import (client_ip, current_user, get_finding, get_org, get_project, get_scan, get_target, org_scope,
                   token_project,
                   require)
from .guard import TargetError, check_web_target
from .models import (FINDING_STATUSES, PERMISSIONS, ROLES, AuditLog, Comment, Finding, Job, Organization, Project, Scan, Target,
                     User)
from .security import (CSRF_COOKIE, SESSION_COOKIE, audit, clear_failures, create_session, end_session,
                       end_user_sessions, hash_password, new_csrf, password_problem, record_failure, throttled,
                       verify_password)

router = APIRouter(prefix="/api")
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
REPORT_LANGS = ("tr", "en", "fr", "de")


def iso(dt):
    if not dt:
        return None
    if getattr(dt, "tzinfo", None) is None and hasattr(dt, "replace"):
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


class LoginIn(BaseModel):
    email: str
    password: str


def user_out(u: User) -> dict:
    return {"id": u.id, "email": u.email, "name": u.name, "role": u.role, "organization_id": u.organization_id,
            "organization": u.organization.name if u.organization else None, "active": u.active, "lang": u.lang,
            "last_login": iso(u.last_login), "created_at": iso(u.created_at),
            "permissions": list(PERMISSIONS) if u.role == "admin" else list(u.permissions or [])}


def has_perm(u: User, perm: str) -> bool:
    if getattr(u, "via_token", False):
        return False
    return u.role == "admin" or perm in (u.permissions or [])


@router.post("/auth/login")
def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)):
    ip = client_ip(request)
    ua = request.headers.get("user-agent", "")[:400]
    email = body.email.strip().lower()[:254]
    key = f"{ip}|{email}"
    window = settings_store.get_int(db, "login_window_minutes", 1)
    user = db.query(User).filter(func.lower(User.email) == email).first()
    if throttled(key, settings_store.get_int(db, "login_max_failures", 1), window * 60):
        _login_event(db, user, email, ip, ua, "password", False, "throttled")
        raise HTTPException(429, f"Çok fazla başarısız deneme; {window} dakika sonra tekrar deneyin")
    if user is None or not user.active or not verify_password(user.password_hash, body.password):
        record_failure(key)
        _login_event(db, user, email, ip, ua, "password", False,
                     "no_account" if user is None else "inactive" if not user.active else "bad_password")
        audit(db, None, "login.failed", "user", detail=body.email[:200], ip=ip)
        raise HTTPException(401, "E-posta veya parola hatalı")
    clear_failures(key)
    if user.role != "admin" and settings_store.get_bool(db, "maintenance_mode"):
        _login_event(db, user, email, ip, ua, "password", False, "maintenance")
        raise HTTPException(503, detail={"code": "maintenance", "message": settings_store.get(db, "maintenance_message")})
    token = create_session(db, user, ip, ua, "password")
    _login_event(db, user, email, ip, ua, "password", True, "")
    cfg = get_config()
    response.set_cookie(SESSION_COOKIE, token, httponly=True, secure=cfg.cookie_secure, samesite="strict",
                        max_age=cfg.session_hours * 3600, path="/")
    response.set_cookie(CSRF_COOKIE, new_csrf(), httponly=False, secure=cfg.cookie_secure, samesite="strict", path="/")
    audit(db, user, "login", "user", user.id, ip=ip)
    return user_out(user)


def _login_event(db: Session, user: User | None, email: str, ip: str, ua: str, method: str, success: bool,
                 reason: str) -> None:
    from .models import LoginEvent
    db.add(LoginEvent(user_id=user.id if user else None, email=email, ip=ip, user_agent=ua, method=method,
                      success=success, reason=reason))
    db.commit()


@router.get("/public/status")
def public_status(db: Session = Depends(get_db)):
    on = settings_store.get_bool(db, "maintenance_mode")
    return {"maintenance": on, "message": settings_store.get(db, "maintenance_message") if on else ""}


@router.post("/auth/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    end_session(db, request.cookies.get(SESSION_COOKIE))
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}


@router.get("/auth/me")
def me(user: User = Depends(current_user)):
    return user_out(user)


class MeIn(BaseModel):
    lang: str


@router.patch("/auth/me")
def update_me(body: MeIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if body.lang not in REPORT_LANGS:
        raise HTTPException(400, "Geçersiz dil")
    user.lang = body.lang
    db.commit()
    return user_out(user)


class PasswordIn(BaseModel):
    current: str
    new: str


@router.post("/auth/password")
def change_password(body: PasswordIn, request: Request, response: Response, user: User = Depends(current_user),
                    db: Session = Depends(get_db)):
    if not verify_password(user.password_hash, body.current):
        raise HTTPException(400, "Mevcut parola hatalı")
    if (p := password_problem(body.new)):
        raise HTTPException(400, p)
    user.password_hash = hash_password(body.new)
    db.commit()
    end_user_sessions(db, user.id)
    response.delete_cookie(SESSION_COOKIE, path="/")
    audit(db, user, "password.change", "user", user.id, ip=client_ip(request))
    return {"ok": True}


class UserIn(BaseModel):
    email: str = Field(max_length=254)
    name: str = ""
    password: str
    role: str
    organization_id: int | None = None


class UserPatch(BaseModel):
    name: str | None = None
    role: str | None = None
    organization_id: int | None = None
    active: bool | None = None
    password: str | None = None
    permissions: list[str] | None = None


def _validate_role(db: Session, role: str, org_id: int | None):
    if role not in ROLES:
        raise HTTPException(400, f"Geçersiz rol: {role}")
    if role == "customer" and (org_id is None or db.get(Organization, org_id) is None):
        raise HTTPException(400, "Müşteri kullanıcısı bir organizasyona bağlı olmalı")


@router.get("/users")
def list_users(_: User = Depends(require("admin")), db: Session = Depends(get_db)):
    return [user_out(u) for u in db.query(User).order_by(User.email)]


@router.post("/users")
def create_user(body: UserIn, request: Request, admin: User = Depends(require("admin")), db: Session = Depends(get_db)):
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", body.email):
        raise HTTPException(400, "Geçersiz e-posta")
    if db.query(User).filter(func.lower(User.email) == body.email.lower()).first():
        raise HTTPException(409, "Bu e-posta zaten kayıtlı")
    _validate_role(db, body.role, body.organization_id)
    if (p := password_problem(body.password)):
        raise HTTPException(400, p)
    u = User(email=body.email.lower(), name=body.name, password_hash=hash_password(body.password), role=body.role,
             organization_id=body.organization_id if body.role == "customer" else body.organization_id)
    db.add(u)
    db.commit()
    audit(db, admin, "user.create", "user", u.id, f"{u.email} rol={u.role}", client_ip(request))
    return user_out(u)


@router.patch("/users/{user_id}")
def update_user(user_id: int, body: UserPatch, request: Request, admin: User = Depends(require("admin")),
                db: Session = Depends(get_db)):
    u = db.get(User, user_id)
    if u is None:
        raise HTTPException(404, "Kullanıcı bulunamadı")
    if u.id == admin.id and (body.role not in (None, "admin") or body.active is False):
        raise HTTPException(400, "Kendi admin yetkinizi kaldıramaz / hesabınızı kapatamazsınız")
    role = body.role or u.role
    org = body.organization_id if body.organization_id is not None else u.organization_id
    _validate_role(db, role, org)
    if body.permissions is not None and not set(body.permissions) <= set(PERMISSIONS):
        raise HTTPException(400, "Geçersiz yetki")
    changes = body.model_dump(exclude_none=True, exclude={"password"})
    for k, v in changes.items():
        setattr(u, k, v)
    if body.password:
        if (p := password_problem(body.password)):
            raise HTTPException(400, p)
        u.password_hash = hash_password(body.password)
    db.commit()
    if body.password or body.active is False or body.role:
        end_user_sessions(db, u.id)
    audit(db, admin, "user.update", "user", u.id, json.dumps(changes, ensure_ascii=False) +
          (" +parola" if body.password else ""), client_ip(request))
    return user_out(u)


@router.delete("/users/{user_id}")
def delete_user(user_id: int, request: Request, admin: User = Depends(require("admin")), db: Session = Depends(get_db)):
    u = db.get(User, user_id)
    if u is None:
        raise HTTPException(404, "Kullanıcı bulunamadı")
    if u.id == admin.id:
        raise HTTPException(400, "Kendi hesabınızı silemezsiniz")
    db.delete(u)
    db.commit()
    audit(db, admin, "user.delete", "user", user_id, u.email, client_ip(request))
    return {"ok": True}


class OrgIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    allowed_domains: list[str] = []
    notes: str = Field(default="", max_length=5000)
    tags: list[str] = Field(default=[], max_length=20)
    industry: str = Field(default="", max_length=100)
    contact_name: str = Field(default="", max_length=200)
    contact_email: str = Field(default="", max_length=254)
    contract_end: datetime | None = None


class OrgPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    allowed_domains: list[str] | None = None
    notes: str | None = Field(default=None, max_length=5000)
    tags: list[str] | None = Field(default=None, max_length=20)
    industry: str | None = Field(default=None, max_length=100)
    contact_name: str | None = Field(default=None, max_length=200)
    contact_email: str | None = Field(default=None, max_length=254)
    contract_end: datetime | None = None


def _org_extra(o: Organization, body) -> None:
    if body.tags is not None:
        o.tags = sorted({x.strip()[:40] for x in body.tags if x.strip()})
    if body.industry is not None:
        o.industry = body.industry.strip() or None
    if body.contact_name is not None:
        o.contact_name = body.contact_name.strip() or None
    if body.contact_email is not None:
        e = body.contact_email.strip().lower()
        if e and not re.match(r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$", e):
            raise HTTPException(400, "Geçersiz e-posta adresi")
        o.contact_email = e or None
    if "contract_end" in body.model_fields_set:
        o.contract_end = body.contract_end


def org_out(o: Organization, db: Session) -> dict:
    return {"id": o.id, "name": o.name, "allowed_domains": o.allowed_domains, "notes": o.notes,
            "created_at": iso(o.created_at), "tags": o.tags or [], "industry": o.industry or "",
            "contact_name": o.contact_name or "", "contact_email": o.contact_email or "",
            "contract_end": iso(o.contract_end),
            "users": db.query(func.count(User.id)).filter_by(organization_id=o.id).scalar(),
            "open": _open_counts(db, organization_id=o.id),
            "projects": db.query(func.count(Project.id)).filter_by(organization_id=o.id).scalar()}


def _clean_domains(items: list[str]) -> list[str]:
    out = []
    for d in items:
        d = d.strip().lower()
        if not d:
            continue
        if not re.match(r"^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", d):
            raise HTTPException(400, f"Geçersiz alan adı: {d}")
        out.append(d)
    return sorted(set(out))


def _purge_files(db: Session, targets) -> None:
    cfg = get_config()
    for t in targets:
        shutil.rmtree(cfg.uploads_dir / str(t.id), ignore_errors=True)
        for (sid,) in db.query(Scan.id).filter(Scan.target_id == t.id):
            shutil.rmtree(cfg.scans_dir / str(sid), ignore_errors=True)


@router.get("/orgs")
def list_orgs(user: User = Depends(current_user), db: Session = Depends(get_db)):
    q = db.query(Organization).order_by(Organization.name)
    if (scope := org_scope(user)) is not None:
        q = q.filter(Organization.id == scope)
    return [org_out(o, db) for o in q]


@router.post("/orgs")
def create_org(body: OrgIn, request: Request, admin: User = Depends(require("admin")), db: Session = Depends(get_db)):
    if db.query(Organization).filter_by(name=body.name).first():
        raise HTTPException(409, "Bu adla bir organizasyon var")
    o = Organization(name=body.name, allowed_domains=_clean_domains(body.allowed_domains), notes=body.notes)
    _org_extra(o, body)
    db.add(o)
    db.commit()
    audit(db, admin, "org.create", "org", o.id, o.name, client_ip(request))
    return org_out(o, db)


@router.patch("/orgs/{org_id}")
def update_org(org_id: int, body: OrgPatch, request: Request, admin: User = Depends(require("admin")),
               db: Session = Depends(get_db)):
    o = get_org(db, admin, org_id)
    if body.name is not None:
        o.name = body.name
    if body.allowed_domains is not None:
        o.allowed_domains = _clean_domains(body.allowed_domains)
    if body.notes is not None:
        o.notes = body.notes
    _org_extra(o, body)
    db.commit()
    audit(db, admin, "org.update", "org", o.id, json.dumps(body.model_dump(mode="json", exclude_none=True), ensure_ascii=False),
          client_ip(request))
    return org_out(o, db)


@router.delete("/orgs/{org_id}")
def delete_org(org_id: int, request: Request, admin: User = Depends(require("admin")), db: Session = Depends(get_db)):
    o = get_org(db, admin, org_id)
    _purge_files(db, [t for p in o.projects for t in p.targets])
    db.delete(o)
    db.commit()
    audit(db, admin, "org.delete", "org", org_id, o.name, client_ip(request))
    return {"ok": True}


class ProjectIn(BaseModel):
    organization_id: int | None = None
    name: str = Field(min_length=1, max_length=200)
    description: str = ""
    report_lang: str = "tr"
    license_policy: dict = {}
    tag_ids: list[int] = []
    status: str = "active"
    due_date: datetime | None = None
    owner_id: int | None = None
    report_langs: list[str] = []


class ProjectPatch(BaseModel):
    name: str | None = None
    description: str | None = None
    report_lang: str | None = None
    license_policy: dict | None = None
    jira_project_key: str | None = None
    jira_instance_id: int | None = None
    queue_policy: dict | None = None
    ci_policy: dict | None = None
    tag_ids: list[int] | None = None
    status: str | None = None
    due_date: datetime | None = None
    owner_id: int | None = None
    report_langs: list[str] | None = None


def _open_counts(db: Session, **flt) -> dict:
    q = db.query(Finding.severity, func.count(Finding.id)).filter(Finding.status.in_(("open", "in_progress")))
    for k, v in flt.items():
        if k == "organization_id":
            q = q.join(Project, Project.id == Finding.project_id).filter(Project.organization_id == v)
        else:
            q = q.filter(getattr(Finding, k) == v)
    return dict(q.group_by(Finding.severity).all())


def _visible_tags(db: Session, user: User):
    from .models import Tag
    q = db.query(Tag)
    if (scope := org_scope(user)) is not None:
        q = q.filter((Tag.organization_id.is_(None)) | (Tag.organization_id == scope))
    return q


def _check_tags(db: Session, user: User, org_id: int, ids: list[int] | None) -> list[int]:
    from .models import Tag
    out = []
    for tid in dict.fromkeys(ids or []):
        tg = _visible_tags(db, user).filter(Tag.id == tid).first()
        if tg is None or (tg.organization_id and tg.organization_id != org_id):
            raise HTTPException(400, "Geçersiz etiket")
        out.append(tid)
    return out[:20]


def _project_tags(db: Session, p: Project) -> list[dict]:
    from .models import Tag
    if not p.tag_ids:
        return []
    tags = {t.id: t for t in db.query(Tag).filter(Tag.id.in_(p.tag_ids))}
    return [{"id": t.id, "name": t.name, "color": t.color, "builtin": t.builtin} for i in p.tag_ids if (t := tags.get(i))]


def _ci_effective(p: Project) -> dict:
    from .ci import effective_policy
    return effective_policy(p)


def project_out(p: Project, db: Session) -> dict:
    return {"id": p.id, "organization_id": p.organization_id, "organization": p.organization.name, "name": p.name,
            "description": p.description, "report_lang": p.report_lang, "license_policy": p.license_policy,
            "jira_project_key": p.jira_project_key, "jira_instance_id": p.jira_instance_id,
            "queue_policy": {**__import__("scakit.server.queueing", fromlist=["x"]).DEFAULT_POLICY, **(p.queue_policy or {})},
            "ci_policy": _ci_effective(p), "tags": _project_tags(db, p),
            "created_at": iso(p.created_at), "targets": len(p.targets), "open": _open_counts(db, project_id=p.id),
            "status": p.status or "active", "due_date": iso(p.due_date),
            "report_langs": [p.report_lang, *[x for x in (p.report_langs or []) if x != p.report_lang]],
            "owner": _brief(db.get(User, p.owner_id)) if p.owner_id else None,
            "last_scan_at": iso(db.query(func.max(Scan.created_at)).join(Target, Target.id == Scan.target_id)
                                .filter(Target.project_id == p.id).scalar()),
            "overdue": db.query(func.count(Finding.id)).filter(Finding.project_id == p.id,
                                                               Finding.status.in_(("open", "in_progress")),
                                                               Finding.due_date < datetime.now(timezone.utc)).scalar()}


PROJECT_STATUSES = ("planning", "active", "on_hold", "done")


def _project_extra(db: Session, user: User, p: Project, body) -> None:
    if body.report_langs is not None:
        p.report_langs = [x for x in dict.fromkeys(body.report_langs) if x in REPORT_LANGS and x != p.report_lang]
    if body.status is not None:
        if body.status not in PROJECT_STATUSES:
            raise HTTPException(400, "Geçersiz proje durumu")
        p.status = body.status
    if "due_date" in body.model_fields_set:
        p.due_date = body.due_date
    if "owner_id" in body.model_fields_set:
        if body.owner_id is not None and not _collab.eligible(db, db.get(User, body.owner_id), p.organization_id):
            raise HTTPException(400, "Bu kişi projeyi göremez; sahip yapılamaz")
        p.owner_id = body.owner_id


def _policy(d: dict) -> dict:
    return {k: [str(x).strip() for x in d.get(k, []) if str(x).strip()] for k in ("allowed", "review", "denied")}


@router.get("/projects")
def list_projects(org_id: int | None = None, tag: int | None = None, user: User = Depends(current_user),
                  db: Session = Depends(get_db)):
    q = db.query(Project).order_by(Project.name)
    if (scope := org_scope(user)) is not None:
        q = q.filter(Project.organization_id == scope)
    if tp := token_project(user):
        q = q.filter(Project.id == tp)
    if org_id:
        q = q.filter(Project.organization_id == org_id)
    rows = list(q)
    if tag:
        rows = [p for p in rows if tag in (p.tag_ids or [])]
    return [project_out(p, db) for p in rows]


@router.post("/projects")
def create_project(body: ProjectIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    org_id = org_scope(user) or body.organization_id
    if org_id is None:
        raise HTTPException(400, "Organizasyon seçilmeli")
    get_org(db, user, org_id)
    p = Project(organization_id=org_id, name=body.name, description=body.description,
                report_lang=body.report_lang if body.report_lang in REPORT_LANGS else "tr",
                license_policy=_policy(body.license_policy))
    p.tag_ids = _check_tags(db, user, org_id, body.tag_ids)
    _project_extra(db, user, p, body)
    db.add(p)
    db.commit()
    audit(db, user, "project.create", "project", p.id, p.name, client_ip(request))
    return project_out(p, db)


@router.get("/projects/{project_id}")
def read_project(project_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    return project_out(get_project(db, user, project_id), db)


@router.patch("/projects/{project_id}")
def update_project(project_id: int, body: ProjectPatch, request: Request, user: User = Depends(current_user),
                   db: Session = Depends(get_db)):
    p = get_project(db, user, project_id)
    if body.name is not None:
        p.name = body.name
    if body.description is not None:
        p.description = body.description
    if body.report_lang in REPORT_LANGS:
        p.report_lang = body.report_lang
    if body.license_policy is not None:
        p.license_policy = _policy(body.license_policy)
    if body.tag_ids is not None:
        p.tag_ids = _check_tags(db, user, p.organization_id, body.tag_ids)
    _project_extra(db, user, p, body)
    if body.ci_policy is not None:
        from .ci import clean_policy
        try:
            p.ci_policy = clean_policy(body.ci_policy)
        except ValueError as ex:
            raise HTTPException(400, str(ex))
    if body.queue_policy is not None:
        from . import queueing
        p.queue_policy = queueing.clean_policy(body.queue_policy, user.role)
    if body.jira_instance_id is not None:
        if body.jira_instance_id == 0:
            p.jira_instance_id = None
        elif not any(i.id == body.jira_instance_id for i in _jira.usable(db, user, p.organization_id)):
            raise HTTPException(400, "Bu Jira bağlantısını kullanma yetkiniz yok")
        else:
            p.jira_instance_id = body.jira_instance_id
    if body.jira_project_key is not None:
        key = body.jira_project_key.strip().upper()
        if key and not re.match(r"^[A-Z][A-Z0-9_]{0,49}$", key):
            raise HTTPException(400, "Geçersiz Jira proje anahtarı")
        p.jira_project_key = key or None
    db.commit()
    audit(db, user, "project.update", "project", p.id, ip=client_ip(request))
    return project_out(p, db)


@router.delete("/projects/{project_id}")
def delete_project(project_id: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    p = get_project(db, user, project_id)
    _purge_files(db, p.targets)
    db.delete(p)
    db.commit()
    audit(db, user, "project.delete", "project", project_id, p.name, client_ip(request))
    return {"ok": True}


class TargetIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    kind: str
    url: str = ""
    options: dict = {}
    auth: dict | None = None


class TargetPatch(BaseModel):
    name: str | None = None
    url: str | None = None
    options: dict | None = None
    auth: dict | None = None


def _apply_auth(db: Session, user: User, t: Target, data: dict | None, org: Organization) -> None:
    from . import webauth
    if data is None or t.kind != "web":
        return
    try:
        auth = webauth.validate(data, webauth.load(t.auth_enc), t.url, role=user.role,
                                allowed_domains=org.allowed_domains,
                                allow_internal=settings_store.get_bool(db, "allow_internal_targets"))
    except webauth.AuthError as ex:
        raise HTTPException(400, str(ex))
    t.auth_enc = webauth.dump(auth)


WEB_OPTS = {"delay": float, "max_pages": int, "probe": bool, "verify_tls": bool, "user_agent": str, "waf_assist": bool,
            "browser_tls": str, "external_assets": bool, "egress": str}
UPLOAD_OPTS = {"os": str, "dev": bool, "type": str}
UPLOAD_TYPES = ("source", "mobile", "image", "desktop", "sbom", "packages", "traffic", "other")


def _browser_tls_available() -> bool:
    from ..collectors.blackbox.browser_tls import available
    return available()


def _options(kind: str, opts: dict) -> dict:
    allowed = WEB_OPTS if kind == "web" else UPLOAD_OPTS
    out = {}
    for k, typ in allowed.items():
        if k in opts and opts[k] not in (None, ""):
            try:
                out[k] = typ(opts[k])
            except (TypeError, ValueError):
                raise HTTPException(400, f"Geçersiz seçenek: {k}")
    if "delay" in out:
        out["delay"] = max(0.2, min(out["delay"], 10.0))
    if "max_pages" in out:
        out["max_pages"] = max(1, min(out["max_pages"], 200))
    if "user_agent" in out:
        ua = out["user_agent"].strip()
        if len(ua) > 300 or any(c in ua for c in "\r\n\0") or not ua.isprintable():
            raise HTTPException(400, "Geçersiz User-Agent")
        out["user_agent"] = ua
    if "egress" in out and not re.fullmatch(r"[A-Za-z0-9_-]{1,30}", out["egress"]):
        raise HTTPException(400, "Geçersiz çıkış noktası")
    if "browser_tls" in out:
        from ..collectors.blackbox.browser_tls import PROFILES, available
        if out["browser_tls"] not in (*PROFILES, "auto", "off"):
            raise HTTPException(400, "Geçersiz tarayıcı profili")
        if out["browser_tls"] in PROFILES and not available():
            raise HTTPException(400, "Sunucuda curl_cffi kurulu değil (pip install 'scakit[browser-tls]')")
    if "type" in out and out["type"] not in UPLOAD_TYPES:
        raise HTTPException(400, "Geçersiz hedef türü")
    if "os" in out and not re.match(r"^[A-Za-z]{2,20}(:[A-Za-z0-9._-]{1,20})?$", out["os"]):
        raise HTTPException(400, "İşletim sistemi biçimi: Debian:12, Ubuntu:22.04, Alpine:3.19")
    return out


def _check_url(db: Session, user: User, org: Organization, url: str) -> str:
    try:
        return check_web_target(url, role=user.role, allowed_domains=org.allowed_domains,
                                allow_internal=settings_store.get_bool(db, "allow_internal_targets"))
    except TargetError as ex:
        raise HTTPException(400, str(ex))


def target_out(t: Target, db: Session) -> dict:
    last = db.query(Scan).filter_by(target_id=t.id).order_by(Scan.id.desc()).first()
    return {"id": t.id, "project_id": t.project_id, "name": t.name, "kind": t.kind, "url": t.url,
            "options": t.options, "files": [{k: f[k] for k in ("name", "size", "sha256", "stored")} for f in t.files],
            "created_at": iso(t.created_at), "open": _open_counts(db, target_id=t.id),
            "last_scan": scan_out(last) if last else None, "auth": _auth_view(t)}


def _auth_view(t: Target) -> dict:
    from . import webauth
    return webauth.masked(webauth.load(t.auth_enc)) if t.kind == "web" else {"type": "none"}


@router.get("/projects/{project_id}/targets")
def list_targets(project_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    p = get_project(db, user, project_id)
    return [target_out(t, db) for t in sorted(p.targets, key=lambda t: t.name.lower())]


@router.post("/projects/{project_id}/targets")
def create_target(project_id: int, body: TargetIn, request: Request, user: User = Depends(current_user),
                  db: Session = Depends(get_db)):
    p = get_project(db, user, project_id)
    if body.kind not in ("web", "upload"):
        raise HTTPException(400, "Hedef türü 'web' veya 'upload' olmalı")
    url = _check_url(db, user, p.organization, body.url) if body.kind == "web" else ""
    t = Target(project_id=p.id, name=body.name, kind=body.kind, url=url, options=_options(body.kind, body.options),
               files=[])
    _apply_auth(db, user, t, body.auth, p.organization)
    db.add(t)
    db.commit()
    audit(db, user, "target.create", "target", t.id, f"{t.kind} {url or t.name} auth={_auth_view(t)['type']}",
          client_ip(request))
    return target_out(t, db)


class BulkWebIn(BaseModel):
    urls: list[str] = Field(min_length=1, max_length=50)
    options: dict = {}
    auth: dict | None = None


@router.post("/projects/{project_id}/targets/bulk")
def create_web_targets(project_id: int, body: BulkWebIn, request: Request, user: User = Depends(current_user),
                       db: Session = Depends(get_db)):
    p = get_project(db, user, project_id)
    opts = _options("web", body.options)
    existing = {t.url for t in p.targets if t.kind == "web"}
    created, errors = [], []
    for raw in dict.fromkeys(u.strip() for u in body.urls if u.strip()):
        u = raw if "://" in raw else f"https://{raw}"
        try:
            url = _check_url(db, user, p.organization, u)
        except HTTPException as ex:
            errors.append({"url": raw, "error": ex.detail})
            continue
        if url in existing:
            errors.append({"url": raw, "error": "Bu adres projede zaten hedef olarak var"})
            continue
        name = (urlparse(url).hostname or url)[:200]
        t = Target(project_id=p.id, name=name, kind="web", url=url, options=dict(opts), files=[])
        _apply_auth(db, user, t, body.auth, p.organization)
        db.add(t)
        db.flush()
        existing.add(url)
        created.append(t)
    db.commit()
    for t in created:
        audit(db, user, "target.create", "target", t.id, f"web {t.url}", client_ip(request))
    return {"created": [target_out(t, db) for t in created], "errors": errors}


@router.get("/targets/{target_id}")
def read_target(target_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    return target_out(get_target(db, user, target_id), db)


@router.patch("/targets/{target_id}")
def update_target(target_id: int, body: TargetPatch, request: Request, user: User = Depends(current_user),
                  db: Session = Depends(get_db)):
    t = get_target(db, user, target_id)
    if body.name is not None:
        t.name = body.name
    if body.url is not None and t.kind == "web":
        t.url = _check_url(db, user, t.project.organization, body.url)
        from . import webauth
        cur = webauth.load(t.auth_enc)
        if cur.get("type") == "form" and body.auth is None and \
                urlparse(cur["login_url"]).hostname != urlparse(t.url).hostname:
            raise HTTPException(400, "Adres değişti: önce form ile giriş ayarını güncelleyin")
    if body.options is not None:
        t.options = _options(t.kind, body.options)
    _apply_auth(db, user, t, body.auth, t.project.organization)
    db.commit()
    audit(db, user, "target.update", "target", t.id, f"auth={_auth_view(t)['type']}" if body.auth else "",
          client_ip(request))
    return target_out(t, db)


@router.delete("/targets/{target_id}")
def delete_target(target_id: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    t = get_target(db, user, target_id)
    _purge_files(db, [t])
    db.delete(t)
    db.commit()
    audit(db, user, "target.delete", "target", target_id, t.name, client_ip(request))
    return {"ok": True}


_SAFE = re.compile(r"[^A-Za-z0-9._-]+")
MAX_FILES_PER_TARGET = 20


async def _store_upload(t: Target, file: UploadFile) -> dict:
    name = _SAFE.sub("_", Path(file.filename or "dosya").name)[:150] or "dosya"
    d = get_config().uploads_dir / str(t.id)
    d.mkdir(parents=True, exist_ok=True)
    stored = f"{uuid.uuid4().hex[:12]}_{name}"
    limit = get_config().max_upload_mb * 1024 * 1024
    h, size = hashlib.sha256(), 0
    dest = d / stored
    with open(dest, "wb") as out:
        while chunk := await file.read(1 << 20):
            size += len(chunk)
            if size > limit:
                out.close()
                dest.unlink(missing_ok=True)
                raise HTTPException(413, f"Dosya sınırı aşıldı ({get_config().max_upload_mb} MB)")
            h.update(chunk)
            out.write(chunk)
    dest.chmod(0o600)
    if name.lower().endswith((".har", ".xml", ".json")):
        from ..collectors.blackbox.traffic import sanitize_upload
        from ..safeio import UnsafeInput
        try:
            if sanitize_upload(dest):
                data = dest.read_bytes()
                size, h = len(data), hashlib.sha256(data)
        except (UnsafeInput, ValueError) as ex:
            dest.unlink(missing_ok=True)
            raise HTTPException(400, str(ex) if isinstance(ex, UnsafeInput) else "Trafik dosyası okunamadı")
    return {"name": name, "stored": stored, "size": size, "sha256": h.hexdigest(),
            "uploaded_at": datetime.now(timezone.utc).isoformat()}


@router.post("/targets/{target_id}/files")
async def upload_file(target_id: int, file: UploadFile, request: Request, user: User = Depends(current_user),
                      db: Session = Depends(get_db)):
    t = get_target(db, user, target_id)
    if t.kind != "upload":
        raise HTTPException(400, "Bu hedef dosya yüklemeyi desteklemiyor")
    if len(t.files) >= MAX_FILES_PER_TARGET:
        raise HTTPException(400, "Bir hedefe en fazla 20 dosya yüklenebilir; eskileri silin")
    entry = await _store_upload(t, file)
    t.files = [*t.files, entry]
    db.commit()
    audit(db, user, "target.upload", "target", t.id, f"{entry['name']} {entry['size']}B sha256={entry['sha256']}",
          client_ip(request))
    return target_out(t, db)


@router.delete("/targets/{target_id}/files/{stored}")
def delete_file(target_id: int, stored: str, request: Request, user: User = Depends(current_user),
                db: Session = Depends(get_db)):
    t = get_target(db, user, target_id)
    if not any(f["stored"] == stored for f in t.files):
        raise HTTPException(404, "Dosya bulunamadı")
    (get_config().uploads_dir / str(t.id) / Path(stored).name).unlink(missing_ok=True)
    t.files = [f for f in t.files if f["stored"] != stored]
    db.commit()
    audit(db, user, "target.file.delete", "target", t.id, stored, client_ip(request))
    return target_out(t, db)


def job_out(j: Job, with_log: bool = False) -> dict:
    out = {"id": j.id, "kind": j.kind, "status": j.status, "progress": j.progress, "error": j.error,
           "created_at": iso(j.created_at), "started_at": iso(j.started_at), "finished_at": iso(j.finished_at)}
    if with_log:
        out["log"] = j.log
        out["events"] = j.events or []
    return out


def scan_out(s: Scan, with_log: bool = False) -> dict:
    return {"id": s.id, "target_id": s.target_id, "target": s.target.name, "project_id": s.target.project_id,
            "project": s.target.project.name, "created_at": iso(s.created_at), "summary": s.summary,
            "job": job_out(s.job, with_log)}


class ScanStartIn(BaseModel):
    priority: str | None = None


def _startable(db: Session, user: User, t: Target) -> None:
    if t.kind == "upload" and not t.files:
        raise HTTPException(400, "Önce dosya yükleyin")
    if t.kind == "web":
        _check_url(db, user, t.project.organization, t.url)
    busy = db.query(Scan).join(Job).filter(Scan.target_id == t.id, Job.status.in_(("queued", "running"))).first()
    if busy:
        raise HTTPException(409, "Bu hedef için zaten bekleyen / çalışan bir tarama var")


@router.post("/targets/{target_id}/scans")
def start_scan(target_id: int, request: Request, body: ScanStartIn | None = None, user: User = Depends(current_user),
               db: Session = Depends(get_db)):
    from . import queueing
    t = get_target(db, user, target_id)
    _startable(db, user, t)
    pol = queueing.project_policy(t.project)
    if body and body.priority:
        pol = queueing.clean_policy({**pol, "priority": body.priority}, user.role)
    s = queueing.new_scan(db, t, user.id, pol)
    db.commit()
    audit(db, user, "scan.start", "scan", s.id, f"{t.name} öncelik={pol['priority']}", client_ip(request))
    return scan_out(s)


class BatchScanIn(BaseModel):
    target_ids: list[int] = Field(min_length=1, max_length=200)
    queue: dict | None = None
    save_default: bool = False


@router.post("/scans/batch")
def start_batch(body: BatchScanIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    from . import queueing
    targets = [get_target(db, user, tid) for tid in dict.fromkeys(body.target_ids)]
    pol = queueing.clean_policy(body.queue, user.role) if body.queue else None
    if body.save_default and pol:
        for pid in {t.project_id for t in targets}:
            p = get_project(db, user, pid)
            p.queue_policy = {**pol, "priority": "normal" if pol["priority"] == "high" else pol["priority"]}
    group = queueing.batch_group() if pol else None
    started, errors = [], []
    for t in targets:
        try:
            _startable(db, user, t)
        except HTTPException as ex:
            errors.append({"target_id": t.id, "name": t.name, "error": ex.detail})
            continue
        s = queueing.new_scan(db, t, user.id, pol, group)
        started.append(s.id)
    db.commit()
    if started:
        audit(db, user, "scan.batch", "scan", "", f"{len(started)} tarama · {pol or 'proje kuralı'}", client_ip(request))
    return {"started": started, "errors": errors}


def _delete_scans(db: Session, scans: list[Scan]) -> None:
    cfg = get_config()
    for s in scans:
        shutil.rmtree(cfg.scans_dir / str(s.id), ignore_errors=True)
        job = s.job
        db.delete(s)
        if job is not None:
            db.delete(job)


@router.delete("/scans/{scan_id}")
def delete_scan(scan_id: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    s = get_scan(db, user, scan_id)
    if s.job and s.job.status in ("queued", "running"):
        raise HTTPException(409, "Sıradaki veya çalışan tarama silinemez; önce iptal edin")
    name = s.target.name
    _delete_scans(db, [s])
    db.commit()
    audit(db, user, "scan.delete", "scan", scan_id, name, client_ip(request))
    return {"ok": True}


BULK_KINDS = ("projects", "targets", "scans")


class BulkIn(BaseModel):
    kind: str = Field(pattern="^(projects|targets|scans)$")
    ids: list[int] = Field(min_length=1, max_length=500)


def _bulk_objects(db: Session, user: User, body: BulkIn):
    getter = {"projects": get_project, "targets": get_target, "scans": get_scan}[body.kind]
    objs, errors = [], []
    for i in dict.fromkeys(body.ids):
        try:
            objs.append(getter(db, user, i))
        except HTTPException:
            errors.append({"id": i, "error": "Bulunamadı veya yetkiniz yok"})
    return objs, errors


def _bulk_counts(db: Session, kind: str, objs) -> dict:
    if kind == "projects":
        tids = [t.id for p in objs for t in p.targets]
        return {"projects": len(objs), "targets": len(tids),
                "scans": db.query(Scan).filter(Scan.target_id.in_(tids)).count() if tids else 0,
                "findings": db.query(Finding).filter(Finding.target_id.in_(tids)).count() if tids else 0}
    if kind == "targets":
        tids = [t.id for t in objs]
        return {"targets": len(tids), "scans": db.query(Scan).filter(Scan.target_id.in_(tids)).count() if tids else 0,
                "findings": db.query(Finding).filter(Finding.target_id.in_(tids)).count() if tids else 0}
    return {"scans": len(objs), "active": sum(1 for s in objs if s.job and s.job.status in ("queued", "running"))}


@router.post("/bulk/preview")
def bulk_preview(body: BulkIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if not has_perm(user, "bulk_delete"):
        raise HTTPException(403, "Toplu silme yetkiniz yok; yöneticiden isteyin")
    objs, errors = _bulk_objects(db, user, body)
    return {"counts": _bulk_counts(db, body.kind, objs), "errors": errors,
            "names": [f"#{o.id} · {o.target.name}" if body.kind == "scans" else o.name for o in objs][:20]}


@router.post("/bulk/delete")
def bulk_delete(body: BulkIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if not has_perm(user, "bulk_delete"):
        raise HTTPException(403, "Toplu silme yetkiniz yok; yöneticiden isteyin")
    objs, errors = _bulk_objects(db, user, body)
    deleted = []
    if body.kind == "scans":
        ok = []
        for s in objs:
            if s.job and s.job.status in ("queued", "running"):
                errors.append({"id": s.id, "error": "Sıradaki veya çalışan tarama silinemez"})
            else:
                ok.append(s)
        deleted = [s.id for s in ok]
        _delete_scans(db, ok)
    else:
        targets = [t for p in objs for t in p.targets] if body.kind == "projects" else objs
        _purge_files(db, targets)
        for o in objs:
            deleted.append(o.id)
            db.delete(o)
    db.commit()
    if deleted:
        audit(db, user, f"{body.kind[:-1]}.bulk_delete", body.kind[:-1], "", f"{len(deleted)} adet: {deleted[:50]}",
              client_ip(request))
    return {"deleted": deleted, "errors": errors}


class QueueMove(BaseModel):
    to: str = Field(pattern="^(top|up|down|bottom)$")


def _queue_order(db: Session) -> list[Job]:
    return db.query(Job).filter(Job.status == "queued").order_by(Job.priority.desc(), Job.created_at, Job.id).all()


@router.get("/queue")
def queue(user: User = Depends(current_user), db: Session = Depends(get_db)):
    scope = org_scope(user)
    scans = {s.job_id: s for s in db.query(Scan).join(Job).filter(Job.status.in_(("queued", "running")))}

    def item(j: Job, pos: int | None):
        s = scans.get(j.id)
        if s is None and j.kind == "scan":
            return None
        if scope is not None and (s is None or s.target.project.organization_id != scope):
            return None
        return {"job_id": j.id, "kind": j.kind, "position": pos, "priority": j.priority, "progress": j.progress,
                "created_at": iso(j.created_at), "started_at": iso(j.started_at),
                "scan_id": s.id if s else None, "target": s.target.name if s else None,
                "target_id": s.target_id if s else None, "project": s.target.project.name if s else None,
                "scheduled": bool((j.params or {}).get("schedule_id")),
                "rule": {"parallel": j.queue_parallel, "gap": j.queue_gap,
                         "batch": bool(j.queue_group and j.queue_group.startswith("batch:"))}}
    running = [x for j in db.query(Job).filter(Job.status == "running").order_by(Job.started_at) if (x := item(j, None))]
    queued = [x for i, j in enumerate(_queue_order(db)) if (x := item(j, i + 1))]
    return {"running": running, "queued": queued,
            "concurrency": settings_store.get_int(db, "queue_concurrency"),
            "gap_seconds": settings_store.get_int(db, "queue_gap_seconds"),
            "can_reorder": user.role in ("admin", "analyst") and not getattr(user, "via_token", False)}


@router.post("/queue/{job_id}/move")
def queue_move(job_id: int, body: QueueMove, request: Request, user: User = Depends(require("admin", "analyst")),
               db: Session = Depends(get_db)):
    order = _queue_order(db)
    idx = next((i for i, j in enumerate(order) if j.id == job_id), None)
    if idx is None:
        raise HTTPException(404, "İş kuyrukta değil")
    job = order.pop(idx)
    to = {"top": 0, "bottom": len(order), "up": max(0, idx - 1), "down": min(len(order), idx + 1)}[body.to]
    order.insert(to, job)
    n = len(order)
    for i, j in enumerate(order):
        j.priority = n - i
    db.commit()
    audit(db, user, "queue.move", "job", job.id, f"{body.to} → sıra {to + 1}/{n}", client_ip(request))
    return {"position": to + 1}


@router.get("/scans")
def list_scans(project_id: int | None = None, target_id: int | None = None, limit: int = Query(50, le=500),
               user: User = Depends(current_user), db: Session = Depends(get_db)):
    q = db.query(Scan).join(Target).join(Project).order_by(Scan.id.desc())
    if (scope := org_scope(user)) is not None:
        q = q.filter(Project.organization_id == scope)
    if tp := token_project(user):
        q = q.filter(Project.id == tp)
    if project_id:
        q = q.filter(Target.project_id == project_id)
    if target_id:
        q = q.filter(Scan.target_id == target_id)
    rows = q.limit(limit).all()
    dups = _duplicates(db, {s.target_id for s in rows})
    return [{**scan_out(s), **dups.get(s.id, {})} for s in rows]


def _duplicates(db: Session, target_ids: set[int]) -> dict[int, dict]:
    out: dict[int, dict] = {}
    if not target_ids:
        return out
    prev: dict[int, Scan] = {}
    for s in db.query(Scan).join(Job).filter(Scan.target_id.in_(target_ids), Job.status == "done").order_by(Scan.id):
        sm = s.summary or {}
        p = prev.get(s.target_id)
        if p is not None and sm.get("result_sha") and (p.summary or {}).get("result_sha") == sm["result_sha"]:
            out[s.id] = {"duplicate_of": p.id, "same_input": (p.summary or {}).get("input_sha") == sm.get("input_sha")}
        prev[s.target_id] = s
    return out


@router.get("/scans/{scan_id}")
def read_scan(scan_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    s = get_scan(db, user, scan_id)
    return {**scan_out(s, with_log=True), **_duplicates(db, {s.target_id}).get(s.id, {}),
            "target_kind": s.target.kind, "target_type": (s.target.options or {}).get("type")}


@router.post("/scans/{scan_id}/cancel")
def cancel_scan(scan_id: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    s = get_scan(db, user, scan_id)
    if s.job.status in ("queued", "running"):
        s.job.status = "canceled"
        s.job.finished_at = datetime.now(timezone.utc)
        db.commit()
        audit(db, user, "scan.cancel", "scan", s.id, ip=client_ip(request))
    return scan_out(s)


def _reports_dir(s: Scan) -> Path | None:
    return Path(s.workdir) / "eng" / "reports" if s.workdir else None


@router.get("/scans/{scan_id}/reports")
def list_reports(scan_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    d = _reports_dir(get_scan(db, user, scan_id))
    if not d or not d.exists():
        return []
    return [{"name": p.name, "size": p.stat().st_size} for p in sorted(d.iterdir()) if p.is_file()]


@router.get("/scans/{scan_id}/reports/{name}")
def download_report(scan_id: int, name: str, request: Request, user: User = Depends(current_user),
                    db: Session = Depends(get_db)):
    s = get_scan(db, user, scan_id)
    d = _reports_dir(s)
    p = (d / Path(name).name) if d else None
    if not p or not p.is_file():
        raise HTTPException(404, "Rapor bulunamadı")
    audit(db, user, "report.download", "scan", s.id, p.name, client_ip(request))
    resp = FileResponse(p, filename=p.name)
    resp.headers["Content-Security-Policy"] = "sandbox"
    return resp


@router.post("/scans/{scan_id}/reports/regenerate")
def regenerate_report(scan_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    s = get_scan(db, user, scan_id)
    if s.job.status != "done":
        raise HTTPException(400, "Tarama tamamlanmadan rapor üretilemez")
    job = Job(kind="report", params={"scan_id": s.id}, created_by=user.id)
    db.add(job)
    db.commit()
    return job_out(job)


@router.get("/scans/{scan_id}/components")
def scan_components(scan_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    s = get_scan(db, user, scan_id)
    p = Path(s.workdir) / "eng" / "inventory.json" if s.workdir else None
    if not p or not p.exists():
        return []
    inv = json.loads(p.read_text())
    return [{"ecosystem": c["ecosystem"], "name": c["name"], "version": c["version"], "confidence": c["confidence"],
             "direct": c.get("direct"), "licenses": c.get("licenses", []), "usage": c.get("usage"),
             "evidence": c["evidence"][:5]} for c in inv["components"]]


@router.get("/jobs/{job_id}")
def read_job(job_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    j = db.get(Job, job_id)
    if j is None:
        raise HTTPException(404, "İş bulunamadı")
    if j.kind == "scan":
        get_scan(db, user, db.query(Scan).filter_by(job_id=j.id).one().id)
    elif j.kind == "report":
        get_scan(db, user, (j.params or {}).get("scan_id", 0))
    elif getattr(user, "via_token", False) or (user.role == "customer" and j.created_by != user.id):
        raise HTTPException(404, "İş bulunamadı")
    return job_out(j, with_log=user.role != "customer" or j.kind != "db_update")


def _user_brief(f: Finding):
    if not f.assignee_id:
        return None
    from sqlalchemy.orm import object_session
    u = object_session(f).get(User, f.assignee_id)
    return {"id": u.id, "email": u.email, "name": u.name} if u else None


def finding_out(f: Finding, full: bool = False) -> dict:
    out = {"id": f.id, "project_id": f.project_id, "target_id": f.target_id, "vuln_id": f.vuln_id,
           "cves": [a for a in f.aliases if a.startswith("CVE-")], "ecosystem": f.ecosystem, "component": f.component,
           "version": f.version, "severity": f.severity, "cvss": f.cvss, "epss": f.epss, "kev": f.kev,
           "malicious": f.malicious, "summary": f.summary, "upgrade_to": f.upgrade_to, "confidence": f.confidence,
           "source": f.source, "reachability": f.reachability, "status": f.status,
           "jira_key": f.jira_key, "jira_url": f.jira_url, "assignee": _user_brief(f),
           "due_date": iso(f.due_date),
           "first_seen_at": iso(f.first_seen_at), "last_seen_at": iso(f.last_seen_at), "resolved_at": iso(f.resolved_at)}
    if full:
        out.update({"aliases": f.aliases, "fixed_versions": f.fixed_versions, "evidence": f.evidence, "purl": f.purl,
                    "status_reason": f.status_reason, "first_seen_scan": f.first_seen_scan,
                    "last_seen_scan": f.last_seen_scan})
    return out


def _findings_query(db: Session, user: User, project_id=None, target_id=None, severity=None, status=None, kev=None,
                    q=None, assignee=None, ecosystem=None, has_fix=None, since_days=None, epss_min=None,
                    target_kind=None, org_id=None):
    from sqlalchemy import String, cast, or_
    qry = (db.query(Finding).join(Project, Project.id == Finding.project_id)
           .join(Target, Target.id == Finding.target_id).join(Organization, Organization.id == Project.organization_id))
    if (scope := org_scope(user)) is not None:
        qry = qry.filter(Project.organization_id == scope)
    if tp := token_project(user):
        qry = qry.filter(Project.id == tp)
    if org_id:
        qry = qry.filter(Project.organization_id == org_id)
    if project_id:
        qry = qry.filter(Finding.project_id == project_id)
    if target_id:
        qry = qry.filter(Finding.target_id == target_id)
    if severity:
        qry = qry.filter(Finding.severity.in_(severity.upper().split(",")))
    if status:
        qry = qry.filter(Finding.status.in_(status.split(",")))
    if kev is not None:
        qry = qry.filter(Finding.kev == kev)
    if assignee == "me":
        qry = qry.filter(Finding.assignee_id == user.id)
    elif assignee == "none":
        qry = qry.filter(Finding.assignee_id.is_(None))
    elif assignee and assignee.isdigit():
        qry = qry.filter(Finding.assignee_id == int(assignee))
    if ecosystem:
        qry = qry.filter(Finding.ecosystem.in_(ecosystem.split(",")))
    if has_fix is True:
        qry = qry.filter(Finding.upgrade_to != "")
    elif has_fix is False:
        qry = qry.filter(Finding.upgrade_to == "")
    if since_days:
        qry = qry.filter(Finding.first_seen_at >= datetime.now(timezone.utc) - timedelta(days=since_days))
    if epss_min is not None:
        qry = qry.filter(Finding.epss >= epss_min)
    if target_kind in ("web", "upload"):
        qry = qry.filter(Target.kind == target_kind)
    for word in (q or "").split()[:8]:
        like = "%" + word.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        qry = qry.filter(or_(*(c.ilike(like, escape="\\") for c in (
            Target.name, Target.url, Project.name, Organization.name, Finding.component, Finding.version,
            Finding.vuln_id, Finding.summary, Finding.purl, cast(Finding.aliases, String)))))
    return qry


def _sorted_findings(qry) -> list:
    rank = {s: i for i, s in enumerate(SEVERITIES)}
    rows = qry.order_by(Finding.malicious.desc(), Finding.kev.desc(), Finding.cvss.desc().nullslast(), Finding.id).all()
    rows.sort(key=lambda f: (not f.malicious, not f.kev, rank.get(f.severity, 9), -(f.epss or 0)))
    return rows


class _FindingFilters:
    def __init__(self, project_id: int | None = None, target_id: int | None = None, org_id: int | None = None,
                 severity: str | None = None, status: str | None = None, kev: bool | None = None,
                 q: str | None = Query(None, max_length=200), assignee: str | None = None,
                 ecosystem: str | None = None, has_fix: bool | None = None,
                 since_days: int | None = Query(None, ge=1, le=3650), epss_min: float | None = Query(None, ge=0, le=1),
                 target_kind: str | None = None):
        self.kw = dict(project_id=project_id, target_id=target_id, org_id=org_id, severity=severity, status=status,
                       kev=kev, q=q, assignee=assignee, ecosystem=ecosystem, has_fix=has_fix, since_days=since_days,
                       epss_min=epss_min, target_kind=target_kind)


@router.get("/findings")
def list_findings(flt: _FindingFilters = Depends(), evidence: bool = False,
                  page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=500),
                  user: User = Depends(current_user), db: Session = Depends(get_db)):
    qry = _findings_query(db, user, **flt.kw)
    total = qry.count()
    items = _sorted_findings(qry)[(page - 1) * size: page * size]
    tids = {f.target_id for f in items}
    names = {t.id: (t.name, t.url, t.kind, t.project.name) for t in db.query(Target).filter(Target.id.in_(tids))} if tids else {}

    def row(f):
        out = finding_out(f)
        tn = names.get(f.target_id)
        if tn:
            out.update({"target": tn[0], "target_url": tn[1], "target_kind": tn[2], "project": tn[3]})
        if evidence:
            out["locations"] = [{"location": e.get("location", ""), "line": e.get("line"), "snippet": e.get("snippet", ""),
                                 "method": e.get("method", "")} for e in (f.evidence or [])[:3]]
        return out
    out = {"total": total, "page": page, "size": size, "items": [row(f) for f in items]}
    if total == 0 and flt.kw.get("q"):
        from sqlalchemy import or_
        tq = db.query(Target).join(Project).join(Organization)
        if (scope := org_scope(user)) is not None:
            tq = tq.filter(Project.organization_id == scope)
        if tp := token_project(user):
            tq = tq.filter(Project.id == tp)
        for word in flt.kw["q"].split()[:8]:
            like = "%" + word.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            tq = tq.filter(or_(Target.name.ilike(like, escape="\\"), Target.url.ilike(like, escape="\\"),
                               Project.name.ilike(like, escape="\\")))
        out["matched_targets"] = [{"id": t.id, "name": t.name, "url": t.url, "project": t.project.name,
                                   "open": sum(_open_counts(db, target_id=t.id).values())} for t in tq.limit(10)]
    return out


@router.get("/findings/facets")
def findings_facets(user: User = Depends(current_user), db: Session = Depends(get_db)):
    qry = _findings_query(db, user)
    return {"ecosystems": sorted({e for (e,) in qry.with_entities(Finding.ecosystem).distinct() if e})}


@router.get("/findings.csv")
def findings_csv(request: Request, flt: _FindingFilters = Depends(), user: User = Depends(current_user),
                 db: Session = Depends(get_db)):
    import csv
    import io
    from ..safeio import csv_cell
    rows = _sorted_findings(_findings_query(db, user, **flt.kw))[:50_000]
    tmap = {t.id: t for t in db.query(Target).filter(Target.id.in_({f.target_id for f in rows}))} if rows else {}
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "severity", "vuln_id", "cves", "component", "version", "ecosystem", "upgrade_to", "epss", "kev",
                "status", "project", "target", "target_url", "first_seen", "last_seen"])
    for f in rows:
        t = tmap.get(f.target_id)
        w.writerow([f.id, f.severity, csv_cell(f.vuln_id), csv_cell(" ".join(a for a in f.aliases if a.startswith("CVE-"))),
                    csv_cell(f.component), csv_cell(f.version), csv_cell(f.ecosystem), csv_cell(f.upgrade_to),
                    f.epss if f.epss is not None else "", int(f.kev), f.status,
                    csv_cell(t.project.name if t else ""), csv_cell(t.name if t else ""), csv_cell(t.url if t else ""),
                    iso(f.first_seen_at), iso(f.last_seen_at)])
    audit(db, user, "findings.export", "finding", "", f"{len(rows)} satır", client_ip(request))
    return Response("\ufeff" + buf.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="bulgular.csv"'})


_LEGACY = [
    ("status", re.compile(r"^Durum: (?P<from>\w+) → (?P<to>\w+)\.\s*(?P<reason>.*)$", re.S)),
    ("approval_request", re.compile(r"^Onay istendi: (?P<from>\w+) → (?P<to>\w+)\.\s*(?P<reason>.*)$", re.S)),
    ("approval_ok", re.compile(r"^Onaylandı: (?P<from>\w+) → (?P<to>\w+)\.\s*(?P<reason>.*?)(?: — (?P<note>.*))?$", re.S)),
    ("approval_no", re.compile(r"^Reddedildi \((?P<to>\w+)\): (?P<note>.*)$", re.S)),
    ("shared", re.compile(r"^Paylaşıldı: (?P<to>[^—]+?)(?: — (?P<message>.*))?$", re.S)),
    ("assigned", re.compile(r"^Atandı: (?P<to>\S+?)(?: \(son tarih (?P<due>[\d-]+)\))?(?:\. (?P<note>.*))?$", re.S)),
    ("jira", re.compile(r"^Jira kaydı oluşturuldu: (?P<key>\S+)$")),
]


def _comment_kind(c: Comment) -> dict:
    if c.kind:
        return {"kind": c.kind, "meta": c.meta or {}}
    for kind, rx in _LEGACY:
        if m := rx.match(c.text or ""):
            meta = {k: v for k, v in m.groupdict().items() if v}
            if kind == "approval_ok":
                return {"kind": "approval_decided", "meta": {**meta, "approved": True}}
            if kind == "approval_no":
                return {"kind": "approval_decided", "meta": {**meta, "approved": False}}
            if kind == "shared":
                meta["to"] = [x.strip() for x in meta["to"].split(",")]
            return {"kind": kind, "meta": meta}
    return {"kind": "comment", "meta": {}}


@router.get("/findings/{finding_id}")
def read_finding(finding_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    f = get_finding(db, user, finding_id)
    out = finding_out(f, full=True)
    out["target"] = db.get(Target, f.target_id).name
    out["comments"] = [{"id": c.id, "text": c.text, **_comment_kind(c),
                        "user": c.user.email if c.user else "", "user_name": c.user.name if c.user else "",
                        "at": iso(c.created_at)}
                       for c in db.query(Comment).filter_by(finding_id=f.id).order_by(Comment.id)]
    return out


class FindingPatch(BaseModel):
    status: str
    reason: str = ""


@router.patch("/findings/{finding_id}")
def update_finding(finding_id: int, body: FindingPatch, request: Request, user: User = Depends(current_user),
                   db: Session = Depends(get_db)):
    f = get_finding(db, user, finding_id)
    if body.status not in FINDING_STATUSES or body.status == "fixed":
        raise HTTPException(400, "Geçersiz durum (\"fixed\" yalnızca tarama ile atanır)")
    if body.status in ("accepted_risk", "false_positive", "not_affected") and not body.reason.strip():
        raise HTTPException(400, "Bu durum için gerekçe zorunlu")
    from . import collab
    from .models import ApprovalRequest
    org_id = collab.finding_org(db, f)
    if collab.needs_approval(db, user, org_id, body.status):
        if db.query(ApprovalRequest).filter_by(finding_id=f.id, state="pending").first():
            raise HTTPException(409, "Bu bulgu için zaten bekleyen bir onay talebi var")
        req = ApprovalRequest(finding_id=f.id, requested_by=user.id, status=body.status, from_status=f.status,
                              reason=body.reason.strip(),
                              approver_ids=collab.approvers_for(db, user, org_id))
        db.add(req)
        db.add(Comment(finding_id=f.id, user_id=user.id, kind="approval_request",
                       meta={"from": f.status, "to": body.status, "reason": body.reason.strip()},
                       text=f"Onay istendi: {f.status} → {body.status}. {body.reason}".strip()))
        db.flush()
        collab.notify(db, req.approver_ids, "approval_requested",
                      {**collab.finding_params(f), "status": body.status, "reason": body.reason[:300]},
                      "/approvals", user)
        db.commit()
        audit(db, user, "finding.approval_request", "finding", f.id, f"{body.status}: {body.reason[:300]}",
              client_ip(request))
        return {**finding_out(f, full=True), "approval": approval_out(db, req)}
    old = f.status
    f.status, f.status_reason, f.status_by = body.status, body.reason.strip(), user.id
    db.add(Comment(finding_id=f.id, user_id=user.id, kind="status",
                   meta={"from": old, "to": body.status, "reason": body.reason.strip()},
                   text=f"Durum: {old} → {body.status}. {body.reason}".strip()))
    db.commit()
    audit(db, user, "finding.status", "finding", f.id, f"{old}->{body.status}: {body.reason[:300]}", client_ip(request))
    return finding_out(f, full=True)


class CommentIn(BaseModel):
    text: str = Field(min_length=1, max_length=5000)


@router.post("/findings/{finding_id}/comments")
def add_comment(finding_id: int, body: CommentIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    from . import collab
    f = get_finding(db, user, finding_id)
    c = Comment(finding_id=f.id, user_id=user.id, text=body.text, kind="comment")
    db.add(c)
    collab.notify(db, collab.mentions(db, body.text, collab.finding_org(db, f)), "mentioned",
                  {**collab.finding_params(f), "text": body.text[:300]}, f"/findings?open={f.id}", user)
    db.commit()
    return {"id": c.id, "text": c.text, "user": user.email, "at": iso(c.created_at)}


@router.get("/dashboard")
def dashboard(user: User = Depends(current_user), db: Session = Depends(get_db)):
    scope = org_scope(user)

    def scoped(q, model_project_col):
        return q.filter(model_project_col.in_(db.query(Project.id).filter(Project.organization_id == scope))) \
            if scope is not None else q

    open_q = scoped(db.query(Finding).filter(Finding.status.in_(("open", "in_progress"))), Finding.project_id)
    sev = dict(open_q.with_entities(Finding.severity, func.count(Finding.id)).group_by(Finding.severity).all())
    kev = open_q.filter(Finding.kev.is_(True)).count()
    top = open_q.with_entities(Finding.component, Finding.version, func.count(Finding.id).label("n"),
                               func.max(Finding.cvss)).group_by(Finding.component, Finding.version) \
        .order_by(func.count(Finding.id).desc()).limit(10).all()
    status = dict(scoped(db.query(Finding.status, func.count(Finding.id)), Finding.project_id)
                  .group_by(Finding.status).all())
    projects = scoped(db.query(Project), Project.id).count()
    targets = scoped(db.query(Target), Target.project_id).count()
    recent = scoped(db.query(Scan).join(Target), Target.project_id).order_by(Scan.id.desc()).limit(8).all()
    return {"open_by_severity": {s: sev.get(s, 0) for s in SEVERITIES}, "open_kev": kev, "status": status,
            "projects": projects, "targets": targets,
            "top_components": [{"component": c, "version": v, "findings": n, "max_cvss": m} for c, v, n, m in top],
            "recent_scans": [scan_out(s) for s in recent]}


@router.get("/settings")
def read_settings(_: User = Depends(require("admin")), db: Session = Depends(get_db)):
    return settings_store.public_view(db)


@router.put("/settings")
def write_settings(body: dict, request: Request, admin: User = Depends(require("admin")), db: Session = Depends(get_db)):
    changed, clean, errors = [], {}, {}
    clear = body.pop("_clear", []) if isinstance(body.get("_clear", []), list) else []
    for k, v in body.items():
        if k not in settings_store.SCHEMA:
            raise HTTPException(400, f"Bilinmeyen ayar: {k}")
        try:
            clean[k] = settings_store.validate(k, v)
        except settings_store.SettingError as ex:
            errors[k] = str(ex)
            continue
        if k == "vulndb_path" and clean[k] and not Path(clean[k]).expanduser().parent.exists():
            errors[k] = "Veritabanı klasörü bulunamadı"
    if errors:
        raise HTTPException(400, detail={"code": "invalid_settings", "fields": errors,
                                         "message": "Bazı ayarlar geçersiz: " + ", ".join(errors)})
    for k, v in clean.items():
        if settings_store.SCHEMA[k][1] and v == "" and k not in clear:
            continue
        settings_store.set_value(db, k, v)
        changed.append(k)
    audit(db, admin, "settings.update", "settings", detail=", ".join(changed), ip=client_ip(request))
    return settings_store.public_view(db)


@router.post("/settings/smtp/test")
def smtp_test(request: Request, admin: User = Depends(require("admin")), db: Session = Depends(get_db)):
    from . import notify
    try:
        notify._send_email(db, [admin.email], f"{PRODUCT_NAME} — SMTP deneme",
                           f"Bu bir deneme iletisidir. {PRODUCT_NAME} e-posta ayarları çalışıyor.")
    except Exception as ex:
        import smtplib
        from .errors import human_text
        if isinstance(ex, smtplib.SMTPAuthenticationError):
            raise HTTPException(400, "Kimlik doğrulama reddedildi (kullanıcı adı / parola)")
        raise HTTPException(400, str(ex) if isinstance(ex, notify.NotifyError) else human_text(ex))
    audit(db, admin, "settings.smtp_test", "settings", detail=admin.email, ip=client_ip(request))
    return {"ok": True, "to": admin.email}


@router.post("/settings/oidc/test")
def oidc_test(admin: User = Depends(require("admin")), db: Session = Depends(get_db)):
    if not settings_store.get(db, "oidc_issuer"):
        raise HTTPException(400, "Önce Issuer adresini girin")
    try:
        _oidc._CACHE.clear()
        doc = _oidc.discovery(db)
        keys = _oidc._jwks(doc["jwks_uri"], refresh=True).get("keys", [])
    except Exception as ex:
        from .errors import human_text
        raise HTTPException(400, str(ex) if isinstance(ex, _oidc.OIDCError) else human_text(ex))
    return {"ok": True, "issuer": doc.get("issuer"), "authorization_endpoint": doc.get("authorization_endpoint"),
            "keys": len(keys), "client_configured": bool(settings_store.get(db, "oidc_client_id")),
            "redirect_uri": f"{(settings_store.get(db, 'public_url') or 'https://<arayüz-adresi>').rstrip('/')}/api/auth/oidc/callback"}


_STATS_CACHE: dict = {}


@router.get("/vulndb")
def vulndb_status(_: User = Depends(require("admin", "analyst")), db: Session = Depends(get_db)):
    from .pipeline import vulndb
    v = vulndb(db)
    try:
        sig = (str(v.path), Path(v.path).stat().st_mtime)
    except OSError:
        sig = None
    if sig is None or _STATS_CACHE.get("sig") != sig:
        _STATS_CACHE.update(sig=sig, stats=v.stats())
    st = _STATS_CACHE["stats"]
    meta = {k: m.get("updated") for k, m in v.meta().items() if not k.startswith("file:")}
    last = db.query(Job).filter_by(kind="db_update").order_by(Job.id.desc()).first()
    return {"path": str(v.path), "stats": st, "updated": meta, "last_job": job_out(last) if last else None}


class DbUpdateIn(BaseModel):
    from_dir: str | None = None
    no_nvd: bool = False


@router.post("/vulndb/update")
def vulndb_update(body: DbUpdateIn, request: Request, admin: User = Depends(require("admin")),
                  db: Session = Depends(get_db)):
    if body.from_dir and not Path(body.from_dir).is_dir():
        raise HTTPException(400, "Klasör bulunamadı (sunucudaki yol olmalı)")
    if db.query(Job).filter(Job.kind == "db_update", Job.status.in_(("queued", "running"))).first():
        raise HTTPException(409, "Zaten çalışan bir güncelleme var")
    job = Job(kind="db_update", params=body.model_dump(), created_by=admin.id)
    db.add(job)
    db.commit()
    audit(db, admin, "vulndb.update", "job", job.id, json.dumps(body.model_dump()), client_ip(request))
    return job_out(job)


def _audit_query(db: Session, user: str = "", action: str = "", object_type: str = "", ip: str = "", q: str = "",
                 date_from: datetime | None = None, date_to: datetime | None = None, user_id: int | None = None):
    qry = db.query(AuditLog)
    if user_id:
        qry = qry.filter(AuditLog.user_id == user_id)
    if user:
        qry = qry.filter(AuditLog.user_email.ilike(f"%{_like(user)}%", escape="\\"))
    if action:
        acts = [a.strip() for a in action.split(",") if a.strip()][:20]
        from sqlalchemy import or_
        qry = qry.filter(or_(*[(AuditLog.action == a) | AuditLog.action.like(f"{_like(a)}.%", escape="\\") for a in acts]))
    if object_type:
        qry = qry.filter(AuditLog.object_type == object_type)
    if ip:
        qry = qry.filter(AuditLog.ip.like(f"{_like(ip)}%", escape="\\"))
    if q:
        qry = qry.filter(AuditLog.detail.ilike(f"%{_like(q)}%", escape="\\"))
    if date_from:
        qry = qry.filter(AuditLog.at >= date_from)
    if date_to:
        qry = qry.filter(AuditLog.at <= date_to)
    return qry.order_by(AuditLog.id.desc())


def _like(s: str) -> str:
    return s[:200].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _audit_row(a: AuditLog) -> dict:
    return {"id": a.id, "at": iso(a.at), "user": a.user_email, "user_id": a.user_id, "action": a.action,
            "object_type": a.object_type, "object_id": a.object_id,
            "object": f"{a.object_type}:{a.object_id}" if a.object_type else "", "detail": a.detail, "ip": a.ip}


@router.get("/audit")
def read_audit(page: int = Query(1, ge=1), size: int = Query(100, le=500), user: str = "", action: str = "",
               object_type: str = "", ip: str = "", q: str = "", date_from: datetime | None = None,
               date_to: datetime | None = None, _: User = Depends(require("admin")), db: Session = Depends(get_db)):
    qry = _audit_query(db, user, action, object_type, ip, q, date_from, date_to)
    return {"total": qry.count(), "items": [_audit_row(a) for a in qry.offset((page - 1) * size).limit(size)]}


@router.get("/audit/facets")
def audit_facets(_: User = Depends(require("admin")), db: Session = Depends(get_db)):
    actions = [r[0] for r in db.query(AuditLog.action).distinct().order_by(AuditLog.action).limit(500)]
    types = [r[0] for r in db.query(AuditLog.object_type).distinct().order_by(AuditLog.object_type).limit(200) if r[0]]
    users = [r[0] for r in db.query(AuditLog.user_email).distinct().order_by(AuditLog.user_email).limit(1000) if r[0]]
    return {"actions": actions, "object_types": types, "users": users}


@router.get("/audit.csv")
def audit_csv(request: Request, user: str = "", action: str = "", object_type: str = "", ip: str = "", q: str = "",
              date_from: datetime | None = None, date_to: datetime | None = None,
              admin: User = Depends(require("admin")), db: Session = Depends(get_db)):
    import csv
    import io
    from ..safeio import csv_cell
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "at", "user", "action", "object_type", "object_id", "detail", "ip"])
    for a in _audit_query(db, user, action, object_type, ip, q, date_from, date_to).limit(100_000):
        w.writerow([a.id, iso(a.at), csv_cell(a.user_email), csv_cell(a.action), csv_cell(a.object_type),
                    csv_cell(a.object_id), csv_cell(a.detail), csv_cell(a.ip)])
    audit(db, admin, "audit.export", "audit", "", ip=client_ip(request))
    return Response("\ufeff" + buf.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="audit.csv"'})


@router.get("/scans/{scan_id}/changes")
def scan_changes(scan_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    s = get_scan(db, user, scan_id)
    base = db.query(Finding).filter(Finding.target_id == s.target_id)
    prev = db.query(Scan).join(Job).filter(Scan.target_id == s.target_id, Scan.id < s.id, Job.status == "done") \
        .order_by(Scan.id.desc()).first()
    return {"previous_scan": prev.id if prev else None,
            "new": [finding_out(f) for f in base.filter(Finding.first_seen_scan == s.id)],
            "fixed": [finding_out(f) for f in base.filter(Finding.resolved_scan == s.id)],
            "reopened": [finding_out(f) for f in base.filter(Finding.reopened_scan == s.id)]}


from . import scheduler as _sched
from .models import NotificationChannel, Schedule


class ScheduleIn(BaseModel):
    kind: str = "scan"
    target_id: int | None = None
    cron: str
    enabled: bool = True


class SchedulePatch(BaseModel):
    cron: str | None = None
    enabled: bool | None = None


def schedule_out(s: Schedule) -> dict:
    return {"id": s.id, "kind": s.kind, "target_id": s.target_id, "target": s.target.name if s.target else None,
            "project_id": s.target.project_id if s.target else None, "cron": s.cron, "enabled": s.enabled,
            "next_run_at": iso(s.next_run_at), "last_run_at": iso(s.last_run_at), "last_job_id": s.last_job_id}


def _schedule_access(db: Session, user: User, s_kind: str, target_id: int | None):
    if s_kind == "db_update":
        if user.role != "admin":
            raise HTTPException(403, "Bu işlem için yetkiniz yok")
    elif s_kind == "scan":
        if target_id is None:
            raise HTTPException(400, "Hedef seçilmeli")
        get_target(db, user, target_id)
    else:
        raise HTTPException(400, "Geçersiz zamanlama türü")


def _validate_cron(db: Session, cron: str):
    try:
        return _sched.validate(cron, _sched.tz(db))
    except ValueError as ex:
        raise HTTPException(400, str(ex))


@router.get("/schedules/preview")
def schedule_preview(cron: str, _: User = Depends(current_user), db: Session = Depends(get_db)):
    runs = _validate_cron(db, cron)
    zone = _sched.tz(db)
    return {"timezone": str(zone), "next": [r.astimezone(zone).isoformat() for r in runs[:5]]}


@router.get("/schedules")
def list_schedules(target_id: int | None = None, kind: str | None = None, project_id: int | None = None,
                   user: User = Depends(current_user), db: Session = Depends(get_db)):
    q = db.query(Schedule).order_by(Schedule.id)
    if project_id:
        get_project(db, user, project_id)
        q = q.join(Target, Target.id == Schedule.target_id).filter(Target.project_id == project_id)
    if target_id:
        get_target(db, user, target_id)
        q = q.filter(Schedule.target_id == target_id)
    if kind:
        q = q.filter(Schedule.kind == kind)
    out = []
    scope = org_scope(user)
    for s in q:
        if s.kind == "db_update" and user.role == "customer":
            continue
        if scope is not None and s.target and s.target.project.organization_id != scope:
            continue
        out.append(schedule_out(s))
    return out


@router.post("/schedules")
def create_schedule(body: ScheduleIn, request: Request, user: User = Depends(current_user),
                    db: Session = Depends(get_db)):
    _schedule_access(db, user, body.kind, body.target_id)
    runs = _validate_cron(db, body.cron)
    s = Schedule(kind=body.kind, target_id=body.target_id if body.kind == "scan" else None, cron=body.cron.strip(),
                 enabled=body.enabled, next_run_at=runs[0] if body.enabled else None, created_by=user.id)
    db.add(s)
    db.commit()
    audit(db, user, "schedule.create", "schedule", s.id, f"{s.kind} {s.cron} hedef={s.target_id}", client_ip(request))
    return schedule_out(s)


class BulkScheduleIn(BaseModel):
    cron: str = Field(max_length=100)
    target_kind: str = Field("web", pattern="^(web|upload|all)$")
    replace: bool = False


@router.post("/projects/{project_id}/schedules")
def bulk_schedule(project_id: int, body: BulkScheduleIn, request: Request, user: User = Depends(current_user),
                  db: Session = Depends(get_db)):
    p = get_project(db, user, project_id)
    runs = _validate_cron(db, body.cron)
    cron = body.cron.strip()
    targets = [t for t in p.targets if body.target_kind == "all" or t.kind == body.target_kind]
    created = skipped = removed = 0
    for t in targets:
        existing = db.query(Schedule).filter_by(kind="scan", target_id=t.id).all()
        if any(e.cron == cron for e in existing):
            skipped += 1
            continue
        if body.replace:
            for e in existing:
                db.delete(e)
                removed += 1
        db.add(Schedule(kind="scan", target_id=t.id, cron=cron, enabled=True, next_run_at=runs[0], created_by=user.id))
        created += 1
    db.commit()
    audit(db, user, "schedule.bulk", "project", p.id, f"{cron} · {created} yeni, {skipped} zaten vardı, {removed} değişti",
          client_ip(request))
    return {"created": created, "skipped": skipped, "replaced": removed}


@router.delete("/projects/{project_id}/schedules")
def bulk_unschedule(project_id: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    p = get_project(db, user, project_id)
    ids = [t.id for t in p.targets]
    n = db.query(Schedule).filter(Schedule.kind == "scan", Schedule.target_id.in_(ids)).delete(synchronize_session=False) if ids else 0
    db.commit()
    audit(db, user, "schedule.bulk_delete", "project", p.id, f"{n} zamanlama silindi", client_ip(request))
    return {"deleted": n}


@router.get("/trends")
def trends(project_id: int | None = None, target_id: int | None = None,
           bucket: str = Query("day", pattern="^(hour|day|week)$"), periods: int = Query(14, ge=2, le=90),
           user: User = Depends(current_user), db: Session = Depends(get_db)):
    zone = _sched.tz(db)
    step = {"hour": timedelta(hours=1), "day": timedelta(days=1), "week": timedelta(weeks=1)}[bucket]
    now = datetime.now(timezone.utc).astimezone(zone)
    cur = now.replace(minute=0, second=0, microsecond=0)
    if bucket != "hour":
        cur = cur.replace(hour=0)
    if bucket == "week":
        cur -= timedelta(days=cur.weekday())
    starts = [cur - step * i for i in range(periods - 1, -1, -1)]
    q = db.query(Scan).join(Job).join(Target).join(Project).filter(Job.status == "done")
    if (scope := org_scope(user)) is not None:
        q = q.filter(Project.organization_id == scope)
    if tp := token_project(user):
        q = q.filter(Project.id == tp)
    if project_id:
        get_project(db, user, project_id)
        q = q.filter(Target.project_id == project_id)
    if target_id:
        get_target(db, user, target_id)
        q = q.filter(Scan.target_id == target_id)
    scans = q.order_by(Job.finished_at, Scan.id).limit(20000).all()
    latest: dict[int, dict] = {}
    out, i = [], 0

    def when(sc):
        d = sc.job.finished_at or sc.created_at
        return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).astimezone(zone)
    for b0 in starts:
        b1 = b0 + step
        while i < len(scans) and when(scans[i]) < b0:
            latest[scans[i].target_id] = scans[i].summary or {}
            i += 1
        n = new = fixed = 0
        while i < len(scans) and when(scans[i]) < b1:
            sm = scans[i].summary or {}
            latest[scans[i].target_id] = sm
            n += 1
            new += int(sm.get("new", 0) or 0)
            fixed += int(sm.get("fixed", 0) or 0)
            i += 1
        out.append({"start": b0.isoformat(), "scans": n, "new": new, "fixed": fixed,
                    "open": sum(int(v.get("findings", 0) or 0) for v in latest.values()),
                    "components": sum(int(v.get("components", 0) or 0) for v in latest.values()),
                    "targets": len(latest)})
    for a, b in zip([None] + out[:-1], out):
        b["delta_open"] = b["open"] - a["open"] if a else 0
    return {"bucket": bucket, "timezone": str(zone), "items": out}


def _get_schedule(db: Session, user: User, sid: int) -> Schedule:
    s = db.get(Schedule, sid)
    if s is None:
        raise HTTPException(404, "Zamanlama bulunamadı")
    try:
        _schedule_access(db, user, s.kind, s.target_id)
    except HTTPException as ex:
        raise HTTPException(404, "Zamanlama bulunamadı") from ex
    return s


@router.patch("/schedules/{sid}")
def update_schedule(sid: int, body: SchedulePatch, request: Request, user: User = Depends(current_user),
                    db: Session = Depends(get_db)):
    s = _get_schedule(db, user, sid)
    if body.cron is not None:
        _validate_cron(db, body.cron)
        s.cron = body.cron.strip()
        s.created_by = user.id
    if body.enabled is not None:
        s.enabled = body.enabled
    s.next_run_at = _sched.next_runs(s.cron, _sched.tz(db), 1)[0] if s.enabled else None
    db.commit()
    audit(db, user, "schedule.update", "schedule", s.id, f"{s.cron} enabled={s.enabled}", client_ip(request))
    return schedule_out(s)


@router.delete("/schedules/{sid}")
def delete_schedule(sid: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    s = _get_schedule(db, user, sid)
    db.delete(s)
    db.commit()
    audit(db, user, "schedule.delete", "schedule", sid, ip=client_ip(request))
    return {"ok": True}


from . import notify as _notify


class ChannelIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    kind: str
    config: dict = {}
    events: list[str] = ["scan_done", "new_findings", "kev", "scan_failed"]
    min_severity: str = "HIGH"
    organization_id: int | None = None
    enabled: bool = True


class ChannelPatch(BaseModel):
    name: str | None = None
    config: dict | None = None
    events: list[str] | None = None
    min_severity: str | None = None
    organization_id: int | None = None
    enabled: bool | None = None


def channel_out(c: NotificationChannel) -> dict:
    return {"id": c.id, "name": c.name, "kind": c.kind, "config": _notify.masked(c), "events": c.events,
            "min_severity": c.min_severity, "organization_id": c.organization_id, "enabled": c.enabled,
            "last_status": c.last_status, "last_sent_at": iso(c.last_sent_at)}


def _check_channel_fields(db: Session, events, sev, org_id):
    from .models import NOTIFY_EVENTS
    if events is not None and any(e not in NOTIFY_EVENTS for e in events):
        raise HTTPException(400, "Geçersiz olay")
    if sev is not None and sev not in SEVERITIES:
        raise HTTPException(400, "Geçersiz şiddet eşiği")
    if org_id and db.get(Organization, org_id) is None:
        raise HTTPException(400, "Organizasyon bulunamadı")


@router.get("/notifications/meta")
def notifications_meta(_: User = Depends(require("admin"))):
    return {"kinds": list(_notify.KINDS), "events": _notify.EVENT_LABEL}


@router.get("/notifications")
def list_channels(_: User = Depends(require("admin")), db: Session = Depends(get_db)):
    return [channel_out(c) for c in db.query(NotificationChannel).order_by(NotificationChannel.name)]


@router.post("/notifications")
def create_channel(body: ChannelIn, request: Request, admin: User = Depends(require("admin")),
                   db: Session = Depends(get_db)):
    _check_channel_fields(db, body.events, body.min_severity, body.organization_id)
    try:
        cfg = _notify.validate_config(body.kind, body.config)
    except _notify.NotifyError as ex:
        raise HTTPException(400, str(ex))
    c = NotificationChannel(name=body.name, kind=body.kind, events=body.events, min_severity=body.min_severity,
                            organization_id=body.organization_id, enabled=body.enabled)
    _notify.set_config(c, cfg)
    db.add(c)
    db.commit()
    audit(db, admin, "notification.create", "notification", c.id, f"{c.kind} {c.name}", client_ip(request))
    return channel_out(c)


def _get_channel(db: Session, cid: int) -> NotificationChannel:
    c = db.get(NotificationChannel, cid)
    if c is None:
        raise HTTPException(404, "Kanal bulunamadı")
    return c


@router.patch("/notifications/{cid}")
def update_channel(cid: int, body: ChannelPatch, request: Request, admin: User = Depends(require("admin")),
                   db: Session = Depends(get_db)):
    c = _get_channel(db, cid)
    _check_channel_fields(db, body.events, body.min_severity, body.organization_id)
    if body.config:
        try:
            _notify.set_config(c, _notify.validate_config(c.kind, body.config))
        except _notify.NotifyError as ex:
            raise HTTPException(400, str(ex))
    for k in ("name", "events", "min_severity", "enabled"):
        v = getattr(body, k)
        if v is not None:
            setattr(c, k, v)
    if "organization_id" in body.model_fields_set:
        c.organization_id = body.organization_id or None
    db.commit()
    audit(db, admin, "notification.update", "notification", c.id, c.name, client_ip(request))
    return channel_out(c)


@router.delete("/notifications/{cid}")
def delete_channel(cid: int, request: Request, admin: User = Depends(require("admin")), db: Session = Depends(get_db)):
    c = _get_channel(db, cid)
    db.delete(c)
    db.commit()
    audit(db, admin, "notification.delete", "notification", cid, c.name, client_ip(request))
    return {"ok": True}


@router.post("/notifications/{cid}/test")
def test_channel(cid: int, _: User = Depends(require("admin")), db: Session = Depends(get_db)):
    c = _get_channel(db, cid)
    msg = _notify.build_simple_message(db, "test", f"{PRODUCT_NAME} test bildirimi",
                                       [f"'{c.name}' kanalı doğru yapılandırılmış."], "/")
    try:
        _notify.send(db, c, msg)
    except Exception as ex:
        c.last_status, c.last_sent_at = _notify.safe_error(ex), datetime.now(timezone.utc)
        db.commit()
        raise HTTPException(400, c.last_status)
    c.last_status, c.last_sent_at = "ok", datetime.now(timezone.utc)
    db.commit()
    return {"ok": True}


from . import jira as _jira


class JiraInstanceIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    url: str = Field(max_length=500)
    auth: str = Field("cloud", pattern="^(cloud|server)$")
    user: str = Field("", max_length=200)
    token: str | None = Field(None, max_length=2000)
    project_key: str = Field("", max_length=50)
    issue_type: str = Field("Bug", max_length=50)
    labels: str = Field("", max_length=300)
    auto_min_severity: str = Field("", pattern="^(|CRITICAL|HIGH|MEDIUM|LOW)$")
    comment_on_fix: bool = True
    enabled: bool = True
    roles: list[str] = Field(default_factory=lambda: ["admin", "analyst"])
    user_ids: list[int] = Field(default_factory=list, max_length=500)
    org_ids: list[int] = Field(default_factory=list, max_length=500)


def _jira_in(db: Session, body: JiraInstanceIn, inst):
    from .models import JiraInstance
    from .security import encrypt
    name = body.name.strip()
    if any(c in name + body.user + body.labels + body.issue_type for c in "\r\n\0"):
        raise HTTPException(400, "Alanlar tek satır olmalı")
    u = urlparse(body.url.strip())
    if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password:
        raise HTTPException(400, "Geçerli bir http(s) Jira adresi girin")
    if body.project_key and not re.fullmatch(r"[A-Z][A-Z0-9_]{0,49}", body.project_key.strip().upper()):
        raise HTTPException(400, "Jira proje anahtarı büyük harf ve rakamlardan oluşmalı (ör. SEC)")
    if not set(body.roles) <= set(ROLES):
        raise HTTPException(400, "Geçersiz rol")
    clash = db.query(JiraInstance).filter(JiraInstance.name == name, JiraInstance.id != (inst.id if inst else 0)).first()
    if clash:
        raise HTTPException(400, "Bu adla bir Jira bağlantısı zaten var")
    known_users = {i for (i,) in db.query(User.id).filter(User.id.in_(body.user_ids))} if body.user_ids else set()
    known_orgs = {i for (i,) in db.query(Organization.id).filter(Organization.id.in_(body.org_ids))} if body.org_ids else set()
    inst = inst or JiraInstance()
    inst.name, inst.url, inst.auth, inst.user = name, body.url.strip().rstrip("/"), body.auth, body.user.strip()
    if body.token is not None and body.token.strip():
        inst.token_enc = encrypt(body.token.strip())
    inst.project_key, inst.issue_type = body.project_key.strip().upper(), body.issue_type.strip() or "Bug"
    inst.labels, inst.auto_min_severity = body.labels.strip(), body.auto_min_severity
    inst.comment_on_fix, inst.enabled = body.comment_on_fix, body.enabled
    inst.roles, inst.user_ids, inst.org_ids = sorted(set(body.roles)), sorted(known_users), sorted(known_orgs)
    return inst


def jira_out(i, admin: bool) -> dict:
    out = {"id": i.id, "name": i.name, "project_key": i.project_key, "ready": _jira.ready(i)}
    if admin:
        out.update({"url": i.url, "auth": i.auth, "user": i.user, "token_set": bool(i.token_enc),
                    "issue_type": i.issue_type, "labels": i.labels, "auto_min_severity": i.auto_min_severity,
                    "comment_on_fix": i.comment_on_fix, "enabled": i.enabled, "roles": i.roles, "user_ids": i.user_ids,
                    "org_ids": i.org_ids})
    return out


@router.get("/jira/instances")
def jira_instances(user: User = Depends(current_user), db: Session = Depends(get_db)):
    if user.role == "admin" and not getattr(user, "via_token", False):
        return [jira_out(i, True) for i in _jira.instances(db, enabled_only=False)]
    return [jira_out(i, False) for i in _jira.usable(db, user)]


@router.post("/jira/instances")
def jira_create(body: JiraInstanceIn, request: Request, user: User = Depends(require("admin")), db: Session = Depends(get_db)):
    inst = _jira_in(db, body, None)
    db.add(inst)
    db.commit()
    audit(db, user, "jira.create", "jira", inst.id, f"{inst.name} {inst.url}", client_ip(request))
    return jira_out(inst, True)


def _jira_get(db: Session, iid: int):
    from .models import JiraInstance
    _jira.migrate_legacy(db)
    inst = db.get(JiraInstance, iid)
    if inst is None:
        raise HTTPException(404, "Jira bağlantısı bulunamadı")
    return inst


@router.put("/jira/instances/{iid}")
def jira_update(iid: int, body: JiraInstanceIn, request: Request, user: User = Depends(require("admin")),
                db: Session = Depends(get_db)):
    inst = _jira_in(db, body, _jira_get(db, iid))
    db.commit()
    audit(db, user, "jira.update", "jira", inst.id, f"{inst.name} roller={inst.roles} kullanıcı={len(inst.user_ids)} "
          f"org={len(inst.org_ids)}", client_ip(request))
    return jira_out(inst, True)


@router.delete("/jira/instances/{iid}")
def jira_delete(iid: int, request: Request, user: User = Depends(require("admin")), db: Session = Depends(get_db)):
    inst = _jira_get(db, iid)
    db.query(Project).filter(Project.jira_instance_id == inst.id).update({Project.jira_instance_id: None})
    name = inst.name
    db.delete(inst)
    db.commit()
    audit(db, user, "jira.delete", "jira", iid, name, client_ip(request))
    return {"ok": True}


class JiraTestIn(BaseModel):
    instance_id: int | None = None


@router.post("/jira/test")
def jira_test(body: JiraTestIn | None = None, user: User = Depends(require("admin")), db: Session = Depends(get_db)):
    ins = _jira.instances(db, enabled_only=False)
    iid = body.instance_id if body else None
    inst = _jira_get(db, iid) if iid else (ins[0] if len(ins) == 1 else None)
    if inst is None:
        raise HTTPException(400, "Test edilecek Jira bağlantısını seçin")
    try:
        return {"ok": True, **_jira.test_connection(inst)}
    except _jira.JiraError as ex:
        raise HTTPException(400, str(ex))


@router.get("/jira/status")
def jira_status(user: User = Depends(current_user), db: Session = Depends(get_db)):
    ok = _jira.usable(db, user)
    return {"configured": bool(ok), "instances": [{"id": i.id, "name": i.name, "project_key": i.project_key} for i in ok]}


class JiraPushIn(BaseModel):
    instance_id: int | None = None


@router.post("/findings/{finding_id}/jira")
def finding_to_jira(finding_id: int, request: Request, body: JiraPushIn | None = None,
                    user: User = Depends(current_user), db: Session = Depends(get_db)):
    f = get_finding(db, user, finding_id)
    existed = bool(f.jira_key)
    try:
        if existed:
            key, url = f.jira_key, f.jira_url or ""
        else:
            inst = _jira.pick(db, user, f, body.instance_id if body else None)
            key, url = _jira.create_issue(db, f, inst)
    except _jira.JiraError as ex:
        raise HTTPException(400, str(ex))
    if not existed:
        db.add(Comment(finding_id=f.id, user_id=user.id, kind="jira", meta={"key": key, "url": f.jira_url, "instance": inst.name},
                       text=f"Jira kaydı oluşturuldu: {key}"))
        db.commit()
        audit(db, user, "finding.jira", "finding", f.id, f"{inst.name}: {key}", client_ip(request))
    return {"key": key, "url": url, "created": not existed}


class BulkJiraIn(BaseModel):
    ids: list[int] = Field(min_length=1, max_length=100)
    instance_id: int | None = None


@router.post("/findings/jira")
def findings_to_jira(body: BulkJiraIn, request: Request, user: User = Depends(current_user),
                     db: Session = Depends(get_db)):
    created, existing, errors = [], [], []
    for fid in body.ids:
        try:
            f = get_finding(db, user, fid)
        except HTTPException:
            errors.append({"id": fid, "error": "bulunamadı"})
            continue
        if f.jira_key:
            existing.append(f.jira_key)
            continue
        try:
            inst = _jira.pick(db, user, f, body.instance_id)
            key, _url = _jira.create_issue(db, f, inst)
            created.append(key)
            db.add(Comment(finding_id=f.id, user_id=user.id, kind="jira", meta={"key": key, "url": f.jira_url, "instance": inst.name},
                           text=f"Jira kaydı oluşturuldu: {key}"))
            db.commit()
        except _jira.JiraError as ex:
            errors.append({"id": fid, "error": str(ex)})
            if "yetkiniz" not in str(ex):
                break
    if created:
        audit(db, user, "finding.jira.bulk", "finding", detail=", ".join(created), ip=client_ip(request))
    return {"created": created, "existing": existing, "errors": errors}


from . import sysinfo as _sys


@router.get("/system")
def system_info(_: User = Depends(require("admin", "analyst")), db: Session = Depends(get_db)):
    info = _sys.collect(db)
    last = db.query(Job).filter_by(kind="selfscan").order_by(Job.id.desc()).first()
    info["selfscan_job"] = job_out(last) if last else None
    from . import maintenance
    info["maintenance"] = maintenance.last_run(db)
    return info


@router.get("/system/selfscan")
def system_selfscan(_: User = Depends(require("admin", "analyst")), db: Session = Depends(get_db)):
    last = db.query(Job).filter_by(kind="selfscan", status="done").order_by(Job.id.desc()).first()
    return (last.params or {}).get("result") if last else None


@router.post("/system/selfscan")
def start_selfscan(request: Request, user: User = Depends(require("admin", "analyst")),
                   db: Session = Depends(get_db)):
    if db.query(Job).filter(Job.kind == "selfscan", Job.status.in_(("queued", "running"))).first():
        raise HTTPException(409, "Öz tarama zaten çalışıyor")
    job = Job(kind="selfscan", params={}, created_by=user.id)
    db.add(job)
    db.commit()
    audit(db, user, "system.selfscan", "job", job.id, ip=client_ip(request))
    return job_out(job)


@router.post("/system/check-latest")
def system_check_latest(request: Request, admin: User = Depends(require("admin")), db: Session = Depends(get_db)):
    audit(db, admin, "system.check_latest", "system", ip=client_ip(request))
    return _sys.check_latest()


from .models import TOKEN_SCOPES, ApiToken


class TokenIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    scopes: list[str] = ["read", "scan"]
    project_id: int | None = None
    expires_days: int | None = Field(default=365, ge=1, le=3650)


def token_out(t: ApiToken) -> dict:
    return {"id": t.id, "name": t.name, "prefix": t.prefix, "scopes": t.scopes, "project_id": t.project_id,
            "project": (_proj_name(t).name if _proj_name(t) else None),
            "owner": t.user.email if t.user else "", "created_at": iso(t.created_at), "expires_at": iso(t.expires_at),
            "last_used_at": iso(t.last_used_at), "last_used_ip": t.last_used_ip, "revoked": t.revoked}


def _proj_name(t: ApiToken):
    from sqlalchemy.orm import object_session
    return object_session(t).get(Project, t.project_id) if t.project_id else None


@router.get("/tokens")
def list_tokens(user: User = Depends(current_user), db: Session = Depends(get_db)):
    q = db.query(ApiToken).order_by(ApiToken.id.desc())
    if user.role != "admin":
        q = q.filter(ApiToken.user_id == user.id)
    return [token_out(t) for t in q]


@router.post("/tokens")
def create_token(body: TokenIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    import hashlib
    import secrets
    from datetime import timedelta
    if not body.scopes or any(sc not in TOKEN_SCOPES for sc in body.scopes):
        raise HTTPException(400, "Geçersiz yetki kapsamı")
    if body.project_id:
        get_project(db, user, body.project_id)
    elif user.role == "customer":
        raise HTTPException(400, "Müşteri token'ı bir projeyle sınırlandırılmalı")
    raw = "lf_" + secrets.token_urlsafe(32)
    t = ApiToken(name=body.name, token_hash=hashlib.sha256(raw.encode()).hexdigest(), prefix=raw[:10],
                 user_id=user.id, project_id=body.project_id, scopes=sorted(set(body.scopes)),
                 expires_at=datetime.now(timezone.utc) + timedelta(days=body.expires_days) if body.expires_days else None)
    db.add(t)
    db.commit()
    audit(db, user, "token.create", "token", t.id, f"{t.name} {t.scopes} proje={t.project_id}", client_ip(request))
    return {**token_out(t), "token": raw}


@router.delete("/tokens/{token_id}")
def revoke_token(token_id: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    t = db.get(ApiToken, token_id)
    if t is None or (user.role != "admin" and t.user_id != user.id):
        raise HTTPException(404, "Token bulunamadı")
    t.revoked = True
    db.commit()
    audit(db, user, "token.revoke", "token", t.id, t.name, client_ip(request))
    return token_out(t)


from . import ci as _ci


def _ci_links(s: Scan, db: Session) -> dict:
    base = settings_store.get(db, "public_url").rstrip("/")
    return {"status_url": f"/api/ci/scans/{s.id}", "sarif_url": f"/api/scans/{s.id}/sarif",
            "ui_url": f"{base}/scans/{s.id}" if base else f"/scans/{s.id}"}


@router.post("/ci/scan")
async def ci_scan(request: Request, file: UploadFile, project_id: int = Form(...), target: str = Form("ci"),
                  ref: str = Form(""), fail_on: str = Form(""), fail_on_kev: str = Form(""),
                  fail_on_malicious: str = Form(""), fail_on_license: str = Form(""), new_only: str = Form(""),
                  user: User = Depends(current_user), db: Session = Depends(get_db)):
    p = get_project(db, user, project_id)
    try:
        overrides = _ci.clean_policy({"fail_on": fail_on, "fail_on_kev": fail_on_kev,
                                      "fail_on_malicious": fail_on_malicious, "fail_on_license": fail_on_license,
                                      "new_only": new_only})
    except ValueError as ex:
        raise HTTPException(400, str(ex))
    name = (target or "ci").strip()[:200] or "ci"
    t = db.query(Target).filter_by(project_id=p.id, name=name, kind="upload").first()
    if t is None:
        t = Target(project_id=p.id, name=name, kind="upload", options={}, files=[])
        db.add(t)
        db.commit()
        audit(db, user, "target.create", "target", t.id, f"ci {name}", client_ip(request))
    if db.query(Scan).join(Job).filter(Scan.target_id == t.id, Job.status.in_(("queued", "running"))).first():
        raise HTTPException(409, "Bu hedef için zaten bekleyen / çalışan bir tarama var")
    entry = await _store_upload(t, file)
    for old in t.files:
        (get_config().uploads_dir / str(t.id) / Path(old["stored"]).name).unlink(missing_ok=True)
    t.files = [entry]
    from . import queueing
    s = queueing.new_scan(db, t, user.id, params={"ci": overrides, "ref": ref[:200]})
    db.commit()
    audit(db, user, "ci.scan", "scan", s.id, f"{name} {entry['name']} {entry['sha256'][:16]} ref={ref[:80]}",
          client_ip(request))
    return {"scan_id": s.id, "target_id": t.id, "policy": _ci.effective_policy(p, overrides), **_ci_links(s, db)}


@router.get("/ci/scans/{scan_id}")
def ci_status(scan_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    s = get_scan(db, user, scan_id)
    out = {"scan_id": s.id, "status": s.job.status, "progress": s.job.progress, "error": s.job.error,
           "summary": s.summary, **_ci_links(s, db)}
    if s.job.status == "done":
        out["gate"] = _ci.evaluate_gate(db, s, (s.job.params or {}).get("ci"))
    return out


@router.get("/scans/{scan_id}/sarif")
def scan_sarif(scan_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    s = get_scan(db, user, scan_id)
    if s.job.status != "done":
        raise HTTPException(400, "Tarama tamamlanmadan rapor üretilemez")
    return PlainTextResponse(_ci.sarif_json(db, s, settings_store.get(db, "public_url")),
                             media_type="application/sarif+json",
                             headers={"Content-Disposition": f'attachment; filename="le-fureteur-{s.id}.sarif"'})


@router.get("/ci/client.py")
def ci_client(_: User = Depends(current_user)):
    src = (Path(__file__).resolve().parents[1] / "ci_client.py").read_text(encoding="utf-8")
    return PlainTextResponse(src, media_type="text/x-python",
                             headers={"Content-Disposition": 'attachment; filename="lf_ci.py"'})


_CLI_CACHE: dict = {}


@router.get("/cli/scakit.tar.gz")
def cli_package(request: Request, user: User = Depends(require("admin", "analyst")), db: Session = Depends(get_db)):
    import io
    import tarfile
    root = Path(__file__).resolve().parents[2]
    pkg = root / "scakit"
    files = [f for f in pkg.rglob("*") if f.is_file() and "__pycache__" not in f.parts and f.suffix not in (".pyc", ".pyo")]
    files += [f for f in (root / "pyproject.toml", root / "README.md") if f.exists()]
    stamp = (__version__, len(files), max(int(f.stat().st_mtime) for f in files))
    if _CLI_CACHE.get("stamp") != stamp:
        buf = io.BytesIO()
        base = f"scakit-{__version__}"
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            for f in sorted(files):
                ti = tf.gettarinfo(str(f), arcname=f"{base}/{f.relative_to(root).as_posix()}")
                ti.uid = ti.gid = 0
                ti.uname = ti.gname = ""
                with open(f, "rb") as fh:
                    tf.addfile(ti, fh)
        _CLI_CACHE.update(stamp=stamp, data=buf.getvalue())
    audit(db, user, "cli.download", "cli", "", f"scakit {__version__}", client_ip(request))
    return Response(_CLI_CACHE["data"], media_type="application/gzip",
                    headers={"Content-Disposition": f'attachment; filename="scakit-{__version__}.tar.gz"'})


@router.get("/meta")
def meta(_: User = Depends(current_user), db: Session = Depends(get_db)):
    return {"product": PRODUCT_NAME, "version": __version__, "public_url": settings_store.get(db, "public_url"),
            "max_upload_mb": get_config().max_upload_mb, "max_files_per_target": MAX_FILES_PER_TARGET,
            "browser_tls": _browser_tls_available(),
            "egress": [n for n, _u in settings_store.proxies(db)]}


from .models import TAG_COLORS, Tag


class TagIn(BaseModel):
    name: str = Field(min_length=1, max_length=40)
    color: str = "gray"
    organization_id: int | None = None


class TagPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=40)
    color: str | None = None


def tag_out(t: Tag, db: Session) -> dict:
    org = db.get(Organization, t.organization_id) if t.organization_id else None
    used = sum(1 for (ids,) in db.query(Project.tag_ids) if ids and t.id in ids)
    return {"id": t.id, "name": t.name, "color": t.color, "builtin": t.builtin, "organization_id": t.organization_id,
            "organization": org.name if org else None, "projects": used}


def _clean_tag_name(name: str) -> str:
    name = " ".join(name.split())
    if not name or any(ord(c) < 32 for c in name):
        raise HTTPException(400, "Geçersiz etiket adı")
    return name


def _tag_for_edit(db: Session, user: User, tag_id: int) -> Tag:
    t = _visible_tags(db, user).filter(Tag.id == tag_id).first()
    if t is None:
        raise HTTPException(404, "Etiket bulunamadı")
    if t.builtin and user.role != "admin":
        raise HTTPException(403, "Yerleşik etiketleri yalnızca yönetici düzenleyebilir")
    if t.organization_id is None and user.role == "customer":
        raise HTTPException(403, "Bu işlem için yetkiniz yok")
    return t


@router.get("/tags")
def list_tags(user: User = Depends(current_user), db: Session = Depends(get_db)):
    return {"colors": list(TAG_COLORS),
            "items": [tag_out(t, db) for t in _visible_tags(db, user).order_by(Tag.builtin.desc(), Tag.name)]}


@router.post("/tags")
def create_tag(body: TagIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    name = _clean_tag_name(body.name)
    if body.color not in TAG_COLORS:
        raise HTTPException(400, "Geçersiz renk")
    org_id = org_scope(user) or body.organization_id
    if org_id:
        get_org(db, user, org_id)
    scope_tags = db.query(Tag).filter((Tag.organization_id.is_(None)) | (Tag.organization_id == org_id)
                                      if org_id else Tag.organization_id.is_(None))
    if any(t.name.casefold() == name.casefold() for t in scope_tags):
        raise HTTPException(409, "Bu adla bir etiket zaten var")
    t = Tag(name=name, color=body.color, organization_id=org_id, created_by=user.id)
    db.add(t)
    db.commit()
    audit(db, user, "tag.create", "tag", t.id, f"{name} org={org_id}", client_ip(request))
    return tag_out(t, db)


@router.patch("/tags/{tag_id}")
def update_tag(tag_id: int, body: TagPatch, request: Request, user: User = Depends(current_user),
               db: Session = Depends(get_db)):
    t = _tag_for_edit(db, user, tag_id)
    if body.name is not None:
        if t.builtin:
            raise HTTPException(400, "Yerleşik etiketin adı değiştirilemez")
        t.name = _clean_tag_name(body.name)
    if body.color is not None:
        if body.color not in TAG_COLORS:
            raise HTTPException(400, "Geçersiz renk")
        t.color = body.color
    db.commit()
    audit(db, user, "tag.update", "tag", t.id, t.name, client_ip(request))
    return tag_out(t, db)


@router.delete("/tags/{tag_id}")
def delete_tag(tag_id: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    t = _tag_for_edit(db, user, tag_id)
    if t.builtin:
        raise HTTPException(400, "Yerleşik etiket silinemez")
    for p in db.query(Project).all():
        if p.tag_ids and t.id in p.tag_ids:
            p.tag_ids = [i for i in p.tag_ids if i != t.id]
    db.delete(t)
    db.commit()
    audit(db, user, "tag.delete", "tag", tag_id, t.name, client_ip(request))
    return {"ok": True}


from . import collab as _collab
from .models import TEAM_ROLES, ApprovalRequest, InboxItem, Team, TeamMember


def _brief(u: User | None) -> dict | None:
    return {"id": u.id, "email": u.email, "name": u.name, "role": u.role} if u else None


@router.get("/directory")
def people_directory(org_id: int | None = None, finding_id: int | None = None, user: User = Depends(current_user),
                     db: Session = Depends(get_db)):
    if finding_id:
        org_id = _collab.finding_org(db, get_finding(db, user, finding_id))
    return [_brief(u) for u in _collab.directory(db, user, org_id)]


class TeamIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = ""
    organization_id: int | None = None


class TeamMemberIn(BaseModel):
    user_id: int
    role: str = "member"
    reports_to: int | None = None


def team_out(db: Session, t: Team) -> dict:
    org = db.get(Organization, t.organization_id) if t.organization_id else None
    return {"id": t.id, "name": t.name, "description": t.description, "organization_id": t.organization_id,
            "organization": org.name if org else None,
            "members": [{"user": _brief(m.user), "role": m.role, "reports_to": m.reports_to} for m in t.members]}


def _team_access(db: Session, user: User, team_id: int) -> Team:
    t = db.get(Team, team_id)
    if t is None or (user.role == "customer" and t.organization_id != user.organization_id):
        raise HTTPException(404, "Takım bulunamadı")
    return t


@router.get("/teams")
def list_teams(org_id: int | None = None, user: User = Depends(current_user), db: Session = Depends(get_db)):
    q = db.query(Team).order_by(Team.name)
    if user.role == "customer":
        q = q.filter(Team.organization_id == user.organization_id)
    elif org_id:
        q = q.filter(Team.organization_id == org_id)
    return [team_out(db, t) for t in q]


@router.post("/teams")
def create_team(body: TeamIn, request: Request, user: User = Depends(require("admin", "analyst")),
                db: Session = Depends(get_db)):
    if body.organization_id and db.get(Organization, body.organization_id) is None:
        raise HTTPException(400, "Organizasyon bulunamadı")
    t = Team(name=body.name.strip(), description=body.description, organization_id=body.organization_id)
    db.add(t)
    db.commit()
    audit(db, user, "team.create", "team", t.id, t.name, client_ip(request))
    return team_out(db, t)


@router.patch("/teams/{team_id}")
def update_team(team_id: int, body: TeamIn, request: Request, user: User = Depends(require("admin", "analyst")),
                db: Session = Depends(get_db)):
    t = _team_access(db, user, team_id)
    t.name, t.description = body.name.strip(), body.description
    db.commit()
    audit(db, user, "team.update", "team", t.id, t.name, client_ip(request))
    return team_out(db, t)


@router.delete("/teams/{team_id}")
def delete_team(team_id: int, request: Request, user: User = Depends(require("admin", "analyst")),
                db: Session = Depends(get_db)):
    t = _team_access(db, user, team_id)
    db.delete(t)
    db.commit()
    audit(db, user, "team.delete", "team", team_id, t.name, client_ip(request))
    return {"ok": True}


@router.put("/teams/{team_id}/members")
def set_team_members(team_id: int, body: list[TeamMemberIn], request: Request,
                     user: User = Depends(require("admin", "analyst")), db: Session = Depends(get_db)):
    t = _team_access(db, user, team_id)
    if len(body) > 500:
        raise HTTPException(400, "Çok fazla üye")
    ids = [m.user_id for m in body]
    if len(set(ids)) != len(ids):
        raise HTTPException(400, "Aynı kişi iki kez eklenemez")
    roles = {m.user_id: m.role for m in body}
    for m in body:
        u = db.get(User, m.user_id)
        ok_org = u is not None and u.active and (u.role in _collab.STAFF or
                                                 (t.organization_id and u.organization_id == t.organization_id))
        if not ok_org:
            raise HTTPException(400, "Üye bu takımın organizasyonuna ait değil")
        if m.role not in TEAM_ROLES:
            raise HTTPException(400, "Geçersiz takım rolü")
        if m.reports_to is not None and (m.reports_to == m.user_id or roles.get(m.reports_to) not in ("manager", "lead")):
            raise HTTPException(400, "Bağlı olunan kişi bu takımda yönetici veya sorumlu olmalı")
    t.members.clear()
    db.flush()
    for m in body:
        t.members.append(TeamMember(user_id=m.user_id, role=m.role, reports_to=m.reports_to))
    db.commit()
    audit(db, user, "team.members", "team", t.id, ", ".join(f"{m.user_id}:{m.role}" for m in body)[:500],
          client_ip(request))
    return team_out(db, t)


class AssignIn(BaseModel):
    assignee_id: int | None = None
    due_date: datetime | None = None
    note: str = Field(default="", max_length=1000)


def _assign(db: Session, user: User, f: Finding, body: AssignIn) -> None:
    org_id = _collab.finding_org(db, f)
    target = db.get(User, body.assignee_id) if body.assignee_id else None
    if body.assignee_id and not _collab.eligible(db, target, org_id):
        raise HTTPException(400, "Bu kişi bu bulguyu göremez; atanamaz")
    f.assignee_id, f.assigned_by = body.assignee_id, user.id
    f.assigned_at = datetime.now(timezone.utc) if body.assignee_id else None
    f.due_date = body.due_date
    if target:
        db.add(Comment(finding_id=f.id, user_id=user.id, kind="assigned",
                       meta={"to": target.email, "to_name": target.name, "due": iso(body.due_date), "note": body.note},
                       text=f"Atandı: {target.email}"
                       + (f" (son tarih {body.due_date.date().isoformat()})" if body.due_date else "")
                       + (f". {body.note}" if body.note else "")))


@router.patch("/findings/{finding_id}/assign")
def assign_finding(finding_id: int, body: AssignIn, request: Request, user: User = Depends(current_user),
                   db: Session = Depends(get_db)):
    f = get_finding(db, user, finding_id)
    _assign(db, user, f, body)
    if body.assignee_id:
        _collab.notify(db, [body.assignee_id], "assigned", {**_collab.finding_params(f), "note": body.note[:300],
                                                             "due": iso(body.due_date)}, f"/findings?open={f.id}", user)
    db.commit()
    audit(db, user, "finding.assign", "finding", f.id, str(body.assignee_id), client_ip(request))
    return finding_out(f, full=True)


class BulkAssignIn(AssignIn):
    ids: list[int] = Field(min_length=1, max_length=500)


@router.post("/findings/assign")
def assign_findings(body: BulkAssignIn, request: Request, user: User = Depends(current_user),
                    db: Session = Depends(get_db)):
    done = []
    for fid in dict.fromkeys(body.ids):
        f = get_finding(db, user, fid)
        _assign(db, user, f, body)
        done.append(f)
    if body.assignee_id and done:
        _collab.notify(db, [body.assignee_id], "assigned_bulk", {"count": len(done), "note": body.note[:300],
                                                                 "due": iso(body.due_date)},
                       "/findings?assignee=me", user)
    db.commit()
    audit(db, user, "finding.assign.bulk", "finding", detail=f"{len(done)} → {body.assignee_id}", ip=client_ip(request))
    return {"assigned": len(done)}


class ShareIn(BaseModel):
    user_ids: list[int] = Field(min_length=1, max_length=50)
    message: str = Field(default="", max_length=2000)


@router.post("/findings/{finding_id}/share")
def share_finding(finding_id: int, body: ShareIn, request: Request, user: User = Depends(current_user),
                  db: Session = Depends(get_db)):
    f = get_finding(db, user, finding_id)
    org_id = _collab.finding_org(db, f)
    users = [db.get(User, i) for i in dict.fromkeys(body.user_ids)]
    if not all(_collab.eligible(db, u, org_id) for u in users):
        raise HTTPException(400, "Bazı kişiler bu bulguyu göremez; paylaşılamaz")
    n = _collab.notify(db, [u.id for u in users], "shared", {**_collab.finding_params(f), "message": body.message},
                       f"/findings?open={f.id}", user)
    db.add(Comment(finding_id=f.id, user_id=user.id, kind="shared",
                   meta={"to": [u.email for u in users], "message": body.message},
                   text=f"Paylaşıldı: {', '.join(u.email for u in users)}"
                   + (f" — {body.message}" if body.message else "")))
    db.commit()
    audit(db, user, "finding.share", "finding", f.id, ", ".join(u.email for u in users), client_ip(request))
    return {"shared": n}


def approval_out(db: Session, r: ApprovalRequest) -> dict:
    f = db.get(Finding, r.finding_id)
    return {"id": r.id, "finding_id": r.finding_id, "status": r.status, "from_status": r.from_status or "open",
            "reason": r.reason, "state": r.state,
            "requested_by": _brief(db.get(User, r.requested_by)) if r.requested_by else None,
            "approvers": [_brief(db.get(User, i)) for i in r.approver_ids or []],
            "decided_by": _brief(db.get(User, r.decided_by)) if r.decided_by else None,
            "decided_at": iso(r.decided_at), "decision_note": r.decision_note, "created_at": iso(r.created_at),
            "finding": finding_out(f) if f else None}


@router.get("/approvals")
def list_approvals(box: str = "todo", state: str = "pending", user: User = Depends(current_user),
                   db: Session = Depends(get_db)):
    q = db.query(ApprovalRequest).order_by(ApprovalRequest.id.desc())
    if box == "todo":
        state = "pending"
    if box == "decided":
        q = q.filter(ApprovalRequest.decided_by == user.id)
    elif state != "all":
        q = q.filter(ApprovalRequest.state == state)
    out = []
    for r in q.limit(500):
        f = db.get(Finding, r.finding_id)
        try:
            get_finding(db, user, f.id)
        except HTTPException:
            continue
        if box == "mine" and r.requested_by != user.id:
            continue
        if box == "todo" and not _collab.can_decide(user, r):
            continue
        out.append(approval_out(db, r))
    return out


@router.get("/approvals/count")
def approvals_count(user: User = Depends(current_user), db: Session = Depends(get_db)):
    n = 0
    for r in db.query(ApprovalRequest).filter_by(state="pending"):
        if _collab.can_decide(user, r):
            try:
                get_finding(db, user, r.finding_id)
                n += 1
            except HTTPException:
                pass
    return {"pending": n}


class DecideIn(BaseModel):
    approve: bool
    note: str = Field(default="", max_length=2000)


@router.post("/approvals/{req_id}/decide")
def decide_approval(req_id: int, body: DecideIn, request: Request, user: User = Depends(current_user),
                    db: Session = Depends(get_db)):
    r = db.get(ApprovalRequest, req_id)
    if r is None:
        raise HTTPException(404, "Onay talebi bulunamadı")
    f = get_finding(db, user, r.finding_id)
    if not _collab.can_decide(user, r) or r.requested_by == user.id:
        raise HTTPException(403, "Bu talep için karar yetkiniz yok")
    if r.state != "pending":
        raise HTTPException(409, "Bu talep zaten sonuçlanmış")
    if not body.approve and not body.note.strip():
        raise HTTPException(400, "Reddetme gerekçesi zorunlu")
    r.state = "approved" if body.approve else "rejected"
    r.decided_by, r.decided_at, r.decision_note = user.id, datetime.now(timezone.utc), body.note.strip()
    if body.approve:
        old = f.status
        f.status, f.status_reason, f.status_by = r.status, r.reason, r.requested_by
        db.add(Comment(finding_id=f.id, user_id=user.id, kind="approval_decided",
                       meta={"approved": True, "from": old, "to": r.status, "note": body.note, "request_id": r.id},
                       text=f"Onaylandı: {old} → {r.status}. {r.reason}" + (f" — {body.note}" if body.note else "")))
    else:
        db.add(Comment(finding_id=f.id, user_id=user.id, kind="approval_decided",
                       meta={"approved": False, "to": r.status, "note": body.note, "request_id": r.id},
                       text=f"Reddedildi ({r.status}): {body.note}"))
    if r.requested_by:
        _collab.notify(db, [r.requested_by], "approval_decided",
                       {**_collab.finding_params(f), "status": r.status, "approved": body.approve,
                        "note": body.note[:300]}, f"/findings?open={f.id}", user)
    db.commit()
    audit(db, user, "approval.decide", "approval", r.id, f"{r.state} {r.status}: {body.note[:200]}", client_ip(request))
    return approval_out(db, r)


@router.post("/approvals/{req_id}/cancel")
def cancel_approval(req_id: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    r = db.get(ApprovalRequest, req_id)
    if r is None or r.requested_by != user.id or r.state != "pending":
        raise HTTPException(404, "Onay talebi bulunamadı")
    r.state = "canceled"
    db.commit()
    audit(db, user, "approval.cancel", "approval", r.id, ip=client_ip(request))
    return approval_out(db, r)


def inbox_out(db: Session, n: InboxItem) -> dict:
    return {"id": n.id, "kind": n.kind, "params": n.params, "link": n.link, "read": n.read_at is not None,
            "created_at": iso(n.created_at)}


@router.get("/inbox")
def inbox(unread: bool = False, limit: int = Query(50, le=200), user: User = Depends(current_user),
          db: Session = Depends(get_db)):
    q = db.query(InboxItem).filter_by(user_id=user.id).order_by(InboxItem.id.desc())
    if unread:
        q = q.filter(InboxItem.read_at.is_(None))
    return [inbox_out(db, n) for n in q.limit(limit)]


@router.get("/inbox/count")
def inbox_count(user: User = Depends(current_user), db: Session = Depends(get_db)):
    return {"unread": db.query(InboxItem).filter(InboxItem.user_id == user.id, InboxItem.read_at.is_(None)).count()}


class ReadIn(BaseModel):
    ids: list[int] = []
    all: bool = False


@router.post("/inbox/read")
def inbox_read(body: ReadIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    q = db.query(InboxItem).filter(InboxItem.user_id == user.id, InboxItem.read_at.is_(None))
    if not body.all:
        q = q.filter(InboxItem.id.in_(body.ids or [0]))
    now = datetime.now(timezone.utc)
    n = 0
    for item in q:
        item.read_at = now
        n += 1
    db.commit()
    return {"read": n}


@router.post("/system/maintenance")
def run_maintenance(request: Request, admin: User = Depends(require("admin")), db: Session = Depends(get_db)):
    from . import maintenance
    stats = maintenance.run(db, log=lambda *_: None)
    audit(db, admin, "system.maintenance", "system", detail=json.dumps(stats), ip=client_ip(request))
    return {"stats": stats, "last": maintenance.last_run(db)}


from fastapi.responses import RedirectResponse

from . import oidc as _oidc


@router.get("/auth/oidc/config")
def oidc_config(db: Session = Depends(get_db)):
    return {"enabled": _oidc.enabled(db), "label": settings_store.get(db, "oidc_button_label")}


@router.get("/auth/oidc/start")
def oidc_start(request: Request, db: Session = Depends(get_db)):
    if not _oidc.enabled(db):
        raise HTTPException(404, "SSO kapalı")
    try:
        url, cookie = _oidc.start(db, str(request.base_url))
    except Exception as ex:
        audit(db, None, "login.sso.error", "user", detail=str(ex)[:300], ip=client_ip(request))
        return RedirectResponse("/login?sso_error=config", status_code=302)
    resp = RedirectResponse(url, status_code=302)
    resp.set_cookie(_oidc.COOKIE, cookie, httponly=True, secure=get_config().cookie_secure, samesite="lax",
                    max_age=600, path="/api/auth/oidc")
    return resp


@router.get("/auth/oidc/callback")
def oidc_callback(request: Request, code: str = "", state: str = "", error: str = "", db: Session = Depends(get_db)):
    ip = client_ip(request)
    fail_resp = lambda reason: RedirectResponse(f"/login?sso_error={reason}", status_code=302)
    if error or not code:
        return fail_resp("denied")
    try:
        email = _oidc.finish(db, code, state, request.cookies.get(_oidc.COOKIE), str(request.base_url))
    except Exception as ex:
        audit(db, None, "login.sso.failed", "user", detail=str(ex)[:300], ip=ip)
        return fail_resp("failed")
    user = db.query(User).filter(func.lower(User.email) == email).first()
    ua = request.headers.get("user-agent", "")[:400]
    if user is None or not user.active:
        _login_event(db, user, email, ip, ua, "sso", False, "no_account")
        audit(db, None, "login.sso.no_account", "user", detail=email[:200], ip=ip)
        return fail_resp("no_account")
    if user.role != "admin" and settings_store.get_bool(db, "maintenance_mode"):
        _login_event(db, user, email, ip, ua, "sso", False, "maintenance")
        return fail_resp("maintenance")
    token = create_session(db, user, ip, ua, "sso")
    _login_event(db, user, email, ip, ua, "sso", True, "")
    cfg = get_config()
    from fastapi.responses import HTMLResponse
    resp = HTMLResponse('<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="0;url=/">'
                        '<title>Le Fureteur</title><a href="/">Devam</a>')
    resp.set_cookie(SESSION_COOKIE, token, httponly=True, secure=cfg.cookie_secure, samesite="strict",
                    max_age=cfg.session_hours * 3600, path="/")
    resp.set_cookie(CSRF_COOKIE, new_csrf(), httponly=False, secure=cfg.cookie_secure, samesite="strict", path="/")
    resp.delete_cookie(_oidc.COOKIE, path="/api/auth/oidc")
    audit(db, user, "login.sso", "user", user.id, ip=ip)
    return resp


from .models import Dispute, DisputeMessage


def _dispute_people(d: Dispute) -> set[int]:
    return {x for x in [d.opened_by, d.delegate_id, *d.participants, *d.judge_ids] if x}


def _dispute_access(db: Session, user: User, dispute_id: int) -> tuple[Dispute, Finding]:
    d = db.get(Dispute, dispute_id)
    if d is None:
        raise HTTPException(404, "Tartışma bulunamadı")
    f = get_finding(db, user, d.finding_id)
    if user.role not in _collab.STAFF and user.id not in _dispute_people(d):
        raise HTTPException(404, "Tartışma bulunamadı")
    return d, f


def _can_judge(user: User, d: Dispute) -> bool:
    return user.role in _collab.STAFF or user.id in d.judge_ids or user.id == d.delegate_id


def dispute_out(db: Session, d: Dispute, user: User, full: bool = False) -> dict:
    f = db.get(Finding, d.finding_id)
    out = {"id": d.id, "finding_id": d.finding_id, "title": d.title, "status": d.status,
           "opened_by": _brief(db.get(User, d.opened_by)) if d.opened_by else None,
           "participants": [_brief(db.get(User, i)) for i in d.participants],
           "judges": [_brief(db.get(User, i)) for i in d.judge_ids],
           "delegate": _brief(db.get(User, d.delegate_id)) if d.delegate_id else None,
           "resolution": d.resolution, "resolved_status": d.resolved_status,
           "resolved_by": _brief(db.get(User, d.resolved_by)) if d.resolved_by else None,
           "created_at": iso(d.created_at), "escalated_at": iso(d.escalated_at), "resolved_at": iso(d.resolved_at),
           "can_judge": _can_judge(user, d), "finding": finding_out(f) if f else None,
           "messages_count": db.query(DisputeMessage).filter_by(dispute_id=d.id).count()}
    if full:
        out["messages"] = [{"id": m.id, "kind": m.kind, "text": m.text, "meta": m.meta or {}, "at": iso(m.created_at),
                            "user": _brief(db.get(User, m.user_id)) if m.user_id else None}
                           for m in db.query(DisputeMessage).filter_by(dispute_id=d.id).order_by(DisputeMessage.id)]
    return out


class DisputeIn(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    message: str = Field(min_length=1, max_length=5000)
    participants: list[int] = Field(default=[], max_length=20)


@router.get("/findings/{finding_id}/disputes")
def finding_disputes(finding_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    get_finding(db, user, finding_id)
    rows = db.query(Dispute).filter_by(finding_id=finding_id).order_by(Dispute.id.desc()).all()
    return [dispute_out(db, d, user) for d in rows if user.role in _collab.STAFF or user.id in _dispute_people(d)]


@router.post("/findings/{finding_id}/disputes")
def open_dispute(finding_id: int, body: DisputeIn, request: Request, user: User = Depends(current_user),
                 db: Session = Depends(get_db)):
    f = get_finding(db, user, finding_id)
    org_id = _collab.finding_org(db, f)
    people = [db.get(User, i) for i in dict.fromkeys(body.participants) if i != user.id]
    if not all(_collab.eligible(db, u, org_id) for u in people):
        raise HTTPException(400, "Bazı kişiler bu bulguyu göremez; tartışmaya eklenemez")
    d = Dispute(finding_id=f.id, title=body.title.strip(), opened_by=user.id, participants=[u.id for u in people])
    db.add(d)
    db.flush()
    db.add(DisputeMessage(dispute_id=d.id, user_id=user.id, text=body.message))
    db.add(Comment(finding_id=f.id, user_id=user.id, kind="dispute", meta={"dispute_id": d.id, "event": "opened",
                                                                            "title": d.title}, text=f"Tartışma açıldı: {d.title}"))
    _collab.notify(db, d.participants, "dispute_opened", {**_collab.finding_params(f), "title": d.title,
                                                          "dispute_id": d.id}, f"/disputes/{d.id}", user)
    db.commit()
    audit(db, user, "dispute.open", "dispute", d.id, d.title, client_ip(request))
    return dispute_out(db, d, user, full=True)


@router.get("/disputes")
def list_disputes(box: str = "all", user: User = Depends(current_user), db: Session = Depends(get_db)):
    out = []
    for d in db.query(Dispute).order_by(Dispute.id.desc()).limit(500):
        if user.role not in _collab.STAFF and user.id not in _dispute_people(d):
            continue
        try:
            get_finding(db, user, d.finding_id)
        except HTTPException:
            continue
        if box == "judge" and not (d.status == "escalated" and (user.id in d.judge_ids or user.id == d.delegate_id)):
            continue
        if box == "open" and d.status == "resolved":
            continue
        out.append(dispute_out(db, d, user))
    return out


@router.get("/disputes/{dispute_id}")
def read_dispute(dispute_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    d, _f = _dispute_access(db, user, dispute_id)
    return dispute_out(db, d, user, full=True)


class DisputeMsgIn(BaseModel):
    text: str = Field(min_length=1, max_length=5000)


@router.post("/disputes/{dispute_id}/messages")
def dispute_message(dispute_id: int, body: DisputeMsgIn, user: User = Depends(current_user),
                    db: Session = Depends(get_db)):
    d, f = _dispute_access(db, user, dispute_id)
    if d.status == "resolved":
        raise HTTPException(409, "Tartışma sonuçlanmış")
    db.add(DisputeMessage(dispute_id=d.id, user_id=user.id, text=body.text))
    _collab.notify(db, _dispute_people(d), "dispute_message", {**_collab.finding_params(f), "title": d.title,
                                                               "text": body.text[:200], "dispute_id": d.id},
                   f"/disputes/{d.id}", user)
    db.commit()
    return dispute_out(db, d, user, full=True)


class EscalateIn(BaseModel):
    note: str = Field(default="", max_length=2000)


@router.post("/disputes/{dispute_id}/escalate")
def escalate_dispute(dispute_id: int, body: EscalateIn, request: Request, user: User = Depends(current_user),
                     db: Session = Depends(get_db)):
    d, f = _dispute_access(db, user, dispute_id)
    if d.status != "open":
        raise HTTPException(409, "Tartışma zaten yöneticide veya sonuçlanmış")
    opener = db.get(User, d.opened_by) or user
    d.judge_ids = [i for i in _collab.approvers_for(db, opener, _collab.finding_org(db, f))
                   if i not in d.participants and i != d.opened_by] or _collab.approvers_for(db, opener, _collab.finding_org(db, f))
    d.status, d.escalated_at = "escalated", datetime.now(timezone.utc)
    db.add(DisputeMessage(dispute_id=d.id, user_id=user.id, kind="system", text="escalated",
                          meta={"event": "escalated", "note": body.note, "judges": d.judge_ids}))
    _collab.notify(db, d.judge_ids, "dispute_escalated", {**_collab.finding_params(f), "title": d.title,
                                                          "note": body.note[:300], "dispute_id": d.id},
                   f"/disputes/{d.id}", user)
    db.commit()
    audit(db, user, "dispute.escalate", "dispute", d.id, body.note[:200], client_ip(request))
    return dispute_out(db, d, user, full=True)


class DelegateIn(BaseModel):
    user_id: int
    note: str = Field(default="", max_length=1000)


@router.post("/disputes/{dispute_id}/delegate")
def delegate_dispute(dispute_id: int, body: DelegateIn, request: Request, user: User = Depends(current_user),
                     db: Session = Depends(get_db)):
    d, f = _dispute_access(db, user, dispute_id)
    if d.status != "escalated" or not _can_judge(user, d):
        raise HTTPException(403, "Bu tartışmada vekâlet verme yetkiniz yok")
    target = db.get(User, body.user_id)
    if not _collab.eligible(db, target, _collab.finding_org(db, f)) or target.id == d.opened_by:
        raise HTTPException(400, "Bu kişiye vekâlet verilemez")
    d.delegate_id = target.id
    db.add(DisputeMessage(dispute_id=d.id, user_id=user.id, kind="system", text="delegated",
                          meta={"event": "delegated", "to": target.email, "note": body.note}))
    _collab.notify(db, [target.id], "dispute_delegated", {**_collab.finding_params(f), "title": d.title,
                                                          "note": body.note[:300], "dispute_id": d.id},
                   f"/disputes/{d.id}", user)
    db.commit()
    audit(db, user, "dispute.delegate", "dispute", d.id, target.email, client_ip(request))
    return dispute_out(db, d, user, full=True)


class ResolveIn(BaseModel):
    resolution: str = Field(min_length=1, max_length=5000)
    status: str | None = None


@router.post("/disputes/{dispute_id}/resolve")
def resolve_dispute(dispute_id: int, body: ResolveIn, request: Request, user: User = Depends(current_user),
                    db: Session = Depends(get_db)):
    d, f = _dispute_access(db, user, dispute_id)
    if d.status == "resolved":
        raise HTTPException(409, "Tartışma sonuçlanmış")
    if d.status == "escalated" and not _can_judge(user, d):
        raise HTTPException(403, "Bu tartışmada karar yetkiniz yok")
    if d.status == "open" and not (user.id == d.opened_by or user.role in _collab.STAFF):
        raise HTTPException(403, "Tartışmayı yalnızca açan kişi veya karar verici kapatabilir")
    if body.status:
        if body.status not in FINDING_STATUSES or body.status == "fixed":
            raise HTTPException(400, "Geçersiz durum (\"fixed\" yalnızca tarama ile atanır)")
        if not _can_judge(user, d):
            raise HTTPException(403, "Bulgu durumunu yalnızca karar verici değiştirebilir")
        old = f.status
        f.status, f.status_reason, f.status_by = body.status, body.resolution.strip()[:2000], user.id
        db.add(Comment(finding_id=f.id, user_id=user.id, kind="status",
                       meta={"from": old, "to": body.status, "reason": body.resolution, "dispute_id": d.id},
                       text=f"Durum: {old} → {body.status} (tartışma #{d.id} kararı)"))
    d.status, d.resolution, d.resolved_status = "resolved", body.resolution.strip(), body.status
    d.resolved_by, d.resolved_at = user.id, datetime.now(timezone.utc)
    db.add(DisputeMessage(dispute_id=d.id, user_id=user.id, kind="system", text="resolved",
                          meta={"event": "resolved", "status": body.status, "resolution": body.resolution}))
    db.add(Comment(finding_id=f.id, user_id=user.id, kind="dispute",
                   meta={"dispute_id": d.id, "event": "resolved", "title": d.title, "resolution": body.resolution},
                   text=f"Tartışma sonuçlandı: {d.title}"))
    _collab.notify(db, _dispute_people(d), "dispute_resolved", {**_collab.finding_params(f), "title": d.title,
                                                                "resolution": body.resolution[:300],
                                                                "status": body.status, "dispute_id": d.id},
                   f"/disputes/{d.id}", user)
    db.commit()
    audit(db, user, "dispute.resolve", "dispute", d.id, f"{body.status}: {body.resolution[:200]}", client_ip(request))
    return dispute_out(db, d, user, full=True)


_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


@router.get("/teams/{team_id}/overview")
def team_overview(team_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    from .models import ApprovalRequest
    tm = _team_access(db, user, team_id)
    if user.role == "customer" and tm.organization_id is None:
        raise HTTPException(404, "Takım bulunamadı")
    ids = [m.user_id for m in tm.members]
    now = datetime.now(timezone.utc)
    since = now - timedelta(days=30)
    base = db.query(Finding).join(Project, Project.id == Finding.project_id).filter(Finding.assignee_id.in_(ids or [-1]))
    if tm.organization_id:
        base = base.filter(Project.organization_id == tm.organization_id)
    if (scope := org_scope(user)) is not None:
        base = base.filter(Project.organization_id == scope)
    open_rows = base.filter(Finding.status.in_(("open", "in_progress"))).all()
    done_rows = base.filter(Finding.status.notin_(("open", "in_progress")), Finding.status_changed_at >= since).all()

    def due(f):
        return f.due_date.replace(tzinfo=f.due_date.tzinfo or timezone.utc) if f.due_date else None

    people = []
    for m in tm.members:
        mine = [f for f in open_rows if f.assignee_id == m.user_id]
        sev: dict[str, int] = {}
        for f in mine:
            sev[f.severity] = sev.get(f.severity, 0) + 1
        people.append({"user": _brief(m.user), "role": m.role, "reports_to": m.reports_to,
                       "open": len(mine), "by_severity": sev,
                       "overdue": sum(1 for f in mine if due(f) and due(f) < now),
                       "delivered_30d": sum(1 for f in done_rows if f.assignee_id == m.user_id)})
    queue = sorted(open_rows, key=lambda f: (due(f) is None, due(f) or now, _SEV_ORDER.get(f.severity, 9), -(f.cvss or 0)))
    approvals = db.query(ApprovalRequest).filter(ApprovalRequest.state == "pending",
                                                 ApprovalRequest.requested_by.in_(ids or [-1])).count()
    disputes = [d for d in db.query(Dispute).filter(Dispute.status != "resolved")
                if d.opened_by in ids or set(d.participants or []) & set(ids)]
    if (scope := org_scope(user)) is not None:
        disputes = [d for d in disputes if db.get(Project, db.get(Finding, d.finding_id).project_id).organization_id == scope]

    def brief_f(f):
        return {**finding_out(f), "assignee": _user_brief(f)}
    return {"team": team_out(db, tm),
            "totals": {"open": len(open_rows), "overdue": sum(1 for f in open_rows if due(f) and due(f) < now),
                       "delivered_30d": len(done_rows), "pending_approvals": approvals, "open_disputes": len(disputes),
                       "critical": sum(1 for f in open_rows if f.severity == "CRITICAL")},
            "people": people, "queue": [brief_f(f) for f in queue[:50]],
            "delivered": [brief_f(f) for f in sorted(done_rows, key=lambda f: f.id, reverse=True)[:20]]}


@router.get("/orgs/{org_id}/overview")
def org_overview(org_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    o = get_org(db, user, org_id)
    projects = db.query(Project).filter_by(organization_id=o.id).order_by(Project.name).all()
    teams = db.query(Team).filter_by(organization_id=o.id).order_by(Team.name).all()
    users = db.query(User).filter_by(organization_id=o.id).order_by(User.email).all()
    return {"org": org_out(o, db), "projects": [project_out(p, db) for p in projects],
            "teams": [team_out(db, t) for t in teams], "users": [_brief(u) for u in users]}


from .models import LoginEvent, SessionToken


def _ua_label(ua: str) -> str:
    ua = ua or ""
    br = next((n for k, n in (("Edg/", "Edge"), ("OPR/", "Opera"), ("Firefox/", "Firefox"), ("Chrome/", "Chrome"),
                              ("Safari/", "Safari"), ("curl/", "curl"), ("python-requests", "Python")) if k in ua), "")
    os_ = next((n for k, n in (("Windows", "Windows"), ("Android", "Android"), ("iPhone", "iOS"), ("iPad", "iOS"),
                               ("Mac OS X", "macOS"), ("Linux", "Linux")) if k in ua), "")
    return " · ".join(x for x in (br, os_) if x) or (ua[:40] if ua else "")


def _session_out(s: SessionToken, current_id: int | None = None) -> dict:
    return {"id": s.id, "created_at": iso(s.created_at), "expires_at": iso(s.expires_at),
            "last_seen_at": iso(s.last_seen_at or s.created_at), "ip": s.last_ip or s.ip, "first_ip": s.ip,
            "user_agent": s.user_agent or "", "device": _ua_label(s.user_agent or ""), "method": s.method or "password",
            "current": s.id == current_id}


def _active_sessions(db: Session, user_id: int):
    now = datetime.now(timezone.utc)
    return [s for s in db.query(SessionToken).filter_by(user_id=user_id).order_by(SessionToken.id.desc())
            if (s.expires_at if s.expires_at.tzinfo else s.expires_at.replace(tzinfo=timezone.utc)) > now]


@router.get("/users/{user_id}/detail")
def user_detail(user_id: int, admin: User = Depends(require("admin")), db: Session = Depends(get_db)):
    u = db.get(User, user_id)
    if u is None:
        raise HTTPException(404, "Kullanıcı bulunamadı")
    logins = db.query(LoginEvent).filter(LoginEvent.user_id == u.id).order_by(LoginEvent.id.desc()).limit(50).all()
    last_ok = next((e for e in logins if e.success), None)
    actions = db.query(AuditLog).filter(AuditLog.user_id == u.id).order_by(AuditLog.id.desc()).limit(50).all()
    teams = [{"id": m.team.id, "name": m.team.name, "role": m.role}
             for m in db.query(TeamMember).filter_by(user_id=u.id)]
    open_assigned = db.query(func.count(Finding.id)).filter(Finding.assignee_id == u.id,
                                                            Finding.status.in_(("open", "in_progress"))).scalar()
    since = datetime.now(timezone.utc) - timedelta(days=30)
    failed_30d = db.query(func.count(LoginEvent.id)).filter(LoginEvent.user_id == u.id, LoginEvent.success.is_(False),
                                                            LoginEvent.at >= since).scalar()
    return {"user": user_out(u),
            "last_ip": last_ok.ip if last_ok else None, "last_user_agent": last_ok.user_agent if last_ok else None,
            "last_device": _ua_label(last_ok.user_agent) if last_ok else None,
            "stats": {"open_assigned": open_assigned, "failed_logins_30d": failed_30d,
                      "sessions": len(_active_sessions(db, u.id)),
                      "api_tokens": db.query(func.count(ApiToken.id)).filter(ApiToken.user_id == u.id,
                                                                            ApiToken.revoked.is_(False)).scalar()},
            "teams": teams,
            "sessions": [_session_out(s) for s in _active_sessions(db, u.id)],
            "logins": [{"id": e.id, "at": iso(e.at), "ip": e.ip, "device": _ua_label(e.user_agent),
                        "user_agent": e.user_agent, "method": e.method, "success": e.success, "reason": e.reason}
                       for e in logins],
            "actions": [_audit_row(a) for a in actions]}


@router.delete("/users/{user_id}/sessions")
def revoke_user_sessions(user_id: int, request: Request, session_id: int | None = None,
                         admin: User = Depends(require("admin")), db: Session = Depends(get_db)):
    u = db.get(User, user_id)
    if u is None:
        raise HTTPException(404, "Kullanıcı bulunamadı")
    q = db.query(SessionToken).filter_by(user_id=u.id)
    if session_id:
        q = q.filter(SessionToken.id == session_id)
    n = q.delete()
    db.commit()
    audit(db, admin, "user.sessions.revoke", "user", u.id, f"{n} oturum", client_ip(request))
    return {"revoked": n}


@router.get("/auth/sessions")
def my_sessions(user: User = Depends(current_user), db: Session = Depends(get_db)):
    if getattr(user, "via_token", False):
        raise HTTPException(403, "API token'ı ile kullanılamaz")
    return [_session_out(s, getattr(user, "session_id", None)) for s in _active_sessions(db, user.id)]


@router.delete("/auth/sessions/{session_id}")
def end_my_session(session_id: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    s = db.get(SessionToken, session_id)
    if s is None or s.user_id != user.id or getattr(user, "via_token", False):
        raise HTTPException(404, "Oturum bulunamadı")
    db.delete(s)
    db.commit()
    audit(db, user, "session.end", "session", session_id, ip=client_ip(request))
    return {"ok": True}
