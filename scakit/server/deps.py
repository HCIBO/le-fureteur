from __future__ import annotations

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .db import get_db
from .models import Finding, Organization, Project, Scan, Target, User
from .security import SESSION_COOKIE, user_for_token


def client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    auth = request.headers.get("authorization", "")
    if auth[:7].lower() == "bearer ":
        return _api_token_user(request, db, auth[7:].strip())
    user = user_for_token(db, request.cookies.get(SESSION_COOKIE), client_ip(request))
    if user is None:
        raise HTTPException(401, "Oturum açmanız gerekiyor")
    user.token_project_id = None
    user.via_token = False
    check_maintenance(user)
    return user


def check_maintenance(user: User) -> None:
    from . import settings_store
    if user.role != "admin" and settings_store.cached("maintenance_mode").strip().lower() in ("1", "true", "yes", "on"):
        raise HTTPException(503, detail={"code": "maintenance",
                                         "message": settings_store.cached("maintenance_message") or ""})


_TOKEN_RULES = {
    "read": [({"GET"}, r"^/api/(auth/me|projects(/\d+(/targets)?)?|targets/\d+|scans(/\d+(/(reports(/[^/]+)?|components|changes|sarif))?)?"
                       r"|findings(/\d+)?|jobs/\d+|ci/.*)$")],
    "scan": [({"POST"}, r"^/api/(ci/.*|targets/\d+/(files|scans)|projects/\d+/targets)$"),
             ({"DELETE"}, r"^/api/targets/\d+/files/[^/]+$"),
             ({"GET"}, r"^/api/(ci/.*|jobs/\d+|scans/\d+(/(reports(/[^/]+)?|sarif))?|auth/me)$")],
}


def token_allows(scopes: list[str], method: str, path: str) -> bool:
    import re
    for sc in scopes or []:
        for methods, pattern in _TOKEN_RULES.get(sc, []):
            if method in methods and re.match(pattern, path):
                return True
    return False


def _api_token_user(request: Request, db: Session, raw: str) -> User:
    import hashlib
    from datetime import datetime, timezone

    from .models import ApiToken
    tok = db.query(ApiToken).filter_by(token_hash=hashlib.sha256(raw.encode()).hexdigest()).first() if raw else None
    now = datetime.now(timezone.utc)
    exp = tok.expires_at if tok and tok.expires_at and tok.expires_at.tzinfo else \
        (tok.expires_at.replace(tzinfo=timezone.utc) if tok and tok.expires_at else None)
    if tok is None or tok.revoked or (exp and exp < now) or not tok.user.active:
        raise HTTPException(401, "Geçersiz veya süresi dolmuş API token'ı")
    if not token_allows(tok.scopes, request.method, request.url.path):
        raise HTTPException(403, "Bu API token'ı bu işlem için yetkili değil")
    last = tok.last_used_at.replace(tzinfo=timezone.utc) if tok.last_used_at and not tok.last_used_at.tzinfo \
        else tok.last_used_at
    if last is None or (now - last).total_seconds() > 60:
        tok.last_used_at, tok.last_used_ip = now, client_ip(request)
        db.commit()
    user = tok.user
    user.token_project_id = tok.project_id
    user.via_token = True
    check_maintenance(tok.user)
    return user


def token_project(user: User) -> int | None:
    return getattr(user, "token_project_id", None)


def require(*roles: str):
    def dep(user: User = Depends(current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(403, "Bu işlem için yetkiniz yok")
        return user
    return dep


def org_scope(user: User) -> int | None:
    if user.role == "customer":
        if user.organization_id is None:
            raise HTTPException(403, "Hesabınız bir organizasyona bağlı değil")
        return user.organization_id
    return None


def _not_found(what: str):
    return HTTPException(404, f"{what} bulunamadı")


def get_org(db: Session, user: User, org_id: int) -> Organization:
    org = db.get(Organization, org_id)
    scope = org_scope(user)
    if org is None or (scope is not None and org.id != scope):
        raise _not_found("Organizasyon")
    return org


def get_project(db: Session, user: User, project_id: int) -> Project:
    p = db.get(Project, project_id)
    scope = org_scope(user)
    tp = token_project(user)
    if p is None or (scope is not None and p.organization_id != scope) or (tp and p.id != tp):
        raise _not_found("Proje")
    return p


def get_target(db: Session, user: User, target_id: int) -> Target:
    t = db.get(Target, target_id)
    if t is None:
        raise _not_found("Hedef")
    get_project(db, user, t.project_id)
    return t


def get_scan(db: Session, user: User, scan_id: int) -> Scan:
    s = db.get(Scan, scan_id)
    if s is None:
        raise _not_found("Tarama")
    get_target(db, user, s.target_id)
    return s


def get_finding(db: Session, user: User, finding_id: int) -> Finding:
    f = db.get(Finding, finding_id)
    if f is None:
        raise _not_found("Bulgu")
    get_project(db, user, f.project_id)
    return f
