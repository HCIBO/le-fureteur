from __future__ import annotations

import re
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from . import settings_store
from .models import ApprovalRequest, Finding, InboxItem, Project, Team, TeamMember, User

STAFF = ("admin", "analyst")
NEEDS_APPROVAL = ("accepted_risk", "false_positive", "not_affected")


def _now():
    return datetime.now(timezone.utc)


def finding_org(db: Session, f: Finding) -> int:
    return db.get(Project, f.project_id).organization_id


def eligible(db: Session, user: User | None, org_id: int) -> bool:
    return bool(user and user.active and (user.role in STAFF or user.organization_id == org_id))


def directory(db: Session, viewer: User, org_id: int | None = None) -> list[User]:
    q = db.query(User).filter(User.active.is_(True))
    if viewer.role == "customer":
        q = q.filter(User.organization_id == viewer.organization_id)
    elif org_id:
        q = q.filter((User.role.in_(STAFF)) | (User.organization_id == org_id))
    return q.order_by(User.email).all()


def memberships(db: Session, user_id: int, org_id: int | None) -> list[TeamMember]:
    q = db.query(TeamMember).join(Team).filter(TeamMember.user_id == user_id)
    return [m for m in q if m.team.organization_id in (org_id, None)]


def is_team_manager(db: Session, user: User, org_id: int) -> bool:
    return any(m.role == "manager" for m in memberships(db, user.id, org_id))


def approvers_for(db: Session, requester: User, org_id: int) -> list[int]:
    ids: set[int] = set()
    for m in memberships(db, requester.id, org_id):
        if m.reports_to:
            ids.add(m.reports_to)
        ids |= {x.user_id for x in m.team.members if x.role == "manager"}
    ids.discard(requester.id)
    users = [u for u in (db.get(User, i) for i in ids) if eligible(db, u, org_id)]
    if not users:
        users = db.query(User).filter(User.role.in_(STAFF), User.active.is_(True)).all()
    return sorted({u.id for u in users if u.id != requester.id})


def needs_approval(db: Session, user: User, org_id: int, status: str) -> bool:
    if status not in NEEDS_APPROVAL or not settings_store.get_bool(db, "approval_required"):
        return False
    return not (user.role in STAFF or is_team_manager(db, user, org_id))


def can_decide(user: User, req: ApprovalRequest) -> bool:
    return user.role in STAFF or user.id in (req.approver_ids or [])


def notify(db: Session, user_ids, kind: str, params: dict, link: str = "", actor: User | None = None) -> int:
    n = 0
    for uid in dict.fromkeys(user_ids):
        if actor and uid == actor.id:
            continue
        db.add(InboxItem(user_id=uid, actor_id=actor.id if actor else None, kind=kind,
                         params={**params, "actor": actor.email if actor else ""}, link=link))
        n += 1
    return n


def finding_params(f: Finding) -> dict:
    cve = next((a for a in (f.aliases or []) if a.startswith("CVE-")), f.vuln_id)
    return {"finding_id": f.id, "vuln": cve, "component": f.component, "version": f.version, "severity": f.severity}


_MENTION = re.compile(r"@([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})")


def mentions(db: Session, text: str, org_id: int) -> list[int]:
    out = []
    for email in dict.fromkeys(m.lower() for m in _MENTION.findall(text or "")):
        u = db.query(User).filter(User.email == email).first()
        if eligible(db, u, org_id):
            out.append(u.id)
    return out
