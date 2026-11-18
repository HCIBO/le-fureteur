from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from . import collab
from .db import get_db
from .deps import client_ip, current_user, get_finding
from .models import Message, MessageReceipt, MessageThread, Reminder, Team, TeamMember, User
from .security import audit

router = APIRouter(prefix="/api")
NUDGE_INTERVAL = timedelta(hours=1)
_LINK = re.compile(r"^/[A-Za-z0-9/_\-?=&.%]*$")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt):
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _brief(u: User | None) -> dict | None:
    return {"id": u.id, "email": u.email, "name": u.name, "role": u.role} if u else None


def can_message(sender: User, to: User | None) -> bool:
    if to is None or not to.active or to.id == sender.id:
        return False
    if sender.role in collab.STAFF or to.role in collab.STAFF:
        return True
    return sender.organization_id is not None and sender.organization_id == to.organization_id


def can_use_team(db: Session, user: User, team: Team | None) -> bool:
    if team is None:
        return False
    if user.role in collab.STAFF:
        return True
    if team.organization_id != user.organization_id:
        return False
    return db.query(TeamMember).filter_by(team_id=team.id, user_id=user.id).first() is not None


def _thread(db: Session, user: User, thread_id: int) -> MessageThread:
    t = db.get(MessageThread, thread_id)
    if t is None or user.id not in (t.participants or []):
        raise HTTPException(404, "Konuşma bulunamadı")
    return t


def _receipt_state(rs: list[MessageReceipt]) -> str:
    if not rs:
        return "sent"
    if all(r.read_at for r in rs):
        return "read"
    if all(r.delivered_at for r in rs):
        return "delivered"
    return "sent"


def _post(db: Session, t: MessageThread, sender: User, body: str) -> Message:
    m = Message(thread_id=t.id, sender_id=sender.id, body=body)
    db.add(m)
    db.flush()
    for uid in t.participants:
        if uid != sender.id:
            db.add(MessageReceipt(message_id=m.id, user_id=uid))
    t.last_at = _now()
    return m


def thread_out(db: Session, t: MessageThread, user: User, full: bool = False) -> dict:
    msgs = db.query(Message).filter_by(thread_id=t.id).order_by(Message.id).all()
    ids = [m.id for m in msgs]
    receipts = db.query(MessageReceipt).filter(MessageReceipt.message_id.in_(ids)).all() if ids else []
    by_msg: dict[int, list[MessageReceipt]] = {}
    for r in receipts:
        by_msg.setdefault(r.message_id, []).append(r)
    unread = sum(1 for r in receipts if r.user_id == user.id and r.read_at is None)
    last = msgs[-1] if msgs else None
    team = db.get(Team, t.team_id) if t.team_id else None
    out = {"id": t.id, "subject": t.subject, "created_by": _brief(db.get(User, t.created_by)) if t.created_by else None,
           "team": {"id": team.id, "name": team.name} if team else None, "finding_id": t.finding_id,
           "participants": [_brief(u) for u in (db.get(User, i) for i in t.participants) if u],
           "created_at": _iso(t.created_at), "last_at": _iso(t.last_at), "unread": unread, "count": len(msgs),
           "last": {"body": last.body[:160], "sender": _brief(db.get(User, last.sender_id)) if last.sender_id else None,
                    "at": _iso(last.created_at),
                    "state": _receipt_state(by_msg.get(last.id, [])) if last.sender_id == user.id else None} if last else None}
    if full:
        users = {}
        def u(i):
            if i not in users:
                users[i] = _brief(db.get(User, i))
            return users[i]
        out["messages"] = []
        for m in msgs:
            rs = by_msg.get(m.id, [])
            mine = m.sender_id == user.id
            out["messages"].append({
                "id": m.id, "body": m.body, "at": _iso(m.created_at), "sender": u(m.sender_id) if m.sender_id else None,
                "mine": mine, "state": _receipt_state(rs) if mine else None,
                "receipts": [{"user": u(r.user_id), "delivered_at": _iso(r.delivered_at), "read_at": _iso(r.read_at)}
                             for r in rs] if mine else []})
    return out


def mark_delivered(db: Session, user: User) -> None:
    now = _now()
    db.query(MessageReceipt).filter(MessageReceipt.user_id == user.id, MessageReceipt.delivered_at.is_(None)) \
        .update({MessageReceipt.delivered_at: now}, synchronize_session=False)


def fire_reminders(db: Session, user_id: int | None = None) -> int:
    q = db.query(Reminder).filter(Reminder.fired_at.is_(None), Reminder.done_at.is_(None), Reminder.due_at <= _now())
    if user_id:
        q = q.filter(Reminder.user_id == user_id)
    n = 0
    for r in q.limit(500):
        r.fired_at = _now()
        collab.notify(db, [r.user_id], "reminder", {"text": r.text, "reminder_id": r.id}, r.link or "/messages?tab=reminders")
        n += 1
    return n


@router.get("/messages/count")
def messages_count(user: User = Depends(current_user), db: Session = Depends(get_db)):
    mark_delivered(db, user)
    fire_reminders(db, user.id)
    db.commit()
    unread = db.query(MessageReceipt).filter(MessageReceipt.user_id == user.id, MessageReceipt.read_at.is_(None)).count()
    return {"unread": unread}


@router.get("/messages/threads")
def list_threads(box: str = "all", q: str = "", user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = []
    for t in db.query(MessageThread).order_by(MessageThread.last_at.desc()).limit(2000):
        if user.id not in (t.participants or []):
            continue
        if box in ("inbox", "sent"):
            mine = Message.sender_id == user.id
            cond = (~mine | Message.sender_id.is_(None)) if box == "inbox" else mine
            if db.query(Message.id).filter(Message.thread_id == t.id, cond).first() is None:
                continue
        if q and q.lower() not in t.subject.lower():
            continue
        out = thread_out(db, t, user)
        if box == "unread" and not out["unread"]:
            continue
        rows.append(out)
        if len(rows) >= 200:
            break
    return rows


class ThreadIn(BaseModel):
    subject: str = Field(min_length=1, max_length=200)
    body: str = Field(min_length=1, max_length=10000)
    to: list[int] = Field(default=[], max_length=50)
    team_id: int | None = None
    finding_id: int | None = None


@router.post("/messages/threads")
def create_thread(body: ThreadIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    people: set[int] = set()
    for uid in dict.fromkeys(body.to):
        to = db.get(User, uid)
        if not can_message(user, to):
            raise HTTPException(400, "Bu kişiye mesaj gönderemezsiniz")
        people.add(uid)
    if body.team_id:
        team = db.get(Team, body.team_id)
        if not can_use_team(db, user, team):
            raise HTTPException(403, "Bu takıma mesaj gönderemezsiniz")
        people |= {m.user_id for m in team.members if m.user_id != user.id and m.user and m.user.active}
    if body.finding_id:
        f = get_finding(db, user, body.finding_id)
        org = collab.finding_org(db, f)
        if not all(collab.eligible(db, db.get(User, i), org) for i in people):
            raise HTTPException(400, "Bazı alıcılar bu bulguyu göremez")
    if not people:
        raise HTTPException(400, "En az bir alıcı seçin")
    t = MessageThread(subject=body.subject.strip(), created_by=user.id, team_id=body.team_id,
                      finding_id=body.finding_id, participants=sorted(people | {user.id}))
    db.add(t)
    db.flush()
    _post(db, t, user, body.body)
    db.commit()
    audit(db, user, "message.thread", "thread", t.id, f"{len(people)} alıcı", client_ip(request))
    return thread_out(db, t, user, full=True)


@router.get("/messages/threads/{thread_id}")
def read_thread(thread_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    t = _thread(db, user, thread_id)
    now = _now()
    ids = [m.id for m in db.query(Message.id).filter_by(thread_id=t.id)]
    if ids:
        for r in db.query(MessageReceipt).filter(MessageReceipt.message_id.in_(ids), MessageReceipt.user_id == user.id,
                                                 MessageReceipt.read_at.is_(None)):
            r.read_at = now
            r.delivered_at = r.delivered_at or now
    db.commit()
    return thread_out(db, t, user, full=True)


class ReplyIn(BaseModel):
    body: str = Field(min_length=1, max_length=10000)


@router.post("/messages/threads/{thread_id}/reply")
def reply(thread_id: int, body: ReplyIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    t = _thread(db, user, thread_id)
    if not any(can_message(user, db.get(User, i)) for i in t.participants if i != user.id):
        raise HTTPException(400, "Bu konuşmada yanıtlayabileceğiniz kimse kalmadı")
    _post(db, t, user, body.body)
    db.commit()
    return thread_out(db, t, user, full=True)


@router.post("/messages/threads/{thread_id}/nudge")
def nudge(thread_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    t = _thread(db, user, thread_id)
    last = db.query(Message).filter_by(thread_id=t.id, sender_id=user.id).order_by(Message.id.desc()).first()
    if last is None:
        raise HTTPException(400, "Bu konuşmada mesajınız yok")
    from .models import InboxItem
    recent = db.query(InboxItem).filter(InboxItem.actor_id == user.id, InboxItem.kind == "message_nudge",
                                        InboxItem.created_at >= _now() - NUDGE_INTERVAL).all()
    if any(i.params.get("thread_id") == t.id for i in recent):
        raise HTTPException(429, "Bu konuşma için son bir saat içinde zaten hatırlatma gönderdiniz")
    pending = [r.user_id for r in db.query(MessageReceipt).filter_by(message_id=last.id) if r.read_at is None]
    if not pending:
        raise HTTPException(400, "Herkes mesajınızı okudu")
    collab.notify(db, pending, "message_nudge", {"subject": t.subject, "thread_id": t.id}, f"/messages/{t.id}", user)
    db.commit()
    return {"nudged": len(pending)}


@router.get("/messages/recipients")
def recipients(user: User = Depends(current_user), db: Session = Depends(get_db)):
    people = [u for u in db.query(User).filter(User.active.is_(True)).order_by(User.email) if can_message(user, u)]
    teams = [t for t in db.query(Team).order_by(Team.name) if can_use_team(db, user, t)]
    return {"users": [_brief(u) for u in people],
            "teams": [{"id": t.id, "name": t.name, "members": len(t.members)} for t in teams]}


class ReminderIn(BaseModel):
    text: str = Field(min_length=1, max_length=500)
    due_at: datetime
    link: str = Field(default="", max_length=300)


def reminder_out(r: Reminder) -> dict:
    return {"id": r.id, "text": r.text, "due_at": _iso(r.due_at), "link": r.link, "fired_at": _iso(r.fired_at),
            "done_at": _iso(r.done_at), "created_at": _iso(r.created_at)}


@router.get("/reminders")
def list_reminders(user: User = Depends(current_user), db: Session = Depends(get_db)):
    fire_reminders(db, user.id)
    db.commit()
    rows = db.query(Reminder).filter_by(user_id=user.id).order_by(Reminder.done_at.isnot(None), Reminder.due_at).limit(300)
    return [reminder_out(r) for r in rows]


@router.post("/reminders")
def create_reminder(body: ReminderIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if body.link and not _LINK.match(body.link):
        raise HTTPException(400, "Bağlantı uygulama içi bir yol olmalı (ör. /findings?open=12)")
    due = body.due_at if body.due_at.tzinfo else body.due_at.replace(tzinfo=timezone.utc)
    if db.query(Reminder).filter(Reminder.user_id == user.id, Reminder.done_at.is_(None)).count() >= 200:
        raise HTTPException(400, "Açık hatırlatıcı sınırına ulaştınız (200)")
    r = Reminder(user_id=user.id, text=body.text.strip(), due_at=due, link=body.link)
    db.add(r)
    db.commit()
    return reminder_out(r)


class ReminderPatch(BaseModel):
    done: bool | None = None
    due_at: datetime | None = None


@router.patch("/reminders/{reminder_id}")
def update_reminder(reminder_id: int, body: ReminderPatch, user: User = Depends(current_user),
                    db: Session = Depends(get_db)):
    r = db.get(Reminder, reminder_id)
    if r is None or r.user_id != user.id:
        raise HTTPException(404, "Hatırlatıcı bulunamadı")
    if body.done is not None:
        r.done_at = _now() if body.done else None
    if body.due_at is not None:
        r.due_at = body.due_at if body.due_at.tzinfo else body.due_at.replace(tzinfo=timezone.utc)
        r.fired_at, r.done_at = None, None
    db.commit()
    return reminder_out(r)


@router.delete("/reminders/{reminder_id}")
def delete_reminder(reminder_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    r = db.get(Reminder, reminder_id)
    if r is None or r.user_id != user.id:
        raise HTTPException(404, "Hatırlatıcı bulunamadı")
    db.delete(r)
    db.commit()
    return {"ok": True}
