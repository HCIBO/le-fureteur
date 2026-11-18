from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from .db import get_db
from .deps import check_maintenance, client_ip, current_user, get_target
from .models import CaptureTicket, Job, Scan, Target, User
from .security import audit

router = APIRouter(prefix="/api")
TTL = timedelta(hours=2)
PREFIX = "lfc_"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(d: datetime) -> datetime:
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _ticket(db: Session, request: Request) -> tuple[CaptureTicket, User, Target]:
    auth = request.headers.get("authorization", "")
    raw = auth[7:].strip() if auth[:7].lower() == "bearer " else ""
    if not raw.startswith(PREFIX):
        raise HTTPException(401, "Geçersiz veya süresi dolmuş bilet")
    tk = db.query(CaptureTicket).filter_by(token_hash=hashlib.sha256(raw.encode()).hexdigest()).first()
    if tk is None or _aware(tk.expires_at) < _now():
        raise HTTPException(401, "Geçersiz veya süresi dolmuş bilet")
    user = db.get(User, tk.created_by)
    if user is None or not user.active:
        raise HTTPException(401, "Geçersiz veya süresi dolmuş bilet")
    user.token_project_id, user.via_token = None, False
    check_maintenance(user)
    t = get_target(db, user, tk.target_id)
    return tk, user, t


@router.post("/targets/{target_id}/capture-ticket")
def create_ticket(target_id: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if getattr(user, "via_token", False):
        raise HTTPException(403, "API token'ı ile bilet üretilemez")
    t = get_target(db, user, target_id)
    if t.kind != "web":
        raise HTTPException(400, "Tarayıcı yardımcısı yalnızca web hedefleri içindir")
    raw = PREFIX + secrets.token_urlsafe(32)
    last = db.query(Scan).filter_by(target_id=t.id).order_by(Scan.id.desc()).first()
    tk = CaptureTicket(token_hash=hashlib.sha256(raw.encode()).hexdigest(), target_id=t.id, created_by=user.id,
                       scan_id=last.id if last else None, expires_at=_now() + TTL)
    db.add(tk)
    db.commit()
    audit(db, user, "capture.ticket", "target", t.id, t.url, client_ip(request))
    return {"ticket": raw, "expires_at": tk.expires_at.isoformat(), "target": t.name, "url": t.url}


@router.get("/capture/info")
def ticket_info(request: Request, db: Session = Depends(get_db)):
    tk, _user, t = _ticket(db, request)
    o = t.options or {}
    return {"url": t.url, "target": t.name, "max_pages": int(o.get("max_pages", 30)),
            "delay": max(1.0, float(o.get("delay", 1.0))), "used": tk.used_at is not None,
            "expires_at": _aware(tk.expires_at).isoformat()}


@router.post("/capture/upload")
async def ticket_upload(file: UploadFile, request: Request, db: Session = Depends(get_db)):
    from ..collectors.blackbox.traffic import sniff
    from .api import _store_upload
    from .config import get_config
    tk, user, web = _ticket(db, request)
    if tk.used_at is not None:
        raise HTTPException(409, "Bu bilet zaten kullanıldı; arayüzden yeni bilet üretin")
    name = f"{web.name} (tarayıcı kaydı)"[:200]
    tt = db.query(Target).filter_by(project_id=web.project_id, kind="upload", name=name).first()
    if tt is None:
        tt = Target(project_id=web.project_id, name=name, kind="upload", url="", options={"type": "traffic"}, files=[])
        db.add(tt)
        db.flush()
    entry = await _store_upload(tt, file)
    stored = get_config().uploads_dir / str(tt.id) / entry["stored"]
    if sniff(stored) != "har":
        stored.unlink(missing_ok=True)
        raise HTTPException(400, "Yüklenen dosya HAR biçiminde değil")
    for old in tt.files:
        (get_config().uploads_dir / str(tt.id) / old["stored"]).unlink(missing_ok=True)
    tt.files = [entry]
    busy = db.query(Scan).join(Job).filter(Scan.target_id == tt.id, Job.status.in_(("queued", "running"))).first()
    if busy:
        raise HTTPException(409, "Bu hedef için zaten çalışan bir tarama var")
    from . import queueing
    s = queueing.new_scan(db, tt, user.id)
    tk.used_at, tk.result_target_id = _now(), tt.id
    db.flush()
    tk.result_scan_id = s.id
    db.commit()
    audit(db, user, "capture.upload", "target", tt.id, f"{entry['name']} {entry['size']}B → tarama #{s.id}",
          client_ip(request))
    return {"target_id": tt.id, "scan_id": s.id, "path": f"/scans/{s.id}"}


@router.get("/capture/helper.py")
def helper_script():
    src = (Path(__file__).resolve().parents[1] / "capture_client.py").read_text(encoding="utf-8")
    return PlainTextResponse(src, media_type="text/x-python",
                             headers={"Content-Disposition": 'attachment; filename="lf_capture.py"'})


@router.get("/targets/{target_id}/capture-status")
def capture_status(target_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    t = get_target(db, user, target_id)
    tk = db.query(CaptureTicket).filter_by(target_id=t.id, created_by=user.id).order_by(CaptureTicket.id.desc()).first()
    if tk is None:
        return {"ticket": None}
    return {"ticket": {"expires_at": _aware(tk.expires_at).isoformat(), "used_at": tk.used_at and _aware(tk.used_at).isoformat(),
                       "result_target_id": tk.result_target_id, "result_scan_id": tk.result_scan_id,
                       "expired": _aware(tk.expires_at) < _now()}}
