from __future__ import annotations

import uuid

from fastapi import HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from .models import Job, Scan, Target

PRIORITIES = ("high", "normal", "low")
DEFAULT_POLICY = {"priority": "normal", "parallel": 0, "gap": 0}


def clean_policy(p: dict | None, role: str = "admin") -> dict:
    p = p or {}
    pr = p.get("priority", "normal")
    if pr not in PRIORITIES:
        raise HTTPException(400, "Geçersiz öncelik")
    if pr == "high" and role not in ("admin", "analyst"):
        raise HTTPException(403, "Kuyrukta öne alma yalnızca yönetici ve analist içindir")
    try:
        par, gap = int(p.get("parallel", 0) or 0), int(p.get("gap", 0) or 0)
    except (TypeError, ValueError):
        raise HTTPException(400, "Geçersiz kuyruk kuralı") from None
    if not 0 <= par <= 20 or not 0 <= gap <= 3600:
        raise HTTPException(400, "Aynı anda 0–20 tarama, bekleme 0–3600 sn olabilir")
    return {"priority": pr, "parallel": par, "gap": gap}


def project_policy(project) -> dict:
    return {**DEFAULT_POLICY, **(project.queue_policy or {})}


def _priority_value(db: Session, pr: str) -> int:
    if pr == "high":
        top = db.query(func.max(Job.priority)).filter(Job.status == "queued").scalar() or 0
        return max(top, 0) + 1
    return -1 if pr == "low" else 0


def new_scan(db: Session, target: Target, user_id: int | None, policy: dict | None = None, group: str | None = None,
             params: dict | None = None) -> Scan:
    pol = policy or project_policy(target.project)
    job = Job(kind="scan", created_by=user_id, params=params or {},
              priority=_priority_value(db, pol["priority"]),
              queue_group=group or f"project:{target.project_id}",
              queue_parallel=int(pol["parallel"]), queue_gap=int(pol["gap"]))
    db.add(job)
    db.flush()
    s = Scan(target_id=target.id, job_id=job.id, created_by=user_id)
    db.add(s)
    db.flush()
    return s


def batch_group() -> str:
    return f"batch:{uuid.uuid4().hex[:12]}"
