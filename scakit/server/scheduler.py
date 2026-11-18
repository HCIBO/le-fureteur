from __future__ import annotations

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from croniter import croniter
from sqlalchemy import update
from sqlalchemy.orm import Session

from . import settings_store
from .models import Job, Scan, Schedule

MIN_INTERVAL = timedelta(hours=1)


def tz(db: Session) -> ZoneInfo:
    try:
        return ZoneInfo(settings_store.get(db, "timezone") or "UTC")
    except Exception:
        return ZoneInfo("UTC")


def next_runs(cron: str, zone: ZoneInfo, n: int = 5, after: datetime | None = None) -> list[datetime]:
    base = (after or datetime.now(timezone.utc)).astimezone(zone)
    it = croniter(cron, base)
    return [it.get_next(datetime).astimezone(timezone.utc) for _ in range(n)]


def validate(cron: str, zone: ZoneInfo) -> list[datetime]:
    cron = cron.strip()
    if len(cron.split()) != 5 or not croniter.is_valid(cron):
        raise ValueError("Geçersiz cron ifadesi (5 alan: dakika saat gün ay haftanın-günü)")
    runs = next_runs(cron, zone, 6)
    if any(b - a < MIN_INTERVAL for a, b in zip(runs, runs[1:])):
        raise ValueError("Zamanlama en sık saatte bir çalışabilir")
    return runs


def tick(db: Session, log=print) -> int:
    now = datetime.now(timezone.utc)
    zone = tz(db)
    created = 0
    due = db.query(Schedule).filter(Schedule.enabled.is_(True), Schedule.next_run_at.is_not(None),
                                    Schedule.next_run_at <= now).all()
    for s in due:
        old = s.next_run_at
        try:
            nxt = next_runs(s.cron, zone, 1)[0]
        except Exception:
            nxt = None
        res = db.execute(update(Schedule).where(Schedule.id == s.id, Schedule.next_run_at == old)
                         .values(next_run_at=nxt, last_run_at=now))
        db.commit()
        if res.rowcount != 1:
            continue
        if s.kind == "scan":
            if s.target is None:
                continue
            busy = db.query(Scan).join(Job).filter(Scan.target_id == s.target_id,
                                                   Job.status.in_(("queued", "running"))).first()
            if busy:
                log(f"schedule #{s.id}: target busy, skipped")
                continue
            from . import queueing
            job = db.get(Job, queueing.new_scan(db, s.target, s.created_by, params={"schedule_id": s.id}).job_id)
        elif s.kind == "db_update":
            if db.query(Job).filter(Job.kind == "db_update", Job.status.in_(("queued", "running"))).first():
                continue
            job = Job(kind="db_update", created_by=s.created_by, params={"schedule_id": s.id})
            db.add(job)
            db.flush()
        else:
            continue
        s.last_job_id = job.id
        db.commit()
        created += 1
    return created
