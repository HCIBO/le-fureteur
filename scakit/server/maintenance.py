from __future__ import annotations

import json
import shutil
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from . import settings_store
from .config import get_config
from .models import AuditLog, InboxItem, Job, Scan, Setting, Target

LAST_KEY = "_maintenance_last"
ACTIVE = ("queued", "running")


def _num(db: Session, key: str) -> int:
    try:
        return max(0, int(float(settings_store.get(db, key) or 0)))
    except ValueError:
        return 0


def _rm_tree(path: Path, root: Path) -> bool:
    try:
        if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()) or path.resolve() == root.resolve():
            return False
    except OSError:
        return False
    shutil.rmtree(path, ignore_errors=True)
    return True


def run(db: Session, log=print) -> dict:
    cfg = get_config()
    now = datetime.now(timezone.utc)
    stats = {"scans": 0, "jobs": 0, "audit": 0, "inbox": 0, "orphan_dirs": 0}
    keep_n = _num(db, "retention_scans_per_target")
    keep_days = _num(db, "retention_scan_days")

    for target in db.query(Target).all():
        scans = db.query(Scan).filter_by(target_id=target.id).order_by(Scan.id.desc()).all()
        finished = [s for s in scans if s.job and s.job.status not in ACTIVE]
        if not finished:
            continue
        latest = finished[0]
        doomed = []
        for i, s in enumerate(finished):
            if s is latest:
                continue
            created = s.created_at if s.created_at.tzinfo else s.created_at.replace(tzinfo=timezone.utc)
            if (keep_n and i >= keep_n) or (keep_days and created < now - timedelta(days=keep_days)):
                doomed.append(s)
        for s in doomed:
            if s.workdir:
                _rm_tree(Path(s.workdir), cfg.scans_dir)
            job = s.job
            db.delete(s)
            if job:
                db.delete(job)
            stats["scans"] += 1
    db.commit()

    scan_job_ids = {jid for (jid,) in db.query(Scan.job_id)}
    cutoff = now - timedelta(days=90)
    for job in db.query(Job).filter(Job.status.notin_(ACTIVE)).all():
        created = job.created_at if job.created_at.tzinfo else job.created_at.replace(tzinfo=timezone.utc)
        if job.id not in scan_job_ids and created < cutoff:
            db.delete(job)
            stats["jobs"] += 1
    if (days := _num(db, "audit_retention_days")):
        stats["audit"] = db.query(AuditLog).filter(AuditLog.at < now - timedelta(days=days)).delete()
    stats["inbox"] = db.query(InboxItem).filter(InboxItem.read_at.is_not(None),
                                                InboxItem.read_at < now - timedelta(days=90)).delete()
    db.commit()

    known_scans = {Path(w).resolve() for (w,) in db.query(Scan.workdir) if w}
    known_targets = {str(i) for (i,) in db.query(Target.id)}
    day_ago = time.time() - 86400
    for d in (cfg.scans_dir.iterdir() if cfg.scans_dir.exists() else []):
        if d.is_dir() and d.resolve() not in known_scans and d.stat().st_mtime < day_ago:
            stats["orphan_dirs"] += _rm_tree(d, cfg.scans_dir)
    for d in (cfg.uploads_dir.iterdir() if cfg.uploads_dir.exists() else []):
        if d.is_dir() and d.name not in known_targets and d.stat().st_mtime < day_ago:
            stats["orphan_dirs"] += _rm_tree(d, cfg.uploads_dir)

    row = db.get(Setting, LAST_KEY) or Setting(key=LAST_KEY, secret=False)
    row.value = json.dumps({"at": now.isoformat(), **stats})
    db.merge(row)
    db.commit()
    log(f"Bakım: {stats}")
    return stats


def last_run(db: Session) -> dict | None:
    row = db.get(Setting, LAST_KEY)
    return json.loads(row.value) if row and row.value else None


def due(db: Session) -> bool:
    last = last_run(db)
    if not last:
        return True
    at = datetime.fromisoformat(last["at"])
    return datetime.now(timezone.utc) - at > timedelta(hours=24)
