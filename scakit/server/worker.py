from __future__ import annotations

import os
import socket
import time
import traceback
from datetime import datetime, timezone

from sqlalchemy import update

from ..analysis import Canceled
from .db import SessionLocal, init_db
from .. import __version__
from .models import Job, Scan, WorkerStatus
from .pipeline import HANDLERS, JobContext

WORKER_ID = f"{socket.gethostname()}:{os.getpid()}"


def _aware(d):
    return d if d is None or d.tzinfo else d.replace(tzinfo=timezone.utc)


def _group_blocked(db, job: Job, now) -> bool:
    if not job.queue_group:
        return False
    same = db.query(Job).filter(Job.queue_group == job.queue_group, Job.id != job.id)
    running = same.filter(Job.status == "running").count()
    if job.queue_parallel and running >= job.queue_parallel:
        return True
    if job.queue_gap:
        if job.queue_parallel == 1:
            last = same.filter(Job.finished_at.is_not(None)).order_by(Job.finished_at.desc()).first()
            ref = _aware(last.finished_at) if last else None
        else:
            last = same.filter(Job.started_at.is_not(None)).order_by(Job.started_at.desc()).first()
            ref = _aware(last.started_at) if last else None
        if ref and (now - ref).total_seconds() < job.queue_gap:
            return True
    return False


def claim(db) -> Job | None:
    now = datetime.now(timezone.utc)
    for job in db.query(Job).filter_by(status="queued").order_by(Job.priority.desc(), Job.created_at, Job.id).limit(200):
        if _group_blocked(db, job, now):
            continue
        res = db.execute(update(Job).where(Job.id == job.id, Job.status == "queued")
                         .values(status="running", worker=WORKER_ID, started_at=datetime.now(timezone.utc)))
        db.commit()
        if res.rowcount == 1:
            db.refresh(job)
            return job
    return None


def _limits_from(db) -> tuple[int, int]:
    from . import settings_store
    timeout = int(os.environ.get("SCAKIT_JOB_TIMEOUT_SECONDS") or
                  float(settings_store.get(db, "job_timeout_minutes") or 120) * 60)
    mem = int(float(settings_store.get(db, "job_memory_mb") or 4096)) * 1024 * 1024
    return max(timeout, 1), mem


def _child(job_id: int, mem: int) -> None:
    code = 0
    try:
        from . import db as dbm
        dbm._engine = dbm._Session = None
        try:
            import resource
            if mem > 0:
                resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except (ImportError, ValueError, OSError):
            pass
        db = SessionLocal()
        try:
            _execute(db, db.get(Job, job_id))
        finally:
            db.close()
    except BaseException:
        traceback.print_exc()
        code = 1
    os._exit(code)


def _finish_abnormal(db, job: Job, status: str, msg: str) -> None:
    db.refresh(job)
    if job.status in ("done", "failed", "canceled") and status != "canceled":
        return
    job.status, job.finished_at = status, datetime.now(timezone.utc)
    if status == "failed":
        job.error = msg
    job.log = (job.log or "") + msg + "\n"
    db.commit()
    if status == "failed":
        _notify_failure(db, job)


def start_isolated(db, job: Job):
    import multiprocessing as mp
    timeout, mem = _limits_from(db)
    proc = mp.get_context("fork").Process(target=_child, args=(job.id, mem), daemon=False)
    proc.start()
    return proc, time.time() + timeout


def supervise(db, job: Job, proc, deadline: float) -> bool:
    if proc.is_alive():
        db.refresh(job, ["status"])
        if job.status == "canceled":
            proc.kill()
            proc.join(5)
            _finish_abnormal(db, job, "canceled", "İptal edildi.")
            return True
        if time.time() > deadline:
            proc.kill()
            proc.join(5)
            _finish_abnormal(db, job, "failed", "Zaman aşımı: iş süre sınırını aştı ve durduruldu")
            return True
        return False
    proc.join()
    db.refresh(job)
    if job.status == "running":
        _finish_abnormal(db, job, "failed", f"İş süreci beklenmedik biçimde sonlandı (çıkış kodu {proc.exitcode}); "
                                            "bellek sınırı aşılmış olabilir")
    return True


def run_job(db, job: Job, isolate: bool | None = None) -> None:
    if isolate is None:
        isolate = os.environ.get("SCAKIT_JOB_ISOLATION", "1") != "0" and hasattr(os, "fork")
    if not isolate:
        return _execute(db, job)
    proc, deadline = start_isolated(db, job)
    while not supervise(db, job, proc, deadline):
        time.sleep(0.5)


def _execute(db, job: Job) -> None:
    ctx = JobContext(db, job)
    try:
        HANDLERS[job.kind](db, job, ctx)
        db.refresh(job, ["status"])
        if job.status != "canceled":
            job.status = "done"
    except Canceled:
        job.status = "canceled"
        ctx.log("İptal edildi.")
    except Exception as ex:
        db.rollback()
        from .errors import humanize
        try:
            ctx.event("failed", "error", **humanize(ex))
        except Exception:
            db.rollback()
        job.status = "failed"
        job.error = f"{type(ex).__name__}: {ex}"
        job.log = (job.log or "") + traceback.format_exc()[-4000:]
    job.finished_at = datetime.now(timezone.utc)
    db.commit()
    if job.status == "failed":
        _notify_failure(db, job)


def _notify_failure(db, job: Job) -> None:
    from . import notify
    try:
        if job.kind == "scan":
            scan = db.query(Scan).filter_by(job_id=job.id).one()
            notify.dispatch(db, "scan_failed", lambda _r: notify.build_scan_message(db, "scan_failed", scan,
                                                                                   error=job.error or ""),
                            scan.target.project.organization_id)
        elif job.kind == "db_update":
            notify.dispatch(db, "db_update_failed", lambda _r: notify.build_simple_message(
                db, "db_update_failed", "Zafiyet veritabanı güncellemesi başarısız", [job.error or ""], "/settings"),
                None)
    except Exception:
        traceback.print_exc()


_last_beat = 0.0


def heartbeat(db, job_id=None, force: bool = False) -> None:
    global _last_beat
    now = time.time()
    if not force and now - _last_beat < 15:
        return
    _last_beat = now
    row = db.get(WorkerStatus, WORKER_ID) or WorkerStatus(worker=WORKER_ID)
    row.last_seen, row.current_job, row.version = datetime.now(timezone.utc), job_id, __version__
    db.merge(row)
    db.commit()


def run_once() -> bool:
    db = SessionLocal()
    try:
        heartbeat(db)
        try:
            from .scheduler import tick
            tick(db)
        except Exception:
            db.rollback()
            traceback.print_exc()
        job = claim(db)
        if job is None:
            return False
        heartbeat(db, job.id, force=True)
        run_job(db, job)
        heartbeat(db, None, force=True)
        return True
    finally:
        db.close()


def recover_stale() -> None:
    db = SessionLocal()
    try:
        for job in db.query(Job).filter(Job.status == "running", Job.worker.like(f"{socket.gethostname()}:%")):
            pid = int(job.worker.rsplit(":", 1)[1])
            if pid != os.getpid():
                try:
                    os.kill(pid, 0)
                    continue
                except ProcessLookupError:
                    pass
                except PermissionError:
                    continue
            job.status, job.error = "failed", "Worker yeniden başlatıldı; iş yarım kaldı"
            job.finished_at = datetime.now(timezone.utc)
        db.commit()
    finally:
        db.close()


def main(poll: float = 2.0, concurrency: int = 1) -> None:
    init_db()
    recover_stale()
    print(f"scakit worker çalışıyor ({WORKER_ID}, eşzamanlı iş: {concurrency})", flush=True)
    running: dict[int, tuple] = {}
    last_finished = 0.0
    db = SessionLocal()
    try:
        from datetime import datetime, timedelta, timezone
        db.query(WorkerStatus).filter(WorkerStatus.last_seen < datetime.now(timezone.utc) - timedelta(hours=1)).delete()
        db.commit()
    except Exception:
        db.rollback()
    try:
        while True:
            try:
                heartbeat(db, next(iter(running), None))
                try:
                    from . import settings_store
                    from .scheduler import tick
                    if not settings_store.get_bool(db, "maintenance_mode"):
                        tick(db)
                    from .messaging import fire_reminders
                    if fire_reminders(db):
                        db.commit()
                    from . import maintenance
                    if maintenance.due(db):
                        maintenance.run(db)
                except Exception:
                    db.rollback()
                    traceback.print_exc()
                for jid, (proc, deadline) in list(running.items()):
                    job = db.get(Job, jid)
                    if job is None or supervise(db, job, proc, deadline):
                        running.pop(jid, None)
                        last_finished = time.monotonic()
                from . import settings_store
                limit = settings_store.get_int(db, "queue_concurrency") or concurrency
                gap = settings_store.get_int(db, "queue_gap_seconds")
                while len(running) < max(1, limit) and time.monotonic() - last_finished >= gap:
                    job = claim(db)
                    if job is None:
                        break
                    running[job.id] = start_isolated(db, job)
                time.sleep(poll if not running else 0.5)
            except KeyboardInterrupt:
                break
            except Exception:
                db.rollback()
                traceback.print_exc()
                time.sleep(poll)
    finally:
        for proc, _d in running.values():
            proc.kill()
        db.close()
