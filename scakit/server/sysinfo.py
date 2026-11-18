from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from importlib import metadata
from pathlib import Path

from sqlalchemy import func, text
from sqlalchemy.orm import Session

from .. import __version__
from . import settings_store
from .config import get_config
from .db import engine
from .models import Job, NotificationChannel, Schedule, User, WorkerStatus

EXTRAS = {"report", "server"}
_SELFSCAN: dict = {}
_LATEST: dict = {}


def _now():
    return datetime.now(timezone.utc)


def _aware(dt):
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def python_packages() -> list[dict]:
    from packaging.requirements import Requirement
    from packaging.utils import canonicalize_name
    out: dict[str, dict] = {}

    def reqs(dist_name: str, extras: set[str]):
        try:
            raw = metadata.requires(dist_name) or []
        except metadata.PackageNotFoundError:
            return []
        res = []
        for r in raw:
            req = Requirement(r)
            if req.marker and not any(req.marker.evaluate({"extra": e}) for e in (extras or {""})):
                continue
            res.append(req)
        return res

    stack = [(r, True) for r in reqs("scakit", EXTRAS)]
    while stack:
        req, direct = stack.pop()
        key = canonicalize_name(req.name)
        if key in out:
            out[key]["direct"] = out[key]["direct"] or direct
            continue
        try:
            ver = metadata.version(req.name)
        except metadata.PackageNotFoundError:
            out[key] = {"name": req.name, "version": None, "direct": direct, "required": str(req.specifier),
                        "installed": False}
            continue
        out[key] = {"name": metadata.metadata(req.name)["Name"], "version": ver, "direct": direct,
                    "required": str(req.specifier), "installed": True}
        stack += [(r, False) for r in reqs(req.name, set(req.extras))]
    return sorted(out.values(), key=lambda p: (not p["direct"], p["name"].lower()))


def frontend_info() -> dict:
    from .app import frontend_dir
    d = frontend_dir()
    f = d / "deps.json"
    if not (d / "index.html").exists():
        return {"built": False, "packages": [], "built_at": None}
    if not f.exists():
        return {"built": True, "packages": [], "built_at": None}
    data = json.loads(f.read_text())
    return {"built": True, "built_at": data.get("built_at"), "packages": data.get("packages", [])}


def os_info() -> dict:
    rel = {}
    for p in ("/etc/os-release", "/usr/lib/os-release"):
        if os.path.exists(p):
            for line in Path(p).read_text().splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    rel[k] = v.strip('"')
            break
    return {"name": rel.get("PRETTY_NAME", platform.platform()), "id": rel.get("ID", ""),
            "version_id": rel.get("VERSION_ID", ""), "container": os.path.exists("/.dockerenv"),
            "release_text": "\n".join(f"{k}={v}" for k, v in rel.items())}


def os_packages() -> list:
    from ..collectors.whitebox import ospkg
    info = os_info()
    eco = ospkg.os_ecosystem(info["release_text"]) if info["release_text"] else None
    if not eco:
        return []
    if os.path.exists("/var/lib/dpkg/status"):
        return ospkg.parse_dpkg_status(Path("/var/lib/dpkg/status").read_text(errors="replace"),
                                       "/var/lib/dpkg/status", eco, "scakit-sunucu")
    if os.path.exists("/lib/apk/db/installed"):
        return ospkg.parse_apk_installed(Path("/lib/apk/db/installed").read_text(errors="replace"),
                                         "/lib/apk/db/installed", eco, "scakit-sunucu")
    return []


def tools() -> list[dict]:
    from ..collectors.blackbox.desktop import _seven_zip
    out = []
    exe = _seven_zip()
    ver = ""
    if exe:
        try:
            r = subprocess.run([exe], capture_output=True, text=True, timeout=5)
            ver = next((ln.strip() for ln in r.stdout.splitlines() if "7-Zip" in ln), "")[:80]
        except Exception:
            pass
    out.append({"name": "7-Zip", "path": exe or "", "version": ver, "ok": bool(exe),
                "purpose": "Masaüstü kurulum dosyalarını (.exe / .msi / NSIS / Inno) açmak için",
                "fix": "Debian/Ubuntu: apt install 7zip (Docker imajında kurulu)"})
    return out


def database_info(db: Session) -> dict:
    eng = engine()
    name = eng.dialect.name
    ver, size = "", None
    try:
        if name == "sqlite":
            import sqlite3
            ver = sqlite3.sqlite_version
            path = eng.url.database
            size = os.path.getsize(path) if path and os.path.exists(path) else None
        elif name == "postgresql":
            ver = db.execute(text("SHOW server_version")).scalar() or ""
            size = db.execute(text("SELECT pg_database_size(current_database())")).scalar()
    except Exception as ex:
        ver = f"? ({ex})"
    return {"engine": name, "version": ver, "size": size}


def _dir_size(p: Path, limit: int = 200_000) -> int:
    total, n = 0, 0
    for root, _dirs, files in os.walk(p):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
            n += 1
            if n > limit:
                return total
    return total


SOURCE_LIMITS = {
    "osv": (48, 24 * 7), "epss": (72, 24 * 14), "kev": (72, 24 * 14), "nvd": (24 * 7, 24 * 30),
}


def vulndb_info(db: Session) -> dict:
    from .pipeline import vulndb
    v = vulndb(db)
    meta = v.meta()
    fams: dict[str, dict] = {}
    for k, m in meta.items():
        if k.startswith("file:"):
            continue
        fam = k.split(":", 1)[0].lower()
        g = fams.setdefault(fam, {"name": fam.upper(), "parts": [], "oldest": None, "count": 0})
        g["parts"].append(k.split(":", 1)[1] if ":" in k else k)
        g["count"] += int(m.get("count") or 0)
        upd = m.get("updated")
        try:
            dt = _aware(datetime.fromisoformat(upd.replace("Z", "+00:00"))) if upd else None
        except ValueError:
            dt = None
        if dt is None or g["oldest"] is None or (g["oldest"] != "never" and dt < g["oldest"]):
            g["oldest"] = dt or "never"
    sources = []
    for fam, g in sorted(fams.items()):
        dt = None if g["oldest"] in (None, "never") else g["oldest"]
        age = (_now() - dt).total_seconds() / 3600 if dt else None
        warn, crit = SOURCE_LIMITS.get(fam, (24 * 7, 24 * 30))
        level = "ok" if age is not None and age < warn else ("warn" if age is not None and age < crit else "crit")
        sources.append({"name": g["name"], "detail": ", ".join(sorted(g["parts"]))[:300] if len(g["parts"]) > 1 else "",
                        "count": g["count"], "updated": dt.isoformat() if dt else None,
                        "age_hours": round(age, 1) if age is not None else None, "level": level})
    path = Path(v.path)
    return {"path": str(path), "size": path.stat().st_size if path.exists() else 0, "sources": sources}


def checks(db: Session, info: dict) -> list[dict]:
    cfg = get_config()
    out = []

    def add(level, cid, title, detail="", action="", **params):
        out.append({"level": level, "id": cid, "params": params, "title": title, "detail": detail, "action": action})

    vdb = info["vulndb"]
    if not vdb["sources"]:
        add("crit", "vulndb_empty", "Zafiyet veritabanı boş", "Bulgu üretilemez.", "Ayarlar → Veritabanını güncelle")
    for s in vdb["sources"]:
        if s["level"] != "ok":
            add(s["level"], "vulndb_stale", f"Zafiyet verisi eski: {s['name']}",
                f"Son güncelleme {s['age_hours']} saat önce" if s["age_hours"] is not None else "Hiç güncellenmemiş",
                "Ayarlar → Veritabanını güncelle", source=s["name"], hours=s["age_hours"])
    if not db.query(Schedule).filter_by(kind="db_update", enabled=True).first():
        add("info", "no_db_schedule", "Otomatik veritabanı güncellemesi yok",
            "Yeni yayımlanan zafiyetler ancak veritabanı güncellenince görünür.",
            "Ayarlar → Zamanlanmış veritabanı güncellemesi ekleyin (ör. her gün 02:00)")
    if not [w for w in info["workers"] if w["alive"]]:
        add("crit", "no_worker", "Çalışan worker yok", "Taramalar ve güncellemeler kuyrukta bekler.",
            "Docker: docker compose up -d worker · Elle: scakit server worker")
    if info["queue"]["failed_24h"]:
        add("warn", "failed_jobs", f"Son 24 saatte {info['queue']['failed_24h']} iş başarısız", "",
            "Taramalar sayfasında günlüğe bakın", n=info["queue"]["failed_24h"])
    if not cfg.cookie_secure:
        add("warn", "cookie_insecure", "Oturum çerezi Secure değil",
            "Arayüz HTTPS olmadan kullanılıyorsa parolalar ve oturum ağda açık gider.",
            "Önüne TLS'li ters vekil (nginx / Caddy) koyup SCAKIT_COOKIE_SECURE=1 yapın")
    if not os.environ.get("SCAKIT_SECRET_KEY"):
        add("info", "secret_file", "Gizli anahtar dosyadan okunuyor", f"{cfg.data_dir / 'secret.key'}",
            "Yedekleme planına bu dosyayı ekleyin (şifreli ayarlar bu anahtarla çözülür)",
            path=str(cfg.data_dir / "secret.key"))
    if info["database"]["engine"] == "sqlite":
        add("info", "sqlite", "Veritabanı SQLite", "Tek kullanıcı / deneme için uygundur.",
            "Çok kullanıcılı kurulumda Docker compose'daki PostgreSQL'i kullanın")
    if settings_store.get_bool(db, "allow_internal_targets"):
        add("warn", "internal_allowed", "İç ağ taraması açık", "Yönetici ve analistler özel IP adreslerini tarayabilir.",
            "Gerekmiyorsa Ayarlar'dan kapatın")
    admins = db.query(User).filter_by(role="admin", active=True).all()
    if any(u.email == "admin@localhost" for u in admins):
        add("warn", "default_admin", "Varsayılan yönetici e-postası kullanılıyor", "admin@localhost",
            "Gerçek bir e-posta ile yönetici oluşturup bu hesabı kapatın")
    if len(admins) == 1:
        add("info", "single_admin", "Tek yönetici hesabı", "Hesap kilitlenirse erişim kaybolur.",
            "İkinci bir yönetici tanımlayın")
    d = info["disk"]
    if d["total"]:
        free = d["free"] / d["total"]
        if free < 0.10:
            add("crit", "disk_low", "Disk dolmak üzere", f"Boş alan %{free * 100:.0f}",
                "Eski taramaları / yüklemeleri temizleyin", pct=round(free * 100))
        elif free < 0.20:
            add("warn", "disk_low", "Disk alanı azalıyor", f"Boş alan %{free * 100:.0f}", "", pct=round(free * 100))
    for t in info["tools"]:
        if not t["ok"]:
            add("info", "tool_missing", f"{t['name']} kurulu değil", t["purpose"], t["fix"], tool=t["name"])
    if not info["frontend"]["built"]:
        add("warn", "frontend_missing", "Arayüz derlenmemiş", "", "cd frontend && npm ci && npm run build")
    if sys.version_info < (3, 10):
        add("warn", "python_old", f"Python {platform.python_version()} destek dışı", "", "Python 3.11+ kullanın",
            version=platform.python_version())
    if not db.query(NotificationChannel).filter_by(enabled=True).first():
        add("info", "no_channels", "Bildirim kanalı yok",
            "Tarama sonuçları ve yeni kritik bulgular kimseye bildirilmiyor.",
            "Bildirimler sayfasından Slack / Teams / e-posta kanalı ekleyin")
    if not settings_store.get(db, "public_url"):
        add("info", "no_public_url", "Arayüz adresi (public_url) tanımlı değil",
            "Bildirim ve Jira kayıtlarında bağlantı olmaz.", "Ayarlar → Genel → Arayüzün adresi")
    if not settings_store.get(db, "nvd_api_key"):
        add("info", "no_nvd_key", "NVD API anahtarı yok",
            "NVD indirmesi yavaş olur; CPE tabanlı (ürün) eşleştirme sınırlı kalır.",
            "nvd.nist.gov/developers adresinden ücretsiz anahtar alıp Ayarlar'a girin")
    order = {"crit": 0, "warn": 1, "info": 2}
    return sorted(out, key=lambda c: order[c["level"]])


def collect(db: Session) -> dict:
    cfg = get_config()
    now = _now()
    workers = [{"worker": w.worker, "last_seen": w.last_seen.isoformat() if w.last_seen else None,
                "current_job": w.current_job, "version": w.version,
                "alive": bool(w.last_seen and now - _aware(w.last_seen) < timedelta(seconds=60))}
               for w in db.query(WorkerStatus).filter(WorkerStatus.last_seen >= now - timedelta(hours=1))
               .order_by(WorkerStatus.last_seen.desc()).limit(20)]
    q = dict(db.query(Job.status, func.count(Job.id)).filter(Job.status.in_(("queued", "running")))
             .group_by(Job.status).all())
    failed = db.query(Job).filter(Job.status == "failed", Job.finished_at >= now - timedelta(hours=24)).count()
    du = shutil.disk_usage(cfg.data_dir)
    info = {
        "scakit": {"version": __version__, "python": platform.python_version(),
                   "python_impl": platform.python_implementation(), "platform": platform.platform()},
        "os": {k: v for k, v in os_info().items() if k != "release_text"},
        "database": database_info(db),
        "vulndb": vulndb_info(db),
        "workers": workers,
        "queue": {"queued": q.get("queued", 0), "running": q.get("running", 0), "failed_24h": failed},
        "disk": {"path": str(cfg.data_dir), "total": du.total, "free": du.free,
                 "uploads": _dir_size(cfg.uploads_dir), "scans": _dir_size(cfg.scans_dir)},
        "tools": tools(),
        "python_packages": python_packages(),
        "frontend": frontend_info(),
        "latest": _LATEST.get("result"),
    }
    info["checks"] = checks(db, info)
    return info


def selfscan(db: Session) -> dict:
    from ..matcher import SEVERITY_RANK, match_inventory
    from ..models import Component, Evidence
    from ..versions import compare
    from .pipeline import vulndb
    v = vulndb(db)
    py = python_packages()
    fe = frontend_info()["packages"]
    osp = os_packages()
    sig = (str(v.path), Path(v.path).stat().st_mtime if Path(v.path).exists() else 0,
           tuple((p["name"], p["version"]) for p in py), tuple((p["name"], p["version"]) for p in fe), len(osp))
    if _SELFSCAN.get("sig") == sig:
        return _SELFSCAN["result"]
    comps = []
    for p in py:
        if p["version"]:
            comps.append(Component("PyPI", p["name"], p["version"], direct=p["direct"],
                                   evidence=[Evidence("pkgdb", "python site-packages", "", "scakit-sunucu")]))
    for p in fe:
        comps.append(Component("npm", p["name"], p["version"], direct=p.get("direct"),
                               evidence=[Evidence("lockfile", "frontend/package-lock.json", "", "scakit-arayüz")]))
    comps += osp
    findings, _notes = match_inventory(comps, v)
    layer = {"PyPI": "Python", "npm": "Arayüz (npm)"}
    groups: dict[str, dict] = {}
    for f in findings:
        g = groups.setdefault(f.component_key, {
            "layer": layer.get(f.component_key.split("|")[0], "İşletim sistemi"),
            "component": f.component_key.split("|")[1], "version": f.component_key.split("|")[2],
            "ecosystem": f.component_key.split("|")[0], "count": 0, "max_severity": "UNKNOWN", "kev": False,
            "upgrade_to": "", "vulns": []})
        g["count"] += 1
        g["kev"] = g["kev"] or f.kev
        if SEVERITY_RANK.get(f.severity, 0) > SEVERITY_RANK.get(g["max_severity"], 0):
            g["max_severity"] = f.severity
        if f.upgrade_to:
            try:
                if not g["upgrade_to"] or compare(g["ecosystem"], f.upgrade_to, g["upgrade_to"]) > 0:
                    g["upgrade_to"] = f.upgrade_to
            except Exception:
                g["upgrade_to"] = g["upgrade_to"] or f.upgrade_to
        if len(g["vulns"]) < 15:
            g["vulns"].append({"id": f.vuln_id, "cves": [a for a in f.aliases if a.startswith("CVE-")][:3],
                               "severity": f.severity, "summary": f.summary[:200], "fixed": f.upgrade_to})
    items = sorted(groups.values(), key=lambda g: (g["layer"] == "İşletim sistemi", not g["kev"],
                                                    -SEVERITY_RANK.get(g["max_severity"], 0), -g["count"]))
    fixable = [g for g in items if g["upgrade_to"]]
    result = {"scanned_at": _now().isoformat(),
              "components": {"python": len(py), "frontend": len(fe), "os": len(osp)},
              "vulnerable": len(items), "fixable": len(fixable),
              "by_layer": {lay: sum(1 for g in items if g["layer"] == lay) for lay in
                           ("Python", "Arayüz (npm)", "İşletim sistemi")},
              "items": items[:400]}
    _SELFSCAN.update(sig=sig, result=result)
    return result


def _fetch_latest(kind: str, name: str) -> str | None:
    import requests
    url = f"https://pypi.org/pypi/{name}/json" if kind == "pypi" else f"https://registry.npmjs.org/{name}/latest"
    r = requests.get(url, timeout=10, headers={"User-Agent": "scakit-update-check"})
    if r.status_code != 200:
        return None
    j = r.json()
    return j["info"]["version"] if kind == "pypi" else j.get("version")


def _bump(eco: str, cur: str, new: str) -> str:
    from ..versions import compare
    try:
        if compare(eco, new, cur) <= 0:
            return "current"
    except Exception:
        if new == cur:
            return "current"
    a, b = cur.split("."), new.split(".")
    if a[0] != b[0]:
        return "major"
    if len(a) > 1 and len(b) > 1 and a[1] != b[1]:
        return "minor"
    return "patch"


def check_latest() -> dict:
    py = [p for p in python_packages() if p["direct"] and p["version"]]
    fe = [p for p in frontend_info()["packages"] if p.get("direct")]
    jobs = [("pypi", "PyPI", p["name"], p["version"]) for p in py] + [("npm", "npm", p["name"], p["version"]) for p in fe]

    def one(j):
        kind, eco, name, cur = j
        try:
            latest = _fetch_latest(kind, name)
        except Exception as ex:
            return {"layer": "Python" if kind == "pypi" else "Arayüz (npm)", "name": name, "current": cur,
                    "latest": None, "bump": "error", "error": str(ex)[:120]}
        return {"layer": "Python" if kind == "pypi" else "Arayüz (npm)", "name": name, "current": cur,
                "latest": latest, "bump": _bump(eco, cur, latest) if latest else "error"}

    with ThreadPoolExecutor(8) as ex:
        rows = list(ex.map(one, jobs))
    order = {"major": 0, "minor": 1, "patch": 2, "error": 3, "current": 4}
    rows.sort(key=lambda r: (order[r["bump"]], r["layer"], r["name"].lower()))
    result = {"checked_at": _now().isoformat(), "items": rows,
              "outdated": sum(r["bump"] in ("major", "minor", "patch") for r in rows)}
    _LATEST["result"] = result
    return result
