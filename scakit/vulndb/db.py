from __future__ import annotations

import csv
import gzip
import io
import json
import re
import os
import sqlite3
import zipfile
import zlib
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from ..models import base_ecosystem, normalize_name

OSV_URL = "https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip"
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

APP_ECOSYSTEMS = ["npm", "PyPI", "Maven", "Go", "NuGet", "Packagist", "crates.io", "RubyGems", "Pub",
                  "SwiftURL"]
OS_ECOSYSTEMS = ["Debian", "Alpine", "Red Hat", "Rocky Linux", "AlmaLinux"]
OPTIONAL_ECOSYSTEMS = ["Ubuntu", "Wolfi", "Chainguard", "SUSE"]
DEFAULT_ECOSYSTEMS = APP_ECOSYSTEMS + OS_ECOSYSTEMS

SCHEMA = """
CREATE TABLE IF NOT EXISTS vulns (id TEXT PRIMARY KEY, modified TEXT, data BLOB);
CREATE TABLE IF NOT EXISTS affected (eco TEXT, eco_full TEXT, name TEXT, vuln_id TEXT);
CREATE INDEX IF NOT EXISTS ix_affected ON affected (eco, name);
CREATE INDEX IF NOT EXISTS ix_affected_vuln ON affected (vuln_id);
CREATE TABLE IF NOT EXISTS aliases (vuln_id TEXT, alias TEXT);
CREATE INDEX IF NOT EXISTS ix_alias ON aliases (alias);
CREATE INDEX IF NOT EXISTS ix_alias_vuln ON aliases (vuln_id);
CREATE TABLE IF NOT EXISTS epss (cve TEXT PRIMARY KEY, score REAL, percentile REAL);
CREATE TABLE IF NOT EXISTS kev (cve TEXT PRIMARY KEY, date_added TEXT, ransomware INTEGER, name TEXT);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""


def default_db_path() -> Path:
    env = os.environ.get("SCAKIT_DB")
    if env:
        return Path(env)
    return Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "scakit" / "vulndb.sqlite"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class VulnDB:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else default_db_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, timeout=60)
        try:
            if self.conn.execute("PRAGMA journal_mode").fetchone()[0].lower() != "wal":
                try:
                    self.conn.execute("PRAGMA journal_mode=WAL")
                except sqlite3.OperationalError:
                    pass
            have = {r[0] for r in self.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if not set(re.findall(r"CREATE TABLE IF NOT EXISTS (\w+)", SCHEMA)) <= have:
                self.conn.executescript(SCHEMA)
        except sqlite3.OperationalError as ex:
            if "locked" in str(ex):
                raise RuntimeError("Zafiyet veritabanı şu anda güncelleniyor (kilitli); güncelleme bitince tekrar deneyin") from ex
            raise

    def close(self):
        self.conn.close()

    def import_osv_zip(self, source, label: str) -> int:
        zf = zipfile.ZipFile(io.BytesIO(source) if isinstance(source, bytes) else source)
        cur = self.conn.cursor()
        n = 0
        batch_v, batch_a, batch_al = [], [], []
        for info in zf.infolist():
            if not info.filename.endswith(".json"):
                continue
            raw = zf.read(info)
            try:
                v = json.loads(raw)
            except ValueError:
                continue
            vid = v.get("id")
            if not vid:
                continue
            batch_v.append((vid, v.get("modified", ""), zlib.compress(raw, 6)))
            cur.execute("DELETE FROM affected WHERE vuln_id = ?", (vid,))
            cur.execute("DELETE FROM aliases WHERE vuln_id = ?", (vid,))
            seen = set()
            for aff in v.get("affected", []):
                pkg = aff.get("package") or {}
                eco_full, name = pkg.get("ecosystem", ""), pkg.get("name", "")
                if not eco_full or not name:
                    continue
                row = (base_ecosystem(eco_full), eco_full, normalize_name(eco_full, name), vid)
                if row not in seen:
                    seen.add(row)
                    batch_a.append(row)
            for al in set([vid] + v.get("aliases", []) + v.get("upstream", [])):
                batch_al.append((vid, al))
            n += 1
            if len(batch_v) >= 2000:
                self._flush(cur, batch_v, batch_a, batch_al)
        self._flush(cur, batch_v, batch_a, batch_al)
        self._set_meta(f"osv:{label}", json.dumps({"updated": _now(), "count": n}))
        self.conn.commit()
        return n

    @staticmethod
    def _flush(cur, bv, ba, bal):
        cur.executemany("INSERT OR REPLACE INTO vulns VALUES (?,?,?)", bv)
        cur.executemany("INSERT INTO affected VALUES (?,?,?,?)", ba)
        cur.executemany("INSERT INTO aliases VALUES (?,?)", bal)
        bv.clear()
        ba.clear()
        bal.clear()

    def import_epss(self, source) -> int:
        data = source if isinstance(source, bytes) else Path(source).read_bytes()
        if data[:2] == b"\x1f\x8b":
            data = gzip.decompress(data)
        rows = []
        model = ""
        reader = csv.reader(io.StringIO(data.decode("utf-8", "replace")))
        for rec in reader:
            if not rec:
                continue
            if rec[0].startswith("#"):
                model = ",".join(rec).lstrip("#")
                continue
            if rec[0] == "cve":
                continue
            try:
                rows.append((rec[0], float(rec[1]), float(rec[2])))
            except (IndexError, ValueError):
                continue
        self.conn.execute("DELETE FROM epss")
        self.conn.executemany("INSERT OR REPLACE INTO epss VALUES (?,?,?)", rows)
        self._set_meta("epss", json.dumps({"updated": _now(), "count": len(rows), "model": model}))
        self.conn.commit()
        return len(rows)

    def import_kev(self, source) -> int:
        data = source if isinstance(source, bytes) else Path(source).read_bytes()
        doc = json.loads(data)
        rows = [(v["cveID"], v.get("dateAdded", ""),
                 1 if str(v.get("knownRansomwareCampaignUse", "")).lower() == "known" else 0,
                 v.get("vulnerabilityName", "")) for v in doc.get("vulnerabilities", [])]
        self.conn.execute("DELETE FROM kev")
        self.conn.executemany("INSERT OR REPLACE INTO kev VALUES (?,?,?,?)", rows)
        self._set_meta("kev", json.dumps({"updated": _now(), "count": len(rows),
                                          "catalog": doc.get("catalogVersion", "")}))
        self.conn.commit()
        return len(rows)

    def _set_meta(self, key, value):
        self.conn.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (key, value))

    def meta(self) -> dict:
        return {k: json.loads(v) for k, v in self.conn.execute("SELECT key, value FROM meta")}

    def vulns_for(self, ecosystem: str, name: str):
        eco = base_ecosystem(ecosystem)
        sql = "SELECT DISTINCT a.vuln_id FROM affected a WHERE a.eco = ? AND a.name = ?"
        args = [eco, normalize_name(ecosystem, name)]
        if ":" in ecosystem and eco not in ("Red Hat", "Rocky Linux", "AlmaLinux"):
            sql += " AND (a.eco_full = ? OR a.eco_full = a.eco OR a.eco_full IS NULL)"
            args.append(ecosystem)
        ids = [r[0] for r in self.conn.execute(sql, args)]
        for vid in ids:
            row = self.conn.execute("SELECT data FROM vulns WHERE id = ?", (vid,)).fetchone()
            if row:
                yield json.loads(zlib.decompress(row[0]))

    def vectors_for_alias(self, alias: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT v.data FROM aliases a JOIN vulns v ON v.id = a.vuln_id WHERE a.alias = ? LIMIT 6",
            (alias,)).fetchall()
        out = []
        for r in rows:
            d = json.loads(zlib.decompress(r[0]))
            out += d.get("severity") or []
        return out

    def maven_names_for_artifact(self, artifact: str) -> list[str]:
        rows = self.conn.execute("SELECT DISTINCT name FROM affected WHERE eco = 'Maven' AND name LIKE ?",
                                 ("%:" + artifact,)).fetchall()
        return [r[0] for r in rows if r[0].split(":", 1)[-1] == artifact]

    def epss_for(self, cve: str):
        return self.conn.execute("SELECT score, percentile FROM epss WHERE cve = ?", (cve,)).fetchone()

    def kev_for(self, cve: str):
        return self.conn.execute("SELECT date_added, ransomware, name FROM kev WHERE cve = ?", (cve,)).fetchone()

    def has_ecosystem(self, ecosystem: str) -> bool:
        return self.conn.execute("SELECT 1 FROM affected WHERE eco = ? LIMIT 1",
                                 (base_ecosystem(ecosystem),)).fetchone() is not None

    def stats(self) -> dict:
        c = self.conn
        return {
            "vulns": c.execute("SELECT COUNT(*) FROM vulns").fetchone()[0],
            "by_ecosystem": dict(c.execute("SELECT eco, COUNT(DISTINCT vuln_id) FROM affected GROUP BY eco")),
            "epss": c.execute("SELECT COUNT(*) FROM epss").fetchone()[0],
            "kev": c.execute("SELECT COUNT(*) FROM kev").fetchone()[0],
        }


FRESH_HOURS = 6


def _fresh(p: Path, hours: float = FRESH_HOURS) -> bool:
    import time
    return p.exists() and p.stat().st_size > 0 and (time.time() - p.stat().st_mtime) < hours * 3600


def _download(url: str, dest: Path, log=print, retries: int = 6) -> Path:
    import time

    import requests

    dest.parent.mkdir(parents=True, exist_ok=True)
    if _fresh(dest):
        log(f"  güncel (atlandı): {dest.name}")
        return dest
    tmp = dest.with_suffix(dest.suffix + ".part")
    tag = dest.with_suffix(dest.suffix + ".part-etag")
    for attempt in range(1, retries + 1):
        have = tmp.stat().st_size if tmp.exists() else 0
        validator = tag.read_text().strip() if have and tag.exists() else ""
        if have and not validator:
            tmp.unlink()
            have = 0
        headers = {"Range": f"bytes={have}-", "If-Range": validator} if have else {}
        try:
            with requests.get(url, stream=True, timeout=(30, 120), headers=headers) as r:
                if r.status_code == 416:
                    break
                r.raise_for_status()
                mode = "ab" if have and r.status_code == 206 else "wb"
                v = r.headers.get("ETag") or r.headers.get("Last-Modified") or ""
                if mode == "wb":
                    if v and not v.startswith("W/"):
                        tag.write_text(v)
                    else:
                        tag.unlink(missing_ok=True)
                with open(tmp, mode) as f:
                    for chunk in r.iter_content(1 << 20):
                        f.write(chunk)
            break
        except (requests.RequestException, OSError) as ex:
            got = tmp.stat().st_size / 1048576 if tmp.exists() else 0
            if attempt == retries:
                raise
            log(f"  ! {dest.name}: bağlantı koptu ({type(ex).__name__}), {got:.0f} MB inmişti; "
                f"yeniden deneniyor ({attempt}/{retries - 1})")
            time.sleep(min(5 * attempt, 30))
    tag.unlink(missing_ok=True)
    if dest.suffix == ".zip" and not _zip_ok(tmp):
        tmp.unlink(missing_ok=True)
        if retries > 1:
            log(f"  ! {dest.name} bozuk indi (CRC); baştan yeniden indiriliyor")
            return _download(url, dest, log, retries=1)
        raise OSError(f"{dest.name} bozuk indi")
    tmp.replace(dest)
    log(f"  indirildi: {dest.name} ({dest.stat().st_size / 1048576:.1f} MB)")
    return dest


def _zip_ok(path: Path) -> bool:
    try:
        with zipfile.ZipFile(path) as zf:
            return zf.testzip() is None
    except (zipfile.BadZipFile, OSError, EOFError):
        return False


def osv_filename(eco: str) -> str:
    return f"osv_{eco.replace(' ', '_').replace('.', '_')}.zip"


def download_all(directory: str | Path, ecosystems=None, log=print, nvd: bool = True) -> Path:
    d = Path(directory)
    if nvd:
        from . import nvd as nvdmod
        log("  NVD ürün verisi indiriliyor (API anahtarı yoksa birkaç dakika sürer; NVD_API_KEY ile hızlanır)")
        nvdmod.download_all(d, log)
    failed = []
    jobs = [(OSV_URL.format(eco=quote(eco)), osv_filename(eco)) for eco in ecosystems or DEFAULT_ECOSYSTEMS]
    jobs += [(EPSS_URL, "epss_scores-current.csv.gz"), (KEV_URL, "known_exploited_vulnerabilities.json")]
    for url, name in jobs:
        try:
            _download(url, d / name, log)
        except Exception as ex:
            failed.append(name)
            log(f"  ! {name} indirilemedi: {type(ex).__name__}")
    (d / "ecosystems.json").write_text(json.dumps(ecosystems or DEFAULT_ECOSYSTEMS))
    if failed:
        log(f"  UYARI: {len(failed)} kaynak indirilemedi ({', '.join(failed)}). Eski verisi (varsa) kullanılır; "
            f"komutu tekrar çalıştırın — inen dosyalar atlanır, yarım kalan kaldığı yerden devam eder.")
    return d


def update_from_dir(db: VulnDB, directory: str | Path, log=print) -> None:
    d = Path(directory)
    ecos = json.loads((d / "ecosystems.json").read_text()) if (d / "ecosystems.json").exists() else None
    done = db.meta()
    failed: list[str] = []
    for z in sorted(d.glob("osv_*.zip")):
        label = next((e for e in (ecos or DEFAULT_ECOSYSTEMS) if osv_filename(e) == z.name), z.stem[4:])
        sig = f"{z.stat().st_size}:{int(z.stat().st_mtime)}"
        if (done.get(f"file:{z.name}") or {}).get("sig") == sig:
            log(f"  OSV {label}: değişmemiş (içe aktarma atlandı)")
            continue
        try:
            n = db.import_osv_zip(str(z), label)
        except (zipfile.BadZipFile, EOFError, OSError) as ex:
            db.conn.rollback()
            z.unlink(missing_ok=True)
            log(f"  ! OSV {label}: arşiv bozuk ({type(ex).__name__}); atlandı, sonraki güncellemede yeniden indirilecek")
            failed.append(label)
            continue
        db._set_meta(f"file:{z.name}", json.dumps({"sig": sig}))
        db.conn.commit()
        log(f"  OSV {label}: {n} kayıt")
    if (d / "epss_scores-current.csv.gz").exists():
        log(f"  EPSS: {db.import_epss(d / 'epss_scores-current.csv.gz')} CVE")
    if (d / "known_exploited_vulnerabilities.json").exists():
        log(f"  KEV: {db.import_kev(d / 'known_exploited_vulnerabilities.json')} CVE")
    if any(d.glob("nvd_*.json")):
        from . import nvd as nvdmod
        nvdmod.import_dir(db, d, log)
    if failed:
        log(f"  UYARI: {len(failed)} OSV kaynağı bozuk olduğu için atlandı ({', '.join(failed)}); diğerleri güncellendi")


def update_online(db: VulnDB, ecosystems=None, cache_dir: str | Path | None = None, log=print,
                  nvd: bool = True) -> None:
    cache = Path(cache_dir) if cache_dir else db.path.parent / "downloads"
    download_all(cache, ecosystems, log, nvd=nvd)
    update_from_dir(db, cache, log)
