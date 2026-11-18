from __future__ import annotations

import json
import os
import re
import time
import zlib
from functools import cmp_to_key
from pathlib import Path

from ..cvss import severity_from_score
from ..models import Component, Finding
from ..versions import cpe_cmp

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

CPE_PRODUCTS = {
    "nginx": ["f5:nginx", "nginx:nginx"],
    "openresty": ["openresty:openresty"],
    "apache-httpd": ["apache:http_server"],
    "microsoft-iis": ["microsoft:internet_information_services"],
    "litespeed": ["litespeedtech:litespeed_web_server"],
    "apache-tomcat": ["apache:tomcat"],
    "apache-tomcat-coyote": ["apache:tomcat"],
    "wildfly": ["redhat:wildfly"],
    "jetty": ["eclipse:jetty"],
    "caddy": ["caddyserver:caddy"],
    "php": ["php:php"],
    "cpython": ["python:python"],
    "node.js": ["nodejs:node.js"],
    "openjdk": ["oracle:openjdk"],
    "ruby": ["ruby-lang:ruby"],
    "openssl": ["openssl:openssl"],
    "zlib": ["zlib:zlib"],
    "curl": ["haxx:curl"],
    "sqlite": ["sqlite:sqlite"],
    "libpng": ["libpng:libpng"],
    "libjpeg-turbo": ["libjpeg-turbo:libjpeg-turbo"],
    "mbedtls": ["arm:mbed_tls"],
    "sqlcipher": ["zetetic:sqlcipher"],
    "wordpress": ["wordpress:wordpress"],
    "drupal": ["drupal:drupal"],
    "redis": ["redis:redis"],
    "jenkins": ["jenkins:jenkins"],
    "confluence": ["atlassian:confluence_server", "atlassian:confluence_data_center"],
    "jira": ["atlassian:jira", "atlassian:jira_server", "atlassian:jira_data_center"],
    "postgresql": ["postgresql:postgresql"],
}
DISTRO_MARK = re.compile(r"\((?:Ubuntu|Debian|CentOS|Red Hat|RHEL|Fedora|Amazon|SUSE|Rocky|AlmaLinux|Raspbian)",
                         re.I)


def all_cpes() -> list[str]:
    return sorted({c for v in CPE_PRODUCTS.values() for c in v})


def cpe_file(cpe: str) -> str:
    return "nvd_" + re.sub(r"[^A-Za-z0-9]+", "_", cpe) + ".json"


def download_product(cpe: str, dest: Path, api_key: str | None = None, log=print) -> Path:
    import requests

    headers = {"apiKey": api_key} if api_key else {}
    delay = 0.8 if api_key else 6.5
    vulns, start = [], 0
    while True:
        for attempt in range(5):
            r = requests.get(API, params={"virtualMatchString": f"cpe:2.3:a:{cpe}", "resultsPerPage": 2000,
                                          "startIndex": start}, headers=headers, timeout=120)
            if r.status_code in (403, 429, 503):
                time.sleep(delay * (attempt + 2))
                continue
            r.raise_for_status()
            break
        doc = r.json()
        vulns += doc.get("vulnerabilities", [])
        start += doc.get("resultsPerPage", 0)
        time.sleep(delay)
        if start >= doc.get("totalResults", 0) or not doc.get("resultsPerPage"):
            break
    p = dest / cpe_file(cpe)
    p.write_text(json.dumps({"cpe": cpe, "vulnerabilities": vulns}))
    log(f"  NVD {cpe}: {len(vulns)} CVE")
    return p


def download_all(dest: str | Path, log=print) -> None:
    d = Path(dest)
    d.mkdir(parents=True, exist_ok=True)
    from .db import _fresh
    key = os.environ.get("NVD_API_KEY")
    for cpe in all_cpes():
        if _fresh(d / cpe_file(cpe), hours=24):
            continue
        try:
            download_product(cpe, d, key, log)
        except Exception as ex:
            log(f"  ! NVD {cpe} indirilemedi ({type(ex).__name__}); eski verisi kullanılır")


def import_dir(db, directory: str | Path, log=print) -> int:
    c = db.conn
    c.executescript("""
        CREATE TABLE IF NOT EXISTS nvd_cves (id TEXT PRIMARY KEY, data BLOB);
        CREATE TABLE IF NOT EXISTS nvd_products (cpe TEXT, cve TEXT);
        CREATE INDEX IF NOT EXISTS ix_nvd_products ON nvd_products (cpe);""")
    total = 0
    for p in sorted(Path(directory).glob("nvd_*.json")):
        doc = json.loads(p.read_text())
        cpe = doc["cpe"]
        c.execute("DELETE FROM nvd_products WHERE cpe = ?", (cpe,))
        for item in doc["vulnerabilities"]:
            cve = item["cve"]
            c.execute("INSERT OR REPLACE INTO nvd_cves VALUES (?,?)",
                      (cve["id"], zlib.compress(json.dumps(cve).encode(), 6)))
            c.execute("INSERT INTO nvd_products VALUES (?,?)", (cpe, cve["id"]))
        total += len(doc["vulnerabilities"])
    from .db import _now
    c.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", ("nvd", json.dumps({"updated": _now(), "count": total})))
    c.commit()
    log(f"  NVD: {total} CVE kaydı")
    return total


def _has_tables(db) -> bool:
    return db.conn.execute("SELECT 1 FROM sqlite_master WHERE name = 'nvd_cves'").fetchone() is not None


def _cpe_parts(criteria: str):
    p = criteria.split(":")
    return (p[3], p[4], p[5], p[6] if len(p) > 6 else "*") if len(p) > 5 else (None, None, None, None)


def _match_version(version: str, m: dict) -> bool:
    _, _, ver, upd = _cpe_parts(m["criteria"])
    if ver not in ("*", "-", ""):
        ver = ver.replace("\\", "")
        target = ver if upd in ("*", "-", "") else ver + upd
        return cpe_cmp(version, target) == 0
    if not any(k in m for k in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding",
                                "versionEndExcluding")):
        return False
    if "versionStartIncluding" in m and cpe_cmp(version, m["versionStartIncluding"]) < 0:
        return False
    if "versionStartExcluding" in m and cpe_cmp(version, m["versionStartExcluding"]) <= 0:
        return False
    if "versionEndIncluding" in m and cpe_cmp(version, m["versionEndIncluding"]) > 0:
        return False
    if "versionEndExcluding" in m and cpe_cmp(version, m["versionEndExcluding"]) >= 0:
        return False
    return True


def _metrics(cve: dict):
    mt = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        arr = mt.get(key) or []
        prim = next((x for x in arr if x.get("type") == "Primary"), arr[0] if arr else None)
        if prim:
            d = prim["cvssData"]
            score = d.get("baseScore")
            sev = d.get("baseSeverity") or prim.get("baseSeverity") or severity_from_score(score)
            return sev.upper(), score, d.get("vectorString", "")
    return "UNKNOWN", None, ""


def match_component(comp: Component, db) -> list[Finding]:
    cpes = CPE_PRODUCTS.get(comp.name.lower())
    if not cpes or not comp.version or not _has_tables(db):
        return []
    distro = any(DISTRO_MARK.search(e.detail or "") for e in comp.evidence)
    out = []
    ids = {r[0] for cpe in cpes for r in db.conn.execute("SELECT cve FROM nvd_products WHERE cpe = ?", (cpe,))}
    for cve_id in sorted(ids):
        row = db.conn.execute("SELECT data FROM nvd_cves WHERE id = ?", (cve_id,)).fetchone()
        if not row:
            continue
        cve = json.loads(zlib.decompress(row[0]))
        if cve.get("vulnStatus") == "Rejected":
            continue
        hit, and_cfg, fixes, incl = False, False, [], []
        for cfg in cve.get("configurations", []):
            for node in cfg.get("nodes", []):
                for m in node.get("cpeMatch", []):
                    if not m.get("vulnerable"):
                        continue
                    vendor, product, _, _ = _cpe_parts(m["criteria"])
                    if f"{vendor}:{product}" not in cpes:
                        continue
                    if _match_version(comp.version, m):
                        hit = True
                        and_cfg = and_cfg or cfg.get("operator") == "AND"
                        if "versionEndExcluding" in m:
                            fixes.append(m["versionEndExcluding"])
                        elif "versionEndIncluding" in m:
                            incl.append(m["versionEndIncluding"])
        if not hit:
            continue
        sev, score, vector = _metrics(cve)
        desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        conf = "low" if distro else ("medium" if and_cfg or comp.confidence != "high" else "high")
        fixes = sorted(set(fixes), key=cmp_to_key(cpe_cmp))
        newer = [f for f in fixes if cpe_cmp(f, comp.version) > 0]
        if not newer and incl:
            newer = ["> " + sorted(incl, key=cmp_to_key(cpe_cmp))[-1]]
        out.append(Finding(
            vuln_id=cve_id, component_key=comp.key, component_purl=comp.purl, summary=desc[:300],
            severity=sev if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "UNKNOWN", cvss_score=score,
            cvss_vector=vector, fixed_versions=fixes, upgrade_to=newer[0] if newer else "",
            references=[r["url"] for r in cve.get("references", [])][:6], confidence=conf,
            published=cve.get("published", "")[:10], source="NVD",
        ))
    return out
