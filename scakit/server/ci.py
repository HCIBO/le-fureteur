from __future__ import annotations

import hashlib
import json
from pathlib import Path

from sqlalchemy.orm import Session

from .. import PRODUCT_NAME, __version__
from ..matcher import SEVERITY_RANK
from .models import Finding, Project, Scan

ACTIVE = ("open", "in_progress")
DEFAULT_POLICY = {"fail_on": "HIGH", "fail_on_kev": True, "fail_on_malicious": True, "fail_on_license": False,
                  "new_only": False}
SEV_CHOICES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE")


def clean_policy(d: dict | None) -> dict:
    out = {}
    for k, v in (d or {}).items():
        if k not in DEFAULT_POLICY or v is None or v == "":
            continue
        if k == "fail_on":
            v = str(v).upper()
            if v not in SEV_CHOICES:
                raise ValueError(f"fail_on: {', '.join(SEV_CHOICES)}")
        else:
            v = v if isinstance(v, bool) else str(v).strip().lower() in ("1", "true", "yes", "on")
        out[k] = v
    return out


def effective_policy(project: Project, overrides: dict | None = None) -> dict:
    return {**DEFAULT_POLICY, **clean_policy(project.ci_policy), **clean_policy(overrides)}


def _scan_findings(db: Session, scan: Scan, new_only: bool) -> list[Finding]:
    q = db.query(Finding).filter(Finding.target_id == scan.target_id, Finding.status.in_(ACTIVE),
                                 Finding.last_seen_scan == scan.id)
    rows = q.all()
    if new_only:
        rows = [f for f in rows if f.first_seen_scan == scan.id or f.reopened_scan == scan.id]
    return rows


def _denied_licenses(scan: Scan, project: Project) -> list[dict]:
    from ..engagement import Engagement
    from ..licenses import evaluate
    if not scan.workdir:
        return []
    eng = Engagement(Path(scan.workdir) / "eng")
    lp = project.license_policy or {}
    policy = {k: {x.lower() for x in lp.get(k, [])} for k in ("allowed", "review", "denied")}
    policy["custom"] = any(lp.get(k) for k in ("allowed", "review", "denied"))
    return [{"component": r["component"].name, "version": r["component"].version, "licenses": r["spdx"]}
            for r in evaluate(eng.inventory.sorted_components(), policy) if r["decision"] == "denied"]


def evaluate_gate(db: Session, scan: Scan, overrides: dict | None = None) -> dict:
    project = scan.target.project
    pol = effective_policy(project, overrides)
    rows = _scan_findings(db, scan, pol["new_only"])
    reasons = []
    if pol["fail_on"] != "NONE":
        thr = SEVERITY_RANK[pol["fail_on"]]
        hit = [f for f in rows if SEVERITY_RANK.get(f.severity, 0) >= thr]
        if hit:
            reasons.append({"rule": "severity", "threshold": pol["fail_on"], "count": len(hit)})
    if pol["fail_on_kev"] and (n := sum(f.kev for f in rows)):
        reasons.append({"rule": "kev", "count": n})
    if pol["fail_on_malicious"] and (n := sum(f.malicious for f in rows)):
        reasons.append({"rule": "malicious", "count": n})
    denied = _denied_licenses(scan, project) if pol["fail_on_license"] else []
    if denied:
        reasons.append({"rule": "license", "count": len(denied), "items": denied[:20]})
    sev = {}
    for f in rows:
        sev[f.severity] = sev.get(f.severity, 0) + 1
    return {"passed": not reasons, "reasons": reasons, "policy": pol,
            "counts": {"findings": len(rows), "severity": sev, "kev": sum(f.kev for f in rows),
                       "malicious": sum(f.malicious for f in rows)}}


LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "UNKNOWN": "warning"}
FILE_METHODS = {"lockfile", "manifest", "pkgdb", "jar-meta", "properties", "installed-package", "sbom",
                "command-output", "image-config"}


def _location(f: Finding) -> str:
    for e in f.evidence or []:
        loc = (e.get("location") or "").split("!")[0].lstrip("./")
        if e.get("method") in FILE_METHODS and loc and "://" not in loc:
            return loc
    for e in f.evidence or []:
        if e.get("location"):
            return e["location"].split("!")[0]
    return "dependencies"


def sarif(db: Session, scan: Scan, public_url: str = "") -> dict:
    rows = _scan_findings(db, scan, new_only=False)
    rules, results, seen = [], [], set()
    for f in sorted(rows, key=lambda f: (-SEVERITY_RANK.get(f.severity, 0), f.vuln_id)):
        cves = [a for a in (f.aliases or []) if a.startswith("CVE-")]
        if f.vuln_id not in seen:
            seen.add(f.vuln_id)
            rules.append({
                "id": f.vuln_id,
                "name": (cves[0] if cves else f.vuln_id).replace("-", ""),
                "shortDescription": {"text": (f.summary or f.vuln_id)[:250]},
                "helpUri": f"https://osv.dev/vulnerability/{f.vuln_id}",
                "help": {"text": f"{f.summary or ''}\nAliases: {', '.join(f.aliases or []) or '-'}"},
                "properties": {"tags": ["security", "sca", "dependency"] + (["kev"] if f.kev else []),
                               "security-severity": str(f.cvss if f.cvss is not None else
                                                        {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.5, "LOW": 2.0}
                                                        .get(f.severity, 5.0))},
            })
        fix = f" Upgrade to {f.upgrade_to}." if f.upgrade_to else " No fixed version yet."
        msg = f"{f.component} {f.version} ({f.ecosystem}) is affected by {cves[0] if cves else f.vuln_id}" \
              f" [{f.severity}{', KEV' if f.kev else ''}].{fix}"
        fp = hashlib.sha256(f"{scan.target_id}|{f.component_key}|{f.vuln_id}".encode()).hexdigest()[:32]
        res = {"ruleId": f.vuln_id, "level": LEVEL.get(f.severity, "warning"), "message": {"text": msg},
               "locations": [{"physicalLocation": {"artifactLocation": {"uri": _location(f)},
                                                   "region": {"startLine": 1}}}],
               "partialFingerprints": {"leFureteurFinding/v1": fp},
               "properties": {"component": f.component, "version": f.version, "purl": f.purl,
                              "epss": f.epss, "kev": f.kev, "fixed": f.upgrade_to}}
        results.append(res)
    driver = {"name": PRODUCT_NAME, "version": __version__, "semanticVersion": __version__, "rules": rules}
    if public_url:
        driver["informationUri"] = public_url.rstrip("/") + "/guide"
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": driver}, "results": results,
                      "automationDetails": {"id": f"le-fureteur/{scan.target.project.name}/{scan.target.name}/"}}]}


def sarif_json(db: Session, scan: Scan, public_url: str = "") -> str:
    return json.dumps(sarif(db, scan, public_url), ensure_ascii=False, indent=1)
