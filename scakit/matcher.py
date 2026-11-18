from __future__ import annotations

import re

from .cvss import cvss3_base_score, severity_from_score
from .models import Component, Finding, base_ecosystem, normalize_name
from .versions import comparator, sort_key

RPM_FAMILY = {"Red Hat", "Rocky Linux", "AlmaLinux"}
_LABEL = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MODERATE": "MEDIUM", "MEDIUM": "MEDIUM", "LOW": "LOW"}
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0, "UNKNOWN": 0}


def _eco_matches(comp_eco: str, osv_eco: str) -> bool:
    if base_ecosystem(comp_eco) != base_ecosystem(osv_eco):
        return False
    if ":" in comp_eco and ":" in osv_eco:
        if base_ecosystem(comp_eco) in RPM_FAMILY:
            ca = re.search(r"\d+", comp_eco.split(":", 1)[1])
            oa = re.search(r"\d+", osv_eco.split(":", 1)[1])
            return bool(ca and oa and ca.group() == oa.group())
        return comp_eco.split(":", 1)[1] == osv_eco.split(":", 1)[1]
    return True


def _in_range(version: str, ecosystem: str, rng: dict) -> bool:
    rtype = rng.get("type", "ECOSYSTEM")
    if rtype == "GIT":
        return False
    cmp = comparator(ecosystem, rtype)
    events = []
    for ev in rng.get("events", []):
        for kind in ("introduced", "fixed", "last_affected", "limit"):
            if kind in ev:
                events.append((kind, ev[kind]))
    if not events:
        return False
    zero = lambda v: v in ("0", "")
    key = sort_key(ecosystem, rtype)

    def ev_key(e):
        return (0, "") if zero(e[1]) else (1, key(e[1]))

    try:
        events.sort(key=lambda e: ev_key(e))
    except TypeError:
        pass
    affected = False
    for kind, val in events:
        if kind == "introduced":
            if zero(val) or cmp(version, val) >= 0:
                affected = True
        elif kind == "fixed":
            if cmp(version, val) >= 0:
                affected = False
        elif kind == "last_affected":
            if cmp(version, val) > 0:
                affected = False
        elif kind == "limit":
            if cmp(version, val) >= 0:
                affected = False
    return affected


def affected_entry(comp: Component, vuln: dict) -> dict | None:
    if vuln.get("withdrawn"):
        return None
    name = normalize_name(comp.ecosystem, comp.name)
    for aff in vuln.get("affected", []):
        pkg = aff.get("package") or {}
        if not _eco_matches(comp.ecosystem, pkg.get("ecosystem", "")):
            continue
        if normalize_name(pkg.get("ecosystem", ""), pkg.get("name", "")) != name:
            continue
        versions = aff.get("versions") or []
        if comp.version in versions:
            return aff
        eco = pkg.get("ecosystem", comp.ecosystem)
        for rng in aff.get("ranges", []):
            if _in_range(comp.version, eco, rng):
                return aff
    return None


def _severity(vuln: dict, aff: dict) -> tuple[str, float | None, str]:
    vectors = [s for s in (vuln.get("severity") or []) + (aff.get("severity") or []) if s.get("score")]
    for s in vectors:
        if s.get("type") == "CVSS_V3":
            score = cvss3_base_score(s["score"])
            if score is not None:
                return severity_from_score(score), score, s["score"]
    label = (vuln.get("database_specific") or {}).get("severity") or \
        (aff.get("ecosystem_specific") or {}).get("severity") or \
        (aff.get("database_specific") or {}).get("severity")
    vec = next((s["score"] for s in vectors), "")
    if isinstance(label, str) and label.upper() in _LABEL:
        return _LABEL[label.upper()], None, vec
    return "UNKNOWN", None, vec


def _severity_from_upstream(cves: list[str], db) -> tuple[str, float | None, str]:
    best = ("UNKNOWN", None, "")
    for cve in cves[:40]:
        for s in db.vectors_for_alias(cve):
            if s.get("type") == "CVSS_V3":
                score = cvss3_base_score(s.get("score", ""))
                if score is not None and (best[1] is None or score > best[1]):
                    best = (severity_from_score(score), score, s["score"])
    return best


def _fixed_versions(aff: dict, ecosystem: str) -> list[str]:
    fixed = []
    for rng in aff.get("ranges", []):
        if rng.get("type") == "GIT":
            continue
        for ev in rng.get("events", []):
            fv = ev.get("fixed")
            if fv and base_ecosystem(ecosystem) in RPM_FAMILY and fv.startswith("0:"):
                fv = fv[2:]
            if fv and fv not in fixed:
                fixed.append(fv)
    try:
        fixed.sort(key=sort_key(ecosystem))
    except TypeError:
        pass
    return fixed


def _cves(vuln: dict) -> list[str]:
    ids = [vuln["id"]] + vuln.get("aliases", []) + vuln.get("upstream", [])
    return sorted({i for i in ids if i.startswith("CVE-")})


def match_inventory(components: list[Component], db, log=None, go_calls: dict | None = None
                    ) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    notes = {"unversioned": 0, "no_db_coverage": set(), "matched_components": 0, "resolved_groupids": 0}
    for comp in components:
        if not comp.version:
            notes["unversioned"] += 1
            continue
        eco = base_ecosystem(comp.ecosystem)
        if eco == "generic":
            from .vulndb import nvd
            if comp.name.lower() in nvd.CPE_PRODUCTS and nvd._has_tables(db):
                nf = nvd.match_component(comp, db)
                findings += nf
                notes["matched_components"] += bool(nf)
                notes["nvd_components"] = notes.get("nvd_components", 0) + 1
            else:
                notes["no_db_coverage"].add(eco)
            continue
        if eco == "CocoaPods":
            notes["no_db_coverage"].add(eco)
            continue
        if not db.has_ecosystem(eco):
            notes["no_db_coverage"].add(eco)
            continue
        candidates = [comp]
        if eco == "Maven" and ":" not in comp.name:
            names = db.maven_names_for_artifact(comp.name)
            candidates = [Component(comp.ecosystem, n, comp.version, confidence="medium") for n in names]
            notes["resolved_groupids"] += bool(names)
        hit = False
        for cand in candidates:
            for vuln in db.vulns_for(cand.ecosystem, cand.name):
                aff = affected_entry(cand, vuln)
                if aff is None:
                    continue
                hit = True
                sev, score, vector = _severity(vuln, aff)
                upstream = [u for u in vuln.get("upstream", []) if u.startswith("CVE-")]
                if sev == "UNKNOWN" and upstream:
                    sev, score, vector = _severity_from_upstream(upstream, db)
                malicious = vuln["id"].startswith("MAL-")
                if malicious:
                    sev = "CRITICAL"
                conf = comp.confidence if cand is comp else "medium"
                reach = ""
                if eco == "Go" and go_calls:
                    from .usage import go_reachability
                    reach = go_reachability(vuln, cand, go_calls)
                findings.append(Finding(
                    vuln_id=vuln["id"], component_key=comp.key, component_purl=comp.purl,
                    aliases=sorted(set(vuln.get("aliases", []) + upstream) - {vuln["id"]}),
                    summary=vuln.get("summary") or (vuln.get("details") or "")[:300],
                    severity=sev, cvss_score=score, cvss_vector=vector,
                    fixed_versions=_fixed_versions(aff, cand.ecosystem),
                    references=[r["url"] for r in vuln.get("references", []) if r.get("url")][:8],
                    malicious=malicious, confidence=conf, published=vuln.get("published", "")[:10],
                    reachability=reach,
                ))
        notes["matched_components"] += hit
    findings = _dedupe(findings)
    by_key = {c.key: c for c in components}
    for f in findings:
        c = by_key.get(f.component_key)
        if c is None or f.source == "NVD":
            continue
        cmp = comparator(c.ecosystem)
        try:
            f.fixed_versions.sort(key=sort_key(c.ecosystem))
        except TypeError:
            pass
        newer = [v for v in f.fixed_versions if cmp(v, c.version) > 0]
        f.upgrade_to = newer[0] if newer else ""
    enrich(findings, db)
    notes["no_db_coverage"] = sorted(notes["no_db_coverage"])
    return findings, notes


def _dedupe(findings: list[Finding]) -> list[Finding]:
    out: dict[tuple, Finding] = {}
    for f in findings:
        ids = {f.vuln_id, *f.aliases}
        merged = None
        for k, existing in out.items():
            if k[0] == f.component_key and ids & ({existing.vuln_id, *existing.aliases}):
                merged = existing
                break
        if merged is None:
            out[(f.component_key, f.vuln_id)] = f
            continue
        reach = "called" if "called" in (f.reachability, merged.reachability) else (f.reachability or merged.reachability)
        f.reachability = merged.reachability = reach
        if f.vuln_id.startswith("GHSA-") and not merged.vuln_id.startswith("GHSA-"):
            f.aliases = sorted(({merged.vuln_id, *merged.aliases, *f.aliases}) - {f.vuln_id})
            for k, v in list(out.items()):
                if v is merged:
                    out[k] = f
        else:
            merged.aliases = sorted(({*merged.aliases, *ids}) - {merged.vuln_id})
            if SEVERITY_RANK[f.severity] > SEVERITY_RANK[merged.severity] and merged.cvss_score is None:
                merged.severity, merged.cvss_score, merged.cvss_vector = f.severity, f.cvss_score, f.cvss_vector
            for fv in f.fixed_versions:
                if fv not in merged.fixed_versions:
                    merged.fixed_versions.append(fv)
    return list(out.values())


def enrich(findings: list[Finding], db) -> None:
    for f in findings:
        cves = sorted({i for i in [f.vuln_id, *f.aliases] if i.startswith("CVE-")})
        best = None
        for cve in cves:
            e = db.epss_for(cve)
            if e and (best is None or e[0] > best[0]):
                best = e
            k = db.kev_for(cve)
            if k:
                f.kev = True
                f.kev_ransomware = f.kev_ransomware or bool(k[1])
        if best:
            f.epss, f.epss_percentile = best


def priority_key(f: Finding):
    return (not f.malicious, not f.kev, -SEVERITY_RANK.get(f.severity, 0), f.reachability != "called",
            -(f.epss or 0), -(f.cvss_score or 0))
