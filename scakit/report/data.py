from __future__ import annotations

from collections import Counter, defaultdict

from ..matcher import SEVERITY_RANK, priority_key
from ..models import base_ecosystem
from ..versions import sort_key

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def build(engagement, findings, fdoc: dict) -> dict:
    inv = engagement.inventory
    comps = {c.key: c for c in inv.components.values()}
    findings = sorted(findings, key=priority_key)

    sev = Counter(f.severity if f.severity in SEVERITIES else "UNKNOWN" for f in findings)
    affected_keys = {f.component_key for f in findings}

    plan = []
    by_comp = defaultdict(list)
    for f in findings:
        by_comp[f.component_key].append(f)
    for key, fs in by_comp.items():
        c = comps.get(key)
        if c is None:
            continue
        targets = [f.upgrade_to for f in fs if f.upgrade_to]
        target = ""
        if targets:
            try:
                target = sorted(set(targets), key=sort_key(c.ecosystem))[-1]
            except TypeError:
                target = targets[-1]
        unfixed = sum(1 for f in fs if not f.upgrade_to)
        plan.append({
            "component": c, "findings": fs, "target": target, "unfixed": unfixed,
            "kev": sum(f.kev for f in fs), "malicious": any(f.malicious for f in fs),
            "max_sev": max((f.severity for f in fs), key=lambda s: SEVERITY_RANK.get(s, 0)),
            "max_epss": max((f.epss or 0) for f in fs),
            "counts": Counter(f.severity for f in fs),
        })
    plan.sort(key=lambda p: (not p["malicious"], -p["kev"], -SEVERITY_RANK.get(p["max_sev"], 0),
                             -p["max_epss"], -len(p["findings"])))

    notes = fdoc.get("notes", {})
    unversioned = [c for c in inv.components.values() if not c.version]
    estimated = [c for c in inv.components.values() if c.version and (c.version_estimated or c.confidence != "high")]
    no_cov = [c for c in inv.components.values() if base_ecosystem(c.ecosystem) in set(notes.get("no_db_coverage", []))
              and c.version]
    eco_counts = Counter(base_ecosystem(c.ecosystem) for c in inv.components.values())
    methods = Counter()
    for c in inv.components.values():
        for e in c.evidence:
            methods[e.method] += 1
    blackbox = any(r.get("kind") in ("web", "apk", "ipa", "desktop") for r in inv.runs)
    direct = [c for c in inv.components.values() if c.direct and c.usage]
    usage = {"imported": sum(c.usage == "imported" for c in direct),
             "not-imported": sum(c.usage == "not-imported" for c in direct),
             "not_imported_list": sorted((c for c in direct if c.usage == "not-imported"), key=lambda c: c.name)}
    reach = {"called": sum(f.reachability == "called" for f in findings),
             "not-called": sum(f.reachability == "not-called" for f in findings)}
    nvd = sum(f.source == "NVD" for f in findings)
    from ..licenses import evaluate, load_policy
    policy = load_policy(engagement.path / "license_policy.json")
    lic_rows = evaluate(list(inv.components.values()), policy)
    lic_count = Counter(r["decision"] for r in lic_rows)
    lic_flag = sorted((r for r in lic_rows if r["decision"] in ("denied", "review")),
                      key=lambda r: ({"denied": 0, "review": 1}[r["decision"]], r["component"].name.lower()))
    sc_kinds = ("dependency-confusion", "private-registry", "internal-package", "deprecated-package", "stale-package")
    supply = {k: [o for o in inv.observations if o.kind == k] for k in sc_kinds}
    supply["malicious"] = [f for f in findings if f.malicious]
    observations = [o for o in inv.observations if o.kind not in sc_kinds]
    return {
        "meta": engagement.meta, "runs": inv.runs, "db": fdoc.get("db", {}), "generated": fdoc.get("generated", ""),
        "findings": findings, "severity": sev, "kev": sum(f.kev for f in findings),
        "malicious": sum(f.malicious for f in findings),
        "components": inv.sorted_components(), "affected_components": len(affected_keys),
        "plan": plan, "observations": observations, "unversioned": unversioned, "estimated": estimated,
        "no_coverage": no_cov, "eco_counts": eco_counts, "methods": methods, "blackbox": blackbox,
        "comps_by_key": comps, "usage": usage, "reach": reach, "nvd_findings": nvd,
        "lic_rows": lic_rows, "lic_count": lic_count, "lic_flag": lic_flag, "lic_policy_custom": policy["custom"],
        "supply": supply, "online": engagement.meta.get("online_enrichment"),
        "suppressed": notes.get("suppressed") or [],
    }
