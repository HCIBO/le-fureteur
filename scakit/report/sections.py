from __future__ import annotations

from .i18n import tr


def license_blocks(d: dict, lang: str) -> list:
    rows = d["lic_rows"]
    if not rows:
        return []
    pol = tr("pol_custom", lang) if d["lic_policy_custom"] else tr("pol_default", lang)
    cnt = d["lic_count"]
    out = [("h", tr("lic_title", lang)), ("p", tr("lic_text", lang).format(pol=pol)),
           ("list", [f"{tr('decision', lang, k)}: {cnt.get(k, 0)}" for k in ("allowed", "review", "denied", "unknown")])]
    if d["lic_flag"]:
        out.append(("table", [tr("component", lang), tr("version", lang), tr("license", lang), tr("category_col", lang),
                              tr("decision_col", lang)],
                    [[r["component"].name, r["component"].version or "?", ", ".join(r["spdx"]) or "—",
                      tr("lic_cat", lang, r["category"]), tr("decision", lang, r["decision"])]
                     for r in d["lic_flag"][:300]]))
    unknown = [r["component"] for r in rows if r["decision"] == "unknown"]
    if unknown:
        out.append(("p", f"{tr('decision', lang, 'unknown')} ({len(unknown)}): " +
                    ", ".join(f"{c.name}@{c.version}" for c in unknown[:80]) + (" …" if len(unknown) > 80 else "")))
    return out


def supply_blocks(d: dict, lang: str) -> list:
    sc = d["supply"]
    out = [("h", tr("sc_title", lang))]
    any_item = False
    if sc["malicious"]:
        any_item = True
        out.append(("p", tr("mal_text", lang).format(m=len(sc["malicious"]))))
        out.append(("list", [f"{f.vuln_id}: {f.component_purl}" for f in sc["malicious"]]))
    for kind in ("dependency-confusion", "private-registry", "internal-package", "deprecated-package", "stale-package"):
        items = sc.get(kind) or []
        if not items:
            continue
        any_item = True
        out.append(("p", f"{tr('obs', lang, kind)} ({len(items)})"))
        out.append(("list", [o.location + (f" — {o.detail}" if o.detail else "") for o in items[:60]]))
    if not any_item:
        out.append(("p", tr("sc_none", lang)))
    return out


def suppressed_blocks(d: dict, lang: str) -> list:
    items = d.get("suppressed") or []
    if not items:
        return []
    rows = []
    for s in items:
        r = s["suppression"]
        comp = s["component_key"].split("|")
        rows.append([s["vuln_id"], f"{comp[1]} {comp[2]}", tr("sup_kind", lang, r["kind"]),
                     r["reason"] + (f" ({r['by']}, {r['date']})" if r.get("by") else f" ({r['date']})")])
    return [("h", tr("sup_title", lang)), ("p", tr("sup_text", lang)),
            ("table", [tr("id", lang), tr("component", lang), tr("decision_col", lang),
                       tr("reason", lang)], rows)]


def method_text(d: dict, lang: str) -> str:
    base = tr("method_text", lang)
    if not d.get("online"):
        return base
    for marker in ("Analiz sırasında kaynak kod", "No source code or inventory", "Aucun code source ni inventaire",
                   "Während der Analyse wurden weder"):
        if marker in base:
            base = base[: base.index(marker)].rstrip()
    return base + " " + tr("online_method", lang).format(svc=", ".join(d["online"]))
