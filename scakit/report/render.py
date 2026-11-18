from __future__ import annotations

import csv
import html
import io
import json
from datetime import datetime

from .. import PRODUCT_NAME, __version__
from ..models import base_ecosystem
from .i18n import T, tr
from .sections import license_blocks, method_text, supply_blocks, suppressed_blocks


def _html_blocks(blocks) -> str:
    out = []
    for b in blocks:
        if b[0] == "h":
            out.append(f"<h2>{_e(b[1])}</h2>")
        elif b[0] == "p":
            out.append(f"<p>{_e(b[1])}</p>")
        elif b[0] == "note":
            out.append(f"<div class='note'>{_e(b[1])}</div>")
        elif b[0] == "list":
            out.append("<ul>" + "".join(f"<li>{_e(x)}</li>" for x in b[1]) + "</ul>")
        elif b[0] == "table":
            out.append("<table><tr>" + "".join(f"<th>{_e(h)}</th>" for h in b[1]) + "</tr>" +
                       "".join("<tr>" + "".join(f"<td>{_e(c)}</td>" for c in r) + "</tr>" for r in b[2]) + "</table>")
    return "".join(out)


def _md_blocks(blocks) -> list[str]:
    out = []
    for b in blocks:
        if b[0] == "h":
            out.append(f"\n## {b[1]}\n")
        elif b[0] in ("p", "note"):
            out.append(("> " if b[0] == "note" else "") + b[1] + "\n")
        elif b[0] == "list":
            out += [f"- {x}" for x in b[1]] + [""]
        elif b[0] == "table":
            out += ["| " + " | ".join(b[1]) + " |", "|" + "---|" * len(b[1])]
            out += ["| " + " | ".join(str(c).replace("|", "/") for c in r) + " |" for r in b[2]] + [""]
    return out

SEV_COLORS = {"CRITICAL": "#8e1b1b", "HIGH": "#c2410c", "MEDIUM": "#b7791f", "LOW": "#2f6f4f", "UNKNOWN": "#5b6472"}
ID_URL = "https://osv.dev/vulnerability/{}"
NVD_URL = "https://nvd.nist.gov/vuln/detail/{}"


def vuln_url(f) -> str:
    from urllib.parse import quote
    return (NVD_URL if getattr(f, "source", "OSV") == "NVD" else ID_URL).format(quote(str(f.vuln_id), safe=""))


def _e(s) -> str:
    return html.escape(str(s if s is not None else ""))


def _sev(sev, lang):
    return tr("sev", lang, sev if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE") else "UNKNOWN")


def _relation(c, lang):
    if c.direct:
        return tr("direct", lang) + (f" — {tr('usage', lang, c.usage)}" if c.usage else "")
    if c.usage == "imported":
        base = tr("transitive", lang) + (f" ({tr('via', lang)} {', '.join(c.parents[:2])})" if c.parents else "")
        return f"{base} — {tr('usage', lang, 'imported')}"
    if c.parents:
        return f"{tr('transitive', lang)} ({tr('via', lang)} {', '.join(c.parents[:2])})"
    return tr("transitive", lang) if c.direct is False else "—"


def _targets(c):
    return sorted({e.target for e in c.evidence if e.target}) if c else []


def _cves(f):
    return [a for a in f.aliases if a.startswith("CVE-")]


def _evidence_text(c, lang, limit=3):
    items = [f"{e.method}: {e.location}" + (f" ({e.detail})" if e.detail else "") for e in c.evidence[:limit]]
    if len(c.evidence) > limit:
        items.append(tr("more", lang).format(n=len(c.evidence) - limit))
    return items


def method_label(m: str, lang: str) -> str:
    return tr("method", lang, m) if m in T["method"] else m


def _locations(c, limit=None) -> list[str]:
    seen, out = set(), []
    for e in c.evidence:
        if e.location not in seen:
            seen.add(e.location)
            out.append(e.location)
    return out[:limit] if limit else out


def _evidence_items(c, lang, limit=4):
    seen, out = set(), []
    for e in c.evidence:
        if e.location in seen:
            continue
        seen.add(e.location)
        loc = f"{e.location}:{e.line}" if getattr(e, "line", None) else e.location
        out.append((method_label(e.method, lang), loc, (getattr(e, "snippet", "") or e.detail or "")[:140]))
    return out[:limit] if limit else out


def _db_line(db: dict) -> str:
    parts = []
    osv = [v.get("updated", "")[:10] for k, v in db.items() if k.startswith("osv:")]
    if osv:
        parts.append(f"OSV {max(osv)}")
    if "epss" in db:
        parts.append(f"EPSS {db['epss'].get('updated', '')[:10]}")
    if "kev" in db:
        parts.append(f"KEV {db['kev'].get('updated', '')[:10]}")
    return " · ".join(parts)


CSS = """
:root{--ink:#1d2430;--muted:#5b6472;--line:#d9dee6;--soft:#f4f6f9;--acc:#1f3a5f}
*{box-sizing:border-box}body{font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:var(--ink);
margin:0;background:#fff}main{max-width:1180px;margin:0 auto;padding:28px 20px 60px}
h1{color:var(--acc);font-size:26px;margin:0 0 4px}h2{color:var(--acc);font-size:19px;margin:34px 0 10px;
border-bottom:2px solid var(--acc);padding-bottom:4px}h3{font-size:15px;margin:18px 0 6px}
.meta{color:var(--muted)}.cards{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0}
.card{border:1px solid var(--line);border-radius:8px;padding:10px 14px;min-width:130px;background:var(--soft)}
.card b{display:block;font-size:22px}.card span{color:var(--muted);font-size:12px}
table{border-collapse:collapse;width:100%;margin:8px 0;font-size:12.5px}th,td{border:1px solid var(--line);
padding:5px 7px;text-align:left;vertical-align:top}th{background:var(--acc);color:#fff;font-weight:600;position:sticky;top:0}
tr:nth-child(even) td{background:#fafbfc}.sev{display:inline-block;color:#fff;border-radius:4px;padding:1px 7px;
font-size:11.5px;font-weight:600}.kev{background:#111;color:#fff;border-radius:4px;padding:1px 6px;font-size:11px}
code{font:12px/1.4 ui-monospace,Consolas,monospace;background:var(--soft);padding:1px 4px;border-radius:3px;
word-break:break-all}.note{background:#fff4e0;border-left:4px solid #e09a2b;padding:10px 14px;margin:10px 0}
.small{font-size:11.5px;color:var(--muted)}ul{margin:6px 0 6px 20px;padding:0}a{color:var(--acc)}
@media print{th{position:static}h2{break-after:avoid}tr{break-inside:avoid}}
"""


def to_html(d: dict, lang: str) -> str:
    m = d["meta"]
    out = io.StringIO()
    w = out.write
    w(f"<!doctype html><html lang='{lang}'><head><meta charset='utf-8'><meta name='viewport' "
      f"content='width=device-width,initial-scale=1'><title>{_e(tr('title', lang))} — {_e(m.get('name'))}</title>"
      f"<style>{CSS}</style></head><body><main>")
    w(f"<h1>{_e(tr('title', lang))}</h1><div class='meta'>{_e(tr('client', lang))}: <b>{_e(m.get('client') or '—')}</b>"
      f" · {_e(tr('engagement', lang))}: <b>{_e(m.get('name'))}</b> · {_e(tr('date', lang))}: "
      f"{datetime.now().strftime('%Y-%m-%d')}<br>{_e(tr('db_state', lang))}: {_e(_db_line(d['db']))}</div>")

    sev = d["severity"]
    w(f"<h2>{_e(tr('summary', lang))}</h2>")
    w(f"<p>{_e(tr('summary_text', lang).format(n=len(d['components']), a=d['affected_components'], f=len(d['findings']), c=sev.get('CRITICAL', 0), h=sev.get('HIGH', 0)))}</p>")
    if d["kev"]:
        w(f"<p><b>{_e(tr('kev_text', lang).format(k=d['kev']))}</b></p>")
    if d["malicious"]:
        w(f"<p><b>{_e(tr('mal_text', lang).format(m=d['malicious']))}</b></p>")
    w("<div class='cards'>")
    w(f"<div class='card'><b>{len(d['components'])}</b><span>{_e(tr('components', lang))}</span></div>")
    w(f"<div class='card'><b>{d['affected_components']}</b><span>{_e(tr('affected', lang))}</span></div>")
    for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
        w(f"<div class='card' style='border-top:4px solid {SEV_COLORS[s]}'><b>{sev.get(s, 0)}</b>"
          f"<span>{_e(_sev(s, lang))}</span></div>")
    w(f"<div class='card' style='border-top:4px solid #111'><b>{d['kev']}</b><span>{_e(tr('kev', lang))}</span></div></div>")
    if d["plan"]:
        w(f"<h3>{_e(tr('top_actions', lang))}</h3><ul>")
        for p in d["plan"][:5]:
            c = p["component"]
            v = p["target"] or tr("no_fix", lang)
            w(f"<li>{_e(tr('upgrade_line', lang).format(c=f'{c.name}@{c.version}', v=v, n=len(p['findings'])))}"
              + (" <span class='kev'>KEV</span>" if p["kev"] else "") + "</li>")
        w("</ul>")

    w(f"<h2>{_e(tr('plan', lang))}</h2><p class='small'>{_e(tr('plan_intro', lang))}</p>")
    if not d["plan"]:
        w(f"<p>{_e(tr('none', lang))}</p>")
    else:
        w(f"<table><tr><th>#</th><th>{_e(tr('component', lang))}</th><th>{_e(tr('current', lang))}</th>"
          f"<th>{_e(tr('recommended', lang))}</th><th>{_e(tr('vulns', lang))}</th><th>{_e(tr('relation', lang))}</th>"
          f"<th>{_e(tr('target_loc', lang))}</th></tr>")
        for i, p in enumerate(d["plan"], 1):
            c = p["component"]
            counts = " ".join(f"<span class='sev' style='background:{SEV_COLORS.get(s, '#555')}'>{p['counts'][s]} "
                              f"{_e(_sev(s, lang))}</span>" for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
                              if p["counts"].get(s))
            if p["kev"]:
                counts += f" <span class='kev'>KEV ×{p['kev']}</span>"
            target = _e(p["target"]) if p["target"] else f"<i>{_e(tr('no_fix', lang))}</i>"
            if p["target"] and p["unfixed"]:
                target += f" <span class='small'>(+{p['unfixed']} {_e(tr('no_fix', lang)).lower()})</span>"
            w(f"<tr><td>{i}</td><td><b>{_e(c.name)}</b><br><span class='small'>{_e(base_ecosystem(c.ecosystem))}</span></td>"
              f"<td><code>{_e(c.version)}</code></td><td><code>{target}</code></td><td>{counts}</td>"
              f"<td>{_e(_relation(c, lang))}</td><td class='small'>{'<br>'.join(_e(t) for t in _targets(c)[:3])}"
              + "".join(f"<br><code>{_e(loc)}</code>" for loc in _locations(c, 2))
              + (f"<br>+{len(_locations(c)) - 2}" if len(_locations(c)) > 2 else "") + "</td></tr>")
        w("</table>")

    w(f"<h2>{_e(tr('details', lang))}</h2>")
    if d["findings"]:
        w(f"<table><tr><th>{_e(tr('id', lang))}</th><th>{_e(tr('severity', lang))}</th><th>EPSS</th>"
          f"<th>{_e(tr('component', lang))}</th><th>{_e(tr('location', lang))}</th><th>{_e(tr('fix', lang))}</th>"
          f"<th>{_e(tr('confidence', lang))}</th></tr>")
        comps = d["comps_by_key"]
        for f in d["findings"]:
            c = comps.get(f.component_key)
            cves = _cves(f)
            ident = f"<a href='{_e(vuln_url(f))}'>{_e(f.vuln_id)}</a>"
            if cves:
                ident += "<br><span class='small'>" + _e(", ".join(cves[:4])) + (" …" if len(cves) > 4 else "") + "</span>"
            ident += f"<br><span class='small'>{_e(f.summary[:160])}</span>"
            sevtxt = f"<span class='sev' style='background:{SEV_COLORS.get(f.severity, '#555')}'>{_e(_sev(f.severity, lang))}</span>"
            if f.cvss_score is not None:
                sevtxt += f" {f.cvss_score}"
            if f.kev:
                sevtxt += " <span class='kev'>KEV</span>"
            if f.malicious:
                sevtxt += f" <span class='kev'>{_e(tr('malicious', lang))}</span>"
            epss = f"{f.epss * 100:.1f}%" if f.epss is not None else "—"
            comp_txt = f"<b>{_e(c.name if c else f.component_purl)}</b> <code>{_e(c.version if c else '')}</code>"
            loc_txt = "<br>".join(f"<b>{_e(m)}</b>: <code>{_e(loc)}</code>" + (f"<br><span class='small'>{_e(det)}</span>"
                                                                                 if det else "")
                                  for m, loc, det in (_evidence_items(c, lang, 4) if c else []))
            extra = f"<br><span class='small'>{_e(tr('reach', lang, f.reachability))}</span>" if f.reachability else ""
            extra += f"<br><span class='small'>{_e(f.source)}</span>" if f.source != "OSV" else ""
            w(f"<tr><td>{ident}</td><td>{sevtxt}</td><td>{epss}</td><td>{comp_txt}</td><td>{loc_txt}</td>"
              f"<td><code>{_e(f.upgrade_to or ', '.join(f.fixed_versions[:2]) or '—')}</code></td>"
              f"<td>{_e(tr('conf', lang, f.confidence))}{extra}</td></tr>")
        w("</table>")
    else:
        w(f"<p>{_e(tr('none', lang))}</p>")

    if d["usage"]["imported"] or d["usage"]["not-imported"] or d["reach"]["called"] or d["reach"]["not-called"]:
        w(f"<h2>{_e(tr('usage_title', lang))}</h2><p>{_e(tr('usage_text', lang))}</p><ul>")
        w(f"<li>{_e(tr('usage_stats', lang).format(i=d['usage']['imported'], n=d['usage']['not-imported']))}</li>")
        if d["reach"]["called"] or d["reach"]["not-called"]:
            w(f"<li>{_e(tr('reach_stats', lang).format(c=d['reach']['called'], n=d['reach']['not-called']))}</li>")
        w("</ul>")
        if d["usage"]["not_imported_list"]:
            w("<p class='small'>" + _e(", ".join(f"{c.name}@{c.version}" for c in d["usage"]["not_imported_list"][:60]))
              + "</p>")

    w(_html_blocks(license_blocks(d, lang) + supply_blocks(d, lang) + suppressed_blocks(d, lang)))

    w(f"<h2>{_e(tr('limits', lang))}</h2>")
    if d["blackbox"]:
        w(f"<div class='note'>{_e(tr('lim_blackbox', lang))}</div>")
    if d["nvd_findings"]:
        w(f"<div class='note'>{_e(tr('nvd_note', lang))}</div>")
    obs_groups = {}
    for o in d["observations"]:
        obs_groups.setdefault(o.kind, []).append(o)
    for kind, items in obs_groups.items():
        label = tr("obs", lang, kind) if kind in T["obs"] else kind
        w(f"<h3>{_e(label)} ({len(items)})</h3><ul>")
        for o in items[:30]:
            w(f"<li><code>{_e(o.location)}</code>" + (f" — {_e(o.detail)}" if o.detail else "")
              + (f" <span class='small'>[{_e(o.target)}]</span>" if o.target else "") + "</li>")
        w("</ul>")
    for key, items in (("lim_unversioned", d["unversioned"]), ("lim_nocov", d["no_coverage"]),
                       ("lim_estimated", d["estimated"])):
        if items:
            w(f"<h3>{_e(tr(key, lang))} ({len(items)})</h3><ul>")
            for c in items[:40]:
                w(f"<li>{_e(c.name)} <code>{_e(c.version or '?')}</code> <span class='small'>"
                  f"{_e(base_ecosystem(c.ecosystem))} · {_e(_evidence_text(c, lang, 1)[0] if c.evidence else '')}</span></li>")
            if len(items) > 40:
                w(f"<li>… +{len(items) - 40}</li>")
            w("</ul>")

    affected = [d["comps_by_key"][p["component"].key] for p in d["plan"] if p["component"].key in d["comps_by_key"]]
    if affected:
        w(f"<h2>{_e(tr('appendix_c', lang))}</h2><p class='small'>{_e(tr('appendix_c_text', lang))}</p>")
        w(f"<table><tr><th>{_e(tr('component', lang))}</th><th>{_e(tr('method_col', lang))}</th>"
          f"<th>{_e(tr('location', lang))}</th></tr>")
        for c in affected:
            for m, loc, det in _evidence_items(c, lang, None):
                w(f"<tr><td><b>{_e(c.name)}</b> <code>{_e(c.version)}</code></td><td>{_e(m)}</td>"
                  f"<td><code>{_e(loc)}</code>" + (f"<br><span class='small'>{_e(det)}</span>" if det else "")
                  + "</td></tr>")
        w("</table>")

    w(f"<h2>{_e(tr('inventory', lang))} ({len(d['components'])})</h2>")
    w(f"<table><tr><th>{_e(tr('ecosystem', lang))}</th><th>{_e(tr('component', lang))}</th><th>{_e(tr('version', lang))}</th>"
      f"<th>{_e(tr('relation', lang))}</th><th>{_e(tr('license', lang))}</th><th>{_e(tr('confidence', lang))}</th>"
      f"<th>{_e(tr('evidence', lang))}</th></tr>")
    for c in d["components"]:
        w(f"<tr><td>{_e(c.ecosystem)}</td><td>{_e(c.name)}</td><td><code>{_e(c.version or '?')}</code></td>"
          f"<td>{_e(_relation(c, lang))}</td><td>{_e(', '.join(c.licenses) or '—')}</td>"
          f"<td>{_e(tr('conf', lang, c.confidence))}</td><td class='small'>{'<br>'.join(_e(x) for x in _evidence_text(c, lang))}</td></tr>")
    w("</table>")

    w(f"<h2>{_e(tr('scope', lang))}</h2><p>{_e(method_text(d, lang))}</p><h3>{_e(tr('runs', lang))}</h3>")
    w(f"<table><tr><th>{_e(tr('time', lang))}</th><th>{_e(tr('target', lang))}</th><th>{_e(tr('source', lang))}</th>"
      f"<th>{_e(tr('detections', lang))}</th></tr>")
    for r in d["runs"]:
        kind = tr("kind", lang, r["kind"]) if r["kind"] in T["kind"] else r["kind"]
        w(f"<tr><td>{_e(r['time'][:16].replace('T', ' '))}</td><td>{_e(r.get('target') or '—')}</td>"
          f"<td>{_e(kind)}<br><code>{_e(r['source'])}</code></td><td>{_e(r.get('detections', ''))}</td></tr>")
    w(f"</table><p class='small'>{PRODUCT_NAME} {__version__}</p></main></body></html>")
    return out.getvalue()


def to_markdown(d: dict, lang: str) -> str:
    m = d["meta"]
    L = []
    a = L.append
    sev = d["severity"]
    a(f"# {tr('title', lang)}\n")
    a(f"**{tr('client', lang)}:** {m.get('client') or '—'} · **{tr('engagement', lang)}:** {m.get('name')} · "
      f"**{tr('date', lang)}:** {datetime.now().strftime('%Y-%m-%d')}  ")
    a(f"**{tr('db_state', lang)}:** {_db_line(d['db'])}\n")
    a(f"## {tr('summary', lang)}\n")
    a(tr("summary_text", lang).format(n=len(d["components"]), a=d["affected_components"], f=len(d["findings"]),
                                       c=sev.get("CRITICAL", 0), h=sev.get("HIGH", 0)) + "\n")
    if d["kev"]:
        a("**" + tr("kev_text", lang).format(k=d["kev"]) + "**\n")
    a("| " + " | ".join(_sev(s, lang) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")) + " | KEV |")
    a("|" + "---|" * 6)
    a("| " + " | ".join(str(sev.get(s, 0)) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")) + f" | {d['kev']} |\n")
    a(f"## {tr('plan', lang)}\n")
    a(f"| # | {tr('component', lang)} | {tr('current', lang)} | {tr('recommended', lang)} | {tr('vulns', lang)} | KEV | {tr('target', lang)} |")
    a("|---|---|---|---|---|---|---|")
    for i, p in enumerate(d["plan"], 1):
        c = p["component"]
        cnt = ", ".join(f"{p['counts'][s]} {_sev(s, lang)}" for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
                        if p["counts"].get(s))
        a(f"| {i} | {c.name} | `{c.version}` | `{p['target'] or tr('no_fix', lang)}` | {cnt} | {p['kev'] or ''} | {', '.join(_targets(c)[:3])} |")
    a(f"\n## {tr('details', lang)}\n")
    a(f"| {tr('id', lang)} | CVE | {tr('severity', lang)} | EPSS | KEV | {tr('component', lang)} | {tr('location', lang)} | {tr('fix', lang)} |")
    a("|---|---|---|---|---|---|---|---|")
    comps = d["comps_by_key"]
    for f in d["findings"]:
        c = comps.get(f.component_key)
        a(f"| [{f.vuln_id}]({vuln_url(f)}) | {', '.join(_cves(f)[:3])} | {_sev(f.severity, lang)}"
          f"{' ' + str(f.cvss_score) if f.cvss_score is not None else ''} | "
          f"{f'{f.epss * 100:.1f}%' if f.epss is not None else '—'} | {'✔' if f.kev else ''} | "
          f"{c.name if c else f.component_purl} `{c.version if c else ''}` | "
          f"{'<br>'.join(f'`{loc}`' for loc in (_locations(c, 3) if c else []))} | `{f.upgrade_to or '—'}` |")
    if d["usage"]["imported"] or d["usage"]["not-imported"]:
        a(f"\n## {tr('usage_title', lang)}\n\n{tr('usage_text', lang)}\n")
        a("- " + tr("usage_stats", lang).format(i=d["usage"]["imported"], n=d["usage"]["not-imported"]))
        if d["reach"]["called"] or d["reach"]["not-called"]:
            a("- " + tr("reach_stats", lang).format(c=d["reach"]["called"], n=d["reach"]["not-called"]))
    L.extend(_md_blocks(license_blocks(d, lang) + supply_blocks(d, lang) + suppressed_blocks(d, lang)))
    a(f"\n## {tr('limits', lang)}\n")
    if d["blackbox"]:
        a("> " + tr("lim_blackbox", lang) + "\n")
    if d["nvd_findings"]:
        a("> " + tr("nvd_note", lang) + "\n")
    for o in d["observations"]:
        label = tr("obs", lang, o.kind) if o.kind in T["obs"] else o.kind
        a(f"- {label}: `{o.location}`" + (f" — {o.detail}" if o.detail else ""))
    for key, items in (("lim_unversioned", d["unversioned"]), ("lim_nocov", d["no_coverage"])):
        if items:
            a(f"- {tr(key, lang)}: " + ", ".join(f"{c.name}" for c in items[:30]))
    a(f"\n## {tr('scope', lang)}\n\n{method_text(d, lang)}\n")
    for r in d["runs"]:
        a(f"- {r['time'][:16].replace('T', ' ')} · {r.get('target') or '—'} · {r['kind']} · `{r['source']}`")
    return "\n".join(L) + "\n"


def to_cyclonedx(d: dict) -> str:
    comps = []
    for c in d["components"]:
        entry = {"type": "library", "bom-ref": c.purl, "name": c.name, "purl": c.purl}
        if c.version:
            entry["version"] = c.version
        if base_ecosystem(c.ecosystem) == "Maven" and ":" in c.name:
            entry["group"], entry["name"] = c.name.split(":", 1)
        if c.licenses:
            from ..licenses import normalize
            ids = []
            for lic in c.licenses:
                ids += [i for i in normalize(lic) if i not in ids]
            entry["licenses"] = [{"license": {"id": i}} if not i.startswith("LicenseRef-") else
                                 {"license": {"name": i[len("LicenseRef-"):]}} for i in ids]
        props = [{"name": "scakit:confidence", "value": c.confidence},
                 {"name": "scakit:ecosystem", "value": c.ecosystem}]
        if c.direct is not None:
            props.append({"name": "scakit:direct", "value": str(bool(c.direct)).lower()})
        for e in c.evidence[:10]:
            props.append({"name": f"scakit:evidence:{e.method}", "value": e.location + (f" ({e.detail})" if e.detail else "")})
        entry["properties"] = props
        comps.append(entry)
    vulns = []
    for f in d["findings"]:
        v = {"id": f.vuln_id, "source": {"name": f.source, "url": vuln_url(f)},
             "affects": [{"ref": f.component_purl}]}
        if f.aliases:
            v["references"] = [{"id": a, "source": {"name": "NVD" if a.startswith("CVE-") else "OSV"}} for a in f.aliases[:10]]
        rating = {"severity": f.severity.lower() if f.severity != "UNKNOWN" else "unknown"}
        if f.cvss_score is not None:
            rating.update({"score": f.cvss_score, "method": "CVSSv31" if "CVSS:3.1" in f.cvss_vector else "CVSSv3",
                           "vector": f.cvss_vector})
        v["ratings"] = [rating]
        if f.summary:
            v["description"] = f.summary
        if f.upgrade_to:
            v["recommendation"] = f"Upgrade to {f.upgrade_to}"
        props = []
        if f.epss is not None:
            props.append({"name": "epss:score", "value": f"{f.epss:.5f}"})
        if f.kev:
            props.append({"name": "cisa:kev", "value": "true"})
        if props:
            v["properties"] = props
        vulns.append(v)
    bom = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": {"timestamp": d["generated"] or datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                     "tools": [{"vendor": PRODUCT_NAME, "name": PRODUCT_NAME, "version": __version__}],
                     "component": {"type": "application", "name": d["meta"].get("name", ""), "bom-ref": "root"}},
        "components": comps, "vulnerabilities": vulns,
    }
    return json.dumps(bom, indent=1, ensure_ascii=False)


def to_spdx(d: dict) -> str:
    import uuid
    from ..licenses import normalize
    created = d["generated"] or datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    pkgs, rels = [], []
    for i, c in enumerate(d["components"], 1):
        sid = f"SPDXRef-Package-{i}"
        ids = []
        for lic in c.licenses:
            ids += [x for x in normalize(lic) if x not in ids]
        declared = " AND ".join(ids) if ids and not any(x.startswith("LicenseRef-") for x in ids) else "NOASSERTION"
        pkgs.append({"SPDXID": sid, "name": c.name, "versionInfo": c.version or "NOASSERTION",
                     "downloadLocation": "NOASSERTION", "filesAnalyzed": False, "licenseConcluded": "NOASSERTION",
                     "licenseDeclared": declared, "copyrightText": "NOASSERTION",
                     "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                                       "referenceLocator": c.purl}]})
        rels.append({"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": sid})
    doc = {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
           "name": d["meta"].get("name", "scakit"),
           "documentNamespace": f"https://spdx.scakit.local/{uuid.uuid4()}",
           "creationInfo": {"created": created, "creators": [f"Tool: le-fureteur-{__version__}"]},
           "packages": pkgs, "relationships": rels}
    return json.dumps(doc, indent=1, ensure_ascii=False)


def to_csv(d: dict, lang: str) -> str:
    out = io.StringIO()
    from ..safeio import csv_cell
    raw = csv.writer(out)

    class _W:
        @staticmethod
        def writerow(row):
            raw.writerow([csv_cell(v) for v in row])
    wr = _W()
    wr.writerow(["id", "cve", "severity", "cvss", "epss", "kev", "malicious", "ecosystem", "component", "version",
                 "upgrade_to", "fixed_versions", "direct", "confidence", "evidence", "summary"])
    comps = d["comps_by_key"]
    for f in d["findings"]:
        c = comps.get(f.component_key)
        wr.writerow([f.vuln_id, " ".join(_cves(f)), f.severity, f.cvss_score or "", f.epss if f.epss is not None else "",
                     int(f.kev), int(f.malicious), c.ecosystem if c else "", c.name if c else f.component_purl,
                     c.version if c else "", f.upgrade_to, " ".join(f.fixed_versions), c.direct if c else "",
                     f.confidence, " | ".join(f"{m}: {loc}" + (f" ({det})" if det else "")
                                             for m, loc, det in _evidence_items(c, lang, None)) if c else "",
                     f.summary])
    return out.getvalue()
