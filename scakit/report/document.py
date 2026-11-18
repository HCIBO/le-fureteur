from __future__ import annotations

from .. import PRODUCT_NAME
import os
import sys
from datetime import datetime
from pathlib import Path

from ..messages import translate
from ..models import base_ecosystem
from .i18n import tr
from .sections import license_blocks, method_text, supply_blocks, suppressed_blocks
from .render import (SEV_COLORS, _cves, _db_line, _evidence_items, _evidence_text, _locations, _relation, _targets,
                     vuln_url)

ACCENT = (0x1F, 0x3A, 0x5F)
LIGHT = (0xE8, 0xEE, 0xF5)
NOTE_BG = (0xFF, 0xF4, 0xE0)
SEVS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
MAIN_SEVS = ("CRITICAL", "HIGH")

EXTRA = {
    "confidential": ("GİZLİ", "CONFIDENTIAL"),
    "page": ("Sayfa", "Page"),
    "prepared": ("Hazırlanma tarihi", "Prepared on"),
    "toc": ("İçindekiler", "Contents"),
    "details_main": ("Bulgu Detayları (Kritik, Yüksek ve aktif istismar edilenler)",
                     "Finding Details (Critical, High and known exploited)"),
    "appendix_a": ("Ek A — Orta, Düşük ve Belirsiz Bulgular", "Appendix A — Medium, Low and Unknown Findings"),
    "appendix_b": ("Ek B — Bileşen Envanteri", "Appendix B — Component Inventory"),
    "sev_dist": ("Şiddet dağılımı", "Severity distribution"),
    "scope_table": ("Analiz edilen kaynaklar", "Analysed sources"),
    "source_col": ("Kaynak", "Source"),
    "status": ("Durum", "Status"),
    "detail_col": ("Detay", "Detail"),
    "inv_note": ("Envanterin makine tarafından okunabilir tam hâli CycloneDX SBOM dosyası olarak ayrıca teslim edilmiştir.",
                 "The complete machine-readable inventory is delivered separately as a CycloneDX SBOM file."),
}


def x(key, lang):
    if lang in ("fr", "de"):
        from .i18n_more import lookup
        hit = lookup(key, lang)
        if hit is not None:
            return hit
    v = EXTRA[key]
    return v[0] if lang == "tr" else v[1]


def find_fonts() -> tuple[str, str, str] | None:
    cands = [
        ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
         "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"),
        ("/usr/share/fonts/dejavu/DejaVuSans.ttf", "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf",
         "/usr/share/fonts/dejavu/DejaVuSansMono.ttf"),
    ]
    win = os.environ.get("WINDIR", r"C:\Windows")
    cands.append((os.path.join(win, "Fonts", "arial.ttf"), os.path.join(win, "Fonts", "arialbd.ttf"),
                  os.path.join(win, "Fonts", "consola.ttf")))
    cands.append(("/mnt/c/Windows/Fonts/arial.ttf", "/mnt/c/Windows/Fonts/arialbd.ttf", "/mnt/c/Windows/Fonts/consola.ttf"))
    cands.append(("/System/Library/Fonts/Supplemental/Arial.ttf", "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
                  "/System/Library/Fonts/Supplemental/Courier New.ttf"))
    for c in cands:
        if all(os.path.exists(p) for p in c):
            return c
    return None


def to_pdf(d: dict, lang: str, out: Path) -> Path:
    from reportlab.graphics.charts.barcharts import HorizontalBarChart
    from reportlab.graphics.shapes import Drawing
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import (KeepTogether, NextPageTemplate, PageBreak, PageTemplate, Paragraph, Spacer,
                                    Table, TableStyle, BaseDocTemplate, Frame)

    fonts = find_fonts()
    if fonts:
        pdfmetrics.registerFont(TTFont("R", fonts[0]))
        pdfmetrics.registerFont(TTFont("RB", fonts[1]))
        pdfmetrics.registerFont(TTFont("RM", fonts[2]))
        pdfmetrics.registerFontFamily("R", normal="R", bold="RB", italic="R", boldItalic="RB")
        F, FB, FM = "R", "RB", "RM"
    else:
        print("warning: no Unicode TTF font found; non-ASCII characters may not render correctly", file=sys.stderr)
        F, FB, FM = "Helvetica", "Helvetica-Bold", "Courier"

    c = lambda rgb: colors.Color(*(v / 255 for v in rgb))
    hexc = lambda h: colors.HexColor(h)
    ACC, LT = c(ACCENT), c(LIGHT)
    st = {
        "cover_t": ParagraphStyle("ct", fontName=FB, fontSize=26, leading=32, textColor=ACC),
        "cover_s": ParagraphStyle("cs", fontName=F, fontSize=14, leading=19, textColor=hexc("#444444")),
        "h1": ParagraphStyle("h1", fontName=FB, fontSize=15, leading=19, textColor=ACC, spaceBefore=6, spaceAfter=8),
        "h2": ParagraphStyle("h2", fontName=FB, fontSize=11, leading=14, textColor=ACC, spaceBefore=8, spaceAfter=4),
        "body": ParagraphStyle("b", fontName=F, fontSize=9.2, leading=13, spaceAfter=5),
        "cell": ParagraphStyle("c", fontName=F, fontSize=7.6, leading=9.6),
        "cellb": ParagraphStyle("cb", fontName=FB, fontSize=7.6, leading=9.6),
        "small": ParagraphStyle("s", fontName=F, fontSize=6.8, leading=8.4, textColor=hexc("#5b6472")),
        "mono": ParagraphStyle("m", fontName=FM, fontSize=7, leading=9),
        "hdr": ParagraphStyle("hd", fontName=FB, fontSize=7.6, leading=9.4, textColor=colors.white),
        "note": ParagraphStyle("n", fontName=F, fontSize=8.4, leading=11.5),
        "tile_n": ParagraphStyle("tn", fontName=FB, fontSize=18, leading=21, alignment=1),
        "tile_l": ParagraphStyle("tl", fontName=F, fontSize=7.5, leading=9, alignment=1, textColor=hexc("#5b6472")),
    }

    def esc(s):
        return (str(s if s is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace('"', "&quot;").replace("'", "&#39;"))

    def P(text, style="cell"):
        return Paragraph(text, st[style])

    def sev_badge(sev):
        col = SEV_COLORS.get(sev, "#5b6472")
        return f'<font color="{col}"><b>{esc(tr("sev", lang, sev if sev in SEVS else "UNKNOWN"))}</b></font>'

    base_ts = [("BACKGROUND", (0, 0), (-1, 0), ACC), ("VALIGN", (0, 0), (-1, -1), "TOP"),
               ("GRID", (0, 0), (-1, -1), 0.35, hexc("#c3ccd8")),
               ("TOPPADDING", (0, 0), (-1, -1), 2.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
               ("LEFTPADDING", (0, 0), (-1, -1), 3.5), ("RIGHTPADDING", (0, 0), (-1, -1), 3.5)]

    def table(header, rows, widths, zebra=True):
        data = [[P(esc(h), "hdr") for h in header]] + rows
        ts = list(base_ts)
        if zebra:
            ts += [("BACKGROUND", (0, i), (-1, i), hexc("#f6f8fb")) for i in range(2, len(data), 2)]
        return Table(data, colWidths=[w * mm for w in widths], repeatRows=1, style=TableStyle(ts))

    def note(text):
        t = Table([[P(text, "note")]], colWidths=[W])
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), c(NOTE_BG)),
                               ("LINEBEFORE", (0, 0), (0, -1), 3, hexc("#e09a2b")),
                               ("LEFTPADDING", (0, 0), (-1, -1), 8), ("TOPPADDING", (0, 0), (-1, -1), 6),
                               ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
        return t

    m = d["meta"]
    title = tr("title", lang)
    W = A4[0] - 30 * mm
    WL = landscape(A4)[0] - 30 * mm

    def footer(cv, doc):
        cv.saveState()
        cv.setFont(F, 7)
        cv.setFillColor(hexc("#666666"))
        pw = cv._pagesize[0]
        cv.setStrokeColor(hexc("#c3ccd8"))
        cv.line(15 * mm, 12 * mm, pw - 15 * mm, 12 * mm)
        cv.drawString(15 * mm, 8 * mm, f"{title} — {m.get('client') or m.get('name')}")
        cv.drawRightString(pw - 15 * mm, 8 * mm, f"{x('confidential', lang)} · {x('page', lang)} {doc.page}")
        cv.restoreState()

    def cover_bg(cv, doc):
        cv.saveState()
        cv.setFillColor(ACC)
        cv.rect(0, A4[1] - 18 * mm, A4[0], 18 * mm, stroke=0, fill=1)
        cv.restoreState()

    doc = BaseDocTemplate(str(out), pagesize=A4, title=f"{title} — {m.get('name')}", author=PRODUCT_NAME,
                          leftMargin=15 * mm, rightMargin=15 * mm, topMargin=15 * mm, bottomMargin=17 * mm)
    fp = Frame(15 * mm, 17 * mm, W, A4[1] - 32 * mm, id="p")
    fl = Frame(15 * mm, 17 * mm, WL, landscape(A4)[1] - 32 * mm, id="l")
    doc.addPageTemplates([PageTemplate("cover", [fp], onPage=cover_bg),
                          PageTemplate("portrait", [fp], onPage=footer),
                          PageTemplate("landscape", [fl], onPage=footer, pagesize=landscape(A4))])
    story = []

    story += [Spacer(1, 45 * mm), P(esc(title), "cover_t"), Spacer(1, 4 * mm),
              P(esc(m.get("name", "")), "cover_s"), Spacer(1, 18 * mm)]
    cover_rows = [[P(f"<b>{esc(tr('client', lang))}</b>"), P(esc(m.get("client") or "—"))],
                  [P(f"<b>{esc(x('prepared', lang))}</b>"), P(datetime.now().strftime("%d.%m.%Y"))],
                  [P(f"<b>{esc(tr('db_state', lang))}</b>"), P(esc(_db_line(d["db"])))],
                  [P(f"<b>{esc(tr('components', lang))}</b>"), P(str(len(d["components"])))],
                  [P(f"<b>{esc(tr('findings', lang))}</b>"), P(str(len(d["findings"])))]]
    t = Table(cover_rows, colWidths=[55 * mm, W - 55 * mm])
    t.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -1), 0.4, hexc("#c3ccd8")),
                           ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
    story += [t, Spacer(1, 25 * mm), P(f"<b>{esc(x('confidential', lang))}</b>", "body"),
              NextPageTemplate("portrait"), PageBreak()]

    sev = d["severity"]
    story.append(P(f"1. {esc(tr('summary', lang))}", "h1"))
    story.append(P(esc(tr("summary_text", lang).format(n=len(d["components"]), a=d["affected_components"],
                                                        f=len(d["findings"]), c=sev.get("CRITICAL", 0),
                                                        h=sev.get("HIGH", 0))), "body"))
    if d["kev"]:
        story.append(P("<b>" + esc(tr("kev_text", lang).format(k=d["kev"])) + "</b>", "body"))
    if d["malicious"]:
        story.append(P("<b>" + esc(tr("mal_text", lang).format(m=d["malicious"])) + "</b>", "body"))
    tiles = [(len(d["components"]), tr("components", lang), "#1f3a5f"),
             (d["affected_components"], tr("affected", lang), "#1f3a5f")] + \
        [(sev.get(s, 0), tr("sev", lang, s), SEV_COLORS[s]) for s in SEVS] + [(d["kev"], "KEV", "#111111")]
    tw = W / len(tiles)
    tt = Table([[P(f'<font color="{col}">{n}</font>', "tile_n") for n, _, col in tiles],
                [P(esc(lbl), "tile_l") for _, lbl, _ in tiles]], colWidths=[tw] * len(tiles))
    tt.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.4, hexc("#c3ccd8")),
                            ("INNERGRID", (0, 0), (-1, -1), 0.4, hexc("#c3ccd8")),
                            ("BACKGROUND", (0, 0), (-1, -1), hexc("#f6f8fb"))]))
    story += [Spacer(1, 2 * mm), tt, Spacer(1, 5 * mm)]
    vals = [sev.get(s, 0) for s in SEVS]
    if any(vals):
        dr = Drawing(W, 42 * mm)
        ch = HorizontalBarChart()
        ch.x, ch.y, ch.width, ch.height = 28 * mm, 4 * mm, W - 40 * mm, 34 * mm
        ch.data = [list(reversed(vals))]
        ch.categoryAxis.categoryNames = [tr("sev", lang, s) for s in reversed(SEVS)]
        ch.categoryAxis.labels.fontName = F
        ch.categoryAxis.labels.fontSize = 7.5
        ch.valueAxis.labels.fontName = F
        ch.valueAxis.labels.fontSize = 7
        ch.valueAxis.valueMin = 0
        ch.bars.strokeWidth = 0
        for i, s in enumerate(reversed(SEVS)):
            ch.bars[(0, i)].fillColor = hexc(SEV_COLORS[s])
        dr.add(ch)
        story += [P(esc(x("sev_dist", lang)), "h2"), dr]
    if d["plan"]:
        story.append(P(esc(tr("top_actions", lang)), "h2"))
        for p in d["plan"][:7]:
            comp = p["component"]
            v = p["target"] or tr("no_fix", lang)
            line = tr("upgrade_line", lang).format(c=f"{comp.name}@{comp.version}", v=v, n=len(p["findings"]))
            story.append(P("• " + esc(line) + (" <b>[KEV]</b>" if p["kev"] else ""), "body"))

    story += [NextPageTemplate("landscape"), PageBreak(), P(f"2. {esc(tr('plan', lang))}", "h1"),
              P(esc(tr("plan_intro", lang)), "small"), Spacer(1, 2 * mm)]
    rows = []
    for i, p in enumerate(d["plan"], 1):
        comp = p["component"]
        counts = " ".join(f'{sev_badge(s)} {p["counts"][s]}' for s in SEVS if p["counts"].get(s))
        if p["kev"]:
            counts += f" <b>KEV×{p['kev']}</b>"
        rows.append([P(str(i)), P(f"<b>{esc(comp.name)}</b><br/>{esc(base_ecosystem(comp.ecosystem))}"),
                     P(esc(comp.version), "mono"), P(esc(p["target"] or tr("no_fix", lang)), "mono"), P(counts),
                     P(esc(_relation(comp, lang))),
                     P(esc(", ".join(_targets(comp)[:3])) + "".join(f"<br/>{esc(loc)}" for loc in _locations(comp, 2))
                       + (f"<br/>+{len(_locations(comp)) - 2}" if len(_locations(comp)) > 2 else ""), "small")])
    if rows:
        story.append(table(["#", tr("component", lang), tr("current", lang), tr("recommended", lang),
                            tr("vulns", lang), tr("relation", lang), tr("target_loc", lang)], rows,
                           [9, 52, 28, 28, 44, 38, WL / mm - 199]))
    else:
        story.append(P(esc(tr("none", lang)), "body"))

    main = [f for f in d["findings"] if f.severity in MAIN_SEVS or f.kev or f.malicious]
    rest = [f for f in d["findings"] if f not in main]
    comps = d["comps_by_key"]

    def finding_rows(fs, full=True):
        rows = []
        for f in fs:
            cc = comps.get(f.component_key)
            cves = _cves(f)
            ident = f'<link href="{esc(vuln_url(f))}" color="#1f3a5f"><b>{esc(f.vuln_id)}</b></link>'
            if cves:
                ident += "<br/>" + esc(", ".join(cves[:3]))
            if full:
                ident += f"<br/><font size='6.6' color='#5b6472'>{esc(f.summary[:220])}</font>"
            sevt = sev_badge(f.severity) + (f" {f.cvss_score}" if f.cvss_score is not None else "")
            if f.kev:
                sevt += " <b>KEV</b>"
            if f.malicious:
                sevt += f" <b>{esc(tr('malicious', lang))}</b>"
            sevt += f"<br/>EPSS {f.epss * 100:.1f}%" if f.epss is not None else ""
            comp_t = f"<b>{esc(cc.name if cc else f.component_purl)}</b> {esc(cc.version if cc else '')}"
            loc_t = "<br/>".join(
                f"<b>{esc(m)}</b>: {esc(loc)}" + (f"<br/><font size='6.2' color='#5b6472'>{esc(det)}</font>"
                                                  if det and full else "")
                for m, loc, det in (_evidence_items(cc, lang, 4 if full else 2) if cc else []))
            conf = esc(tr("conf", lang, f.confidence))
            if f.reachability:
                conf += "<br/>" + esc(tr("reach", lang, f.reachability))
            if f.source != "OSV":
                conf += f"<br/>{esc(f.source)}"
            rows.append([P(ident), P(sevt), P(comp_t), P(loc_t, "small"),
                         P(esc(f.upgrade_to or ", ".join(f.fixed_versions[:2]) or "—"), "mono"), P(conf)])
        return rows

    hdr = [tr("id", lang), tr("severity", lang), tr("component", lang), tr("location", lang), tr("fix", lang),
           tr("confidence", lang)]
    widths = [60, 26, 38, 88, 28, WL / mm - 240]
    story += [PageBreak(), P(f"3. {esc(x('details_main', lang))}", "h1")]
    if main:
        story.append(table(hdr, finding_rows(main), widths))
    else:
        story.append(P(esc(tr("none", lang)), "body"))

    story += [NextPageTemplate("portrait"), PageBreak()]
    n = 4
    if d["usage"]["imported"] or d["usage"]["not-imported"] or d["reach"]["called"] or d["reach"]["not-called"]:
        story += [P(f"{n}. {esc(tr('usage_title', lang))}", "h1"), P(esc(tr("usage_text", lang)), "body"),
                  P("• " + esc(tr("usage_stats", lang).format(i=d["usage"]["imported"], n=d["usage"]["not-imported"])),
                    "body")]
        if d["reach"]["called"] or d["reach"]["not-called"]:
            story.append(P("• " + esc(tr("reach_stats", lang).format(c=d["reach"]["called"],
                                                                     n=d["reach"]["not-called"])), "body"))
        if d["usage"]["not_imported_list"]:
            story.append(P(esc(", ".join(f"{cc.name}@{cc.version}" for cc in d["usage"]["not_imported_list"][:80])),
                           "small"))
        n += 1
    for blk in license_blocks(d, lang) + supply_blocks(d, lang) + suppressed_blocks(d, lang):
        if blk[0] == "h":
            story.append(P(f"{n}. {esc(blk[1])}", "h1"))
            n += 1
        elif blk[0] in ("p", "note"):
            story.append(note(esc(blk[1])) if blk[0] == "note" else P(esc(blk[1]), "body"))
        elif blk[0] == "list":
            story += [P("• " + esc(x), "small") for x in blk[1]]
        elif blk[0] == "table":
            wcols = [55, 25, 40, 30, W / mm - 150]
            story.append(table(blk[1], [[P(esc(c)) for c in r] for r in blk[2]], wcols))
    story.append(P(f"{n}. {esc(tr('limits', lang))}", "h1"))
    if d["blackbox"]:
        story += [note(esc(tr("lim_blackbox", lang))), Spacer(1, 3 * mm)]
    if d["nvd_findings"]:
        story += [note(esc(tr("nvd_note", lang))), Spacer(1, 3 * mm)]
    groups = {}
    for o in d["observations"]:
        groups.setdefault(o.kind, []).append(o)
    from .i18n import T
    for kind, items in groups.items():
        label = tr("obs", lang, kind) if kind in T["obs"] else kind
        block = [P(f"{esc(label)} ({len(items)})", "h2")]
        for o in items[:25]:
            block.append(P("• " + esc(o.location) + (f" — {esc(translate(o.detail, lang))}" if o.detail else ""), "small"))
        story.append(KeepTogether(block[:4]))
        story += block[4:]
    for key, items in (("lim_unversioned", d["unversioned"]), ("lim_nocov", d["no_coverage"]),
                       ("lim_estimated", d["estimated"])):
        if items:
            story.append(P(f"{esc(tr(key, lang))} ({len(items)})", "h2"))
            story.append(P(esc(", ".join(f"{cc.name} {cc.version or '?'}" for cc in items[:80]))
                           + (f" … +{len(items) - 80}" if len(items) > 80 else ""), "small"))
    n += 1
    story += [P(f"{n}. {esc(tr('scope', lang))}", "h1"), P(esc(method_text(d, lang)), "body"),
              P(esc(x("scope_table", lang)), "h2")]
    run_rows = []
    for r in d["runs"]:
        from .i18n import T as _T
        kind = tr("kind", lang, r["kind"]) if r["kind"] in _T["kind"] else r["kind"]
        run_rows.append([P(esc(r["time"][:16].replace("T", " "))), P(esc(r.get("target") or "—")),
                         P(esc(kind) + "<br/>" + f"<font size='6.4'>{esc(r['source'][-90:])}</font>"),
                         P(str(r.get("detections", "")))])
    if run_rows:
        story.append(table([tr("time", lang), tr("target", lang), x("source_col", lang), tr("detections", lang)],
                           run_rows, [28, 40, W / mm - 88, 20]))

    if rest:
        story += [NextPageTemplate("landscape"), PageBreak(), P(esc(x("appendix_a", lang)), "h1"),
                  table(hdr, finding_rows(rest, full=False), widths)]
        story += [NextPageTemplate("portrait")]
    affected = [p["component"] for p in d["plan"]]
    if affected:
        story += [NextPageTemplate("landscape"), PageBreak(), P(esc(tr("appendix_c", lang)), "h1"),
                  P(esc(tr("appendix_c_text", lang)), "small"), Spacer(1, 2 * mm)]
        crow = []
        for cc in affected:
            for m_, loc, det in _evidence_items(cc, lang, None):
                crow.append([P(f"<b>{esc(cc.name)}</b> {esc(cc.version)}"), P(esc(m_)), P(esc(loc), "small"),
                             P(esc(det), "small")])
        story.append(table([tr("component", lang), tr("method_col", lang), tr("location", lang), x("detail_col", lang)],
                           crow, [55, 30, 110, WL / mm - 195]))
        story += [NextPageTemplate("portrait")]
    story += [PageBreak(), P(esc(x("appendix_b", lang)) + f" ({len(d['components'])})", "h1"),
              P(esc(x("inv_note", lang)), "small"), Spacer(1, 2 * mm)]
    inv_rows = [[P(esc(base_ecosystem(cc.ecosystem))), P(esc(cc.name)), P(esc(cc.version or "?"), "mono"),
                 P(esc(tr("conf", lang, cc.confidence))), P(esc(", ".join(_targets(cc)[:2])), "small")]
                for cc in d["components"]]
    story.append(table([tr("ecosystem", lang), tr("component", lang), tr("version", lang), tr("confidence", lang),
                        tr("target", lang)], inv_rows, [22, 72, 34, 16, W / mm - 144]))
    doc.build(story)
    return out


def to_docx(d: dict, lang: str, out: Path) -> Path:
    from docx import Document
    from docx.enum.section import WD_ORIENT
    from docx.enum.text import WD_BREAK
    from docx.oxml import parse_xml
    from docx.oxml.ns import nsdecls, qn
    from docx.shared import Mm, Pt, RGBColor

    doc = Document()
    sec = doc.sections[0]
    sec.page_width, sec.page_height = Mm(210), Mm(297)
    sec.left_margin = sec.right_margin = Mm(15)
    sec.top_margin, sec.bottom_margin = Mm(15), Mm(15)
    normal = doc.styles["Normal"]
    normal.font.name = "Calibri"
    normal.font.size = Pt(9.5)
    normal.paragraph_format.space_after = Pt(4)
    acc = RGBColor(*ACCENT)
    hexc = lambda rgb: "%02X%02X%02X" % rgb
    m = d["meta"]
    title = tr("title", lang)

    def shade(cell, rgb):
        cell._tc.get_or_add_tcPr().append(parse_xml(f'<w:shd {nsdecls("w")} w:val="clear" w:color="auto" '
                                                    f'w:fill="{hexc(rgb)}"/>'))

    def heading(text, size=14):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(10)
        p.paragraph_format.keep_with_next = True
        r = p.add_run(text)
        r.bold, r.font.size, r.font.color.rgb = True, Pt(size), acc
        return p

    def para(text, size=None, bold=False, color=None):
        p = doc.add_paragraph()
        r = p.add_run(text)
        r.bold = bold
        if size:
            r.font.size = Pt(size)
        if color:
            r.font.color.rgb = RGBColor.from_string(color.lstrip("#"))
        return p

    def table(header, rows, widths_mm, size=7.5):
        t = doc.add_table(rows=1, cols=len(header))
        t.style = "Table Grid"
        t.autofit = False
        t._tbl.tblPr.append(parse_xml(f'<w:tblLayout {nsdecls("w")} w:type="fixed"/>'))
        for gc, w in zip(t._tbl.tblGrid.findall(qn("w:gridCol")), widths_mm):
            gc.set(qn("w:w"), str(int(w * 56.7)))
        for i, h in enumerate(header):
            cell = t.rows[0].cells[i]
            shade(cell, ACCENT)
            r = cell.paragraphs[0].add_run(h)
            r.bold, r.font.size, r.font.color.rgb = True, Pt(size), RGBColor(255, 255, 255)
        t.rows[0]._tr.get_or_add_trPr().append(parse_xml(f'<w:tblHeader {nsdecls("w")}/>'))
        for row in rows:
            cells = t.add_row().cells
            for i, val in enumerate(row):
                parts = val if isinstance(val, list) else [(val, {})]
                p = cells[i].paragraphs[0]
                p.paragraph_format.space_after = Pt(0)
                for j, (txt, fmt) in enumerate(parts):
                    if j and fmt.get("newline", True):
                        p.add_run().add_break(WD_BREAK.LINE)
                    r = p.add_run(str(txt))
                    r.font.size = Pt(fmt.get("size", size))
                    r.bold = fmt.get("bold", False)
                    if fmt.get("color"):
                        r.font.color.rgb = RGBColor.from_string(fmt["color"].lstrip("#"))
                    if fmt.get("mono"):
                        r.font.name = "Consolas"
        ncols = len(t.columns)
        if len(widths_mm) != ncols:
            total = sum(widths_mm)
            widths_mm = [total / ncols] * ncols
        for row in t.rows:
            for cell, w in zip(row.cells, widths_mm):
                cell.width = Mm(w)
        doc.add_paragraph()
        return t

    def landscape(on: bool):
        s = doc.add_section()
        if on:
            s.orientation = WD_ORIENT.LANDSCAPE
            s.page_width, s.page_height = Mm(297), Mm(210)
        else:
            s.orientation = WD_ORIENT.PORTRAIT
            s.page_width, s.page_height = Mm(210), Mm(297)
        s.left_margin = s.right_margin = Mm(15)

    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(120)
    r = p.add_run(title)
    r.bold, r.font.size, r.font.color.rgb = True, Pt(26), acc
    para(m.get("name", ""), 14, color="#444444")
    doc.add_paragraph()
    for k, v in ((tr("client", lang), m.get("client") or "—"), (x("prepared", lang), datetime.now().strftime("%d.%m.%Y")),
                 (tr("db_state", lang), _db_line(d["db"])), (tr("components", lang), str(len(d["components"]))),
                 (tr("findings", lang), str(len(d["findings"])))):
        p = doc.add_paragraph()
        r = p.add_run(f"{k}: ")
        r.bold = True
        p.add_run(v)
    para(x("confidential", lang), bold=True)
    doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)

    sev = d["severity"]
    heading(f"1. {tr('summary', lang)}")
    para(tr("summary_text", lang).format(n=len(d["components"]), a=d["affected_components"], f=len(d["findings"]),
                                         c=sev.get("CRITICAL", 0), h=sev.get("HIGH", 0)))
    if d["kev"]:
        para(tr("kev_text", lang).format(k=d["kev"]), bold=True)
    if d["malicious"]:
        para(tr("mal_text", lang).format(m=d["malicious"]), bold=True)
    table([tr("sev", lang, s) for s in SEVS] + ["KEV"],
          [[[(str(sev.get(s, 0)), {"bold": True, "size": 14, "color": SEV_COLORS[s]})] for s in SEVS]
           + [[(str(d["kev"]), {"bold": True, "size": 14})]]], [30] * 6, size=9)
    if d["plan"]:
        heading(tr("top_actions", lang), 11)
        for pl in d["plan"][:7]:
            comp = pl["component"]
            doc.add_paragraph(tr("upgrade_line", lang).format(c=f"{comp.name}@{comp.version}",
                                                              v=pl["target"] or tr("no_fix", lang),
                                                              n=len(pl["findings"])) + (" [KEV]" if pl["kev"] else ""),
                              style="List Bullet")

    landscape(True)
    heading(f"2. {tr('plan', lang)}")
    para(tr("plan_intro", lang), 8, color="#5b6472")
    rows = []
    for i, pl in enumerate(d["plan"], 1):
        comp = pl["component"]
        cnt = [(f"{tr('sev', lang, s)} {pl['counts'][s]}", {"color": SEV_COLORS[s], "bold": True})
               for s in SEVS if pl["counts"].get(s)]
        if pl["kev"]:
            cnt.append((f"KEV×{pl['kev']}", {"bold": True}))
        rows.append([str(i), [(comp.name, {"bold": True}), (base_ecosystem(comp.ecosystem), {"size": 6.5})],
                     [(comp.version, {"mono": True})], [(pl["target"] or tr("no_fix", lang), {"mono": True})],
                     cnt or "—", _relation(comp, lang),
                     [(", ".join(_targets(comp)[:3]), {})] + [(loc, {"size": 6.5}) for loc in _locations(comp, 2)]])
    table(["#", tr("component", lang), tr("current", lang), tr("recommended", lang), tr("vulns", lang),
           tr("relation", lang), tr("target_loc", lang)], rows, [8, 52, 28, 28, 42, 40, 69])

    main = [f for f in d["findings"] if f.severity in MAIN_SEVS or f.kev or f.malicious]
    rest = [f for f in d["findings"] if f not in main]
    comps = d["comps_by_key"]

    def frows(fs, full=True):
        out_rows = []
        for f in fs:
            cc = comps.get(f.component_key)
            ident = [(f.vuln_id, {"bold": True})]
            if _cves(f):
                ident.append((", ".join(_cves(f)[:3]), {}))
            if full and f.summary:
                ident.append((f.summary[:220], {"size": 6.5, "color": "#5b6472"}))
            sv = [(tr("sev", lang, f.severity if f.severity in SEVS else "UNKNOWN")
                   + (f" {f.cvss_score}" if f.cvss_score is not None else ""), {"bold": True,
                                                                                "color": SEV_COLORS.get(f.severity)})]
            if f.kev:
                sv.append(("KEV", {"bold": True}))
            if f.epss is not None:
                sv.append((f"EPSS {f.epss * 100:.1f}%", {}))
            ct = [(f"{cc.name if cc else f.component_purl} {cc.version if cc else ''}", {"bold": True})]
            loc = []
            for m_, lc, det in (_evidence_items(cc, lang, 4 if full else 2) if cc else []):
                loc += [(m_, {"bold": True, "size": 6.8}), (lc, {"size": 6.8})]
                if det and full:
                    loc.append((det, {"size": 6.2, "color": "#5b6472"}))
            conf = [(tr("conf", lang, f.confidence), {})]
            if f.reachability:
                conf.append((tr("reach", lang, f.reachability), {"size": 6.5}))
            if f.source != "OSV":
                conf.append((f.source, {"size": 6.5}))
            out_rows.append([ident, sv, ct, loc or "—",
                             [(f.upgrade_to or ", ".join(f.fixed_versions[:2]) or "—", {"mono": True})], conf])
        return out_rows

    hdr = [tr("id", lang), tr("severity", lang), tr("component", lang), tr("location", lang), tr("fix", lang),
           tr("confidence", lang)]
    dwidths = [60, 26, 38, 84, 30, 29]
    doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)
    heading(f"3. {x('details_main', lang)}")
    if main:
        table(hdr, frows(main), dwidths)
    else:
        para(tr("none", lang))

    landscape(False)
    n = 4
    if d["usage"]["imported"] or d["usage"]["not-imported"]:
        heading(f"{n}. {tr('usage_title', lang)}")
        para(tr("usage_text", lang))
        doc.add_paragraph(tr("usage_stats", lang).format(i=d["usage"]["imported"], n=d["usage"]["not-imported"]),
                          style="List Bullet")
        if d["reach"]["called"] or d["reach"]["not-called"]:
            doc.add_paragraph(tr("reach_stats", lang).format(c=d["reach"]["called"], n=d["reach"]["not-called"]),
                              style="List Bullet")
        n += 1
    for blk in license_blocks(d, lang) + supply_blocks(d, lang) + suppressed_blocks(d, lang):
        if blk[0] == "h":
            heading(f"{n}. {blk[1]}")
            n += 1
        elif blk[0] in ("p", "note"):
            para(blk[1], 9)
        elif blk[0] == "list":
            for item in blk[1]:
                doc.add_paragraph(item, style="List Bullet")
        elif blk[0] == "table":
            table(blk[1], blk[2], [55, 25, 40, 30, 30])
    heading(f"{n}. {tr('limits', lang)}")
    if d["blackbox"]:
        para(tr("lim_blackbox", lang), 8.5)
    if d["nvd_findings"]:
        para(tr("nvd_note", lang), 8.5)
    from .i18n import T
    groups = {}
    for o in d["observations"]:
        groups.setdefault(o.kind, []).append(o)
    for kind, items in groups.items():
        heading((tr("obs", lang, kind) if kind in T["obs"] else kind) + f" ({len(items)})", 10.5)
        for o in items[:25]:
            para(f"• {o.location}" + (f" — {translate(o.detail, lang)}" if o.detail else ""), 7.5)
    for key, items in (("lim_unversioned", d["unversioned"]), ("lim_nocov", d["no_coverage"])):
        if items:
            heading(f"{tr(key, lang)} ({len(items)})", 10.5)
            para(", ".join(f"{cc.name} {cc.version or '?'}" for cc in items[:80]), 7.5)
    n += 1
    heading(f"{n}. {tr('scope', lang)}")
    para(method_text(d, lang))
    table([tr("time", lang), tr("target", lang), x("source_col", lang), tr("detections", lang)],
          [[r["time"][:16].replace("T", " "), r.get("target") or "—",
            [(tr("kind", lang, r["kind"]) if r["kind"] in T["kind"] else r["kind"], {}),
             (r["source"][-90:], {"size": 6.5})], str(r.get("detections", ""))] for r in d["runs"]],
          [28, 40, 92, 20])
    affected = [p["component"] for p in d["plan"]]
    if rest or affected:
        landscape(True)
        if rest:
            heading(x("appendix_a", lang))
            table(hdr, frows(rest, False), dwidths)
        if affected:
            heading(tr("appendix_c", lang))
            para(tr("appendix_c_text", lang), 8, color="#5b6472")
            crow = []
            for cc in affected:
                for m_, loc, det in _evidence_items(cc, lang, None):
                    crow.append([[(cc.name, {"bold": True}), (cc.version or "", {})], m_, [(loc, {"size": 7})],
                                 [(det, {"size": 6.5, "color": "#5b6472"})] if det else "—"])
            table([tr("component", lang), tr("method_col", lang), tr("location", lang),
                   x("detail_col", lang)], crow, [55, 30, 110, 72])
        landscape(False)
    else:
        doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)
    heading(x("appendix_b", lang) + f" ({len(d['components'])})")
    para(x("inv_note", lang), 8, color="#5b6472")
    table([tr("ecosystem", lang), tr("component", lang), tr("version", lang), tr("confidence", lang),
           tr("target", lang)],
          [[base_ecosystem(cc.ecosystem), cc.name, [(cc.version or "?", {"mono": True})],
            tr("conf", lang, cc.confidence), ", ".join(_targets(cc)[:2])] for cc in d["components"]],
          [22, 72, 34, 16, 36], size=7)

    for s in doc.sections:
        s.footer.is_linked_to_previous = True
    fp = doc.sections[0].footer.paragraphs[0]
    rr = fp.add_run(f"{title} — {m.get('client') or m.get('name')}   ·   {x('confidential', lang)}   ·   {x('page', lang)} ")
    rr.font.size = Pt(7)
    rr = fp.add_run()
    rr.font.size = Pt(7)
    for xml in (f'<w:fldChar {nsdecls("w")} w:fldCharType="begin"/>',
                f'<w:instrText {nsdecls("w")} xml:space="preserve"> PAGE </w:instrText>',
                f'<w:fldChar {nsdecls("w")} w:fldCharType="end"/>'):
        rr._r.append(parse_xml(xml))
    doc.core_properties.title = f"{title} — {m.get('name')}"
    doc.save(str(out))
    return out
