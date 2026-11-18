import re
import sys
from datetime import date, datetime, time
from pathlib import Path

from build import ACCENT, LIGHT, NOTE_BG, NOTE_BORDER
from content import UI, VERSION, resolve
from guide_content import SECTIONS, SUBTITLE, TITLE, localize

CODE_INLINE = re.compile(r"L:([^|\n]+)\|([^\n]+)")
TOKENS = re.compile(r"(\*\*.+?\*\*|`[^`]+`|\*[^*\s][^*]*\*)")
CODE_MAX = 104

GUIDE_SPEC = {'title': TITLE, 'subtitle': SUBTITLE, 'sections': SECTIONS, 'breaks': (2, 8, 10)}
TOC_LABEL = {"tr": "İçindekiler", "en": "Contents"}
CHECK = "☐"


def code_loc(s, lang):
    return CODE_INLINE.sub(lambda m: m.group(1) if lang == "tr" else m.group(2), s)


def tokens(text):
    out = []
    for part in TOKENS.split(text):
        if not part:
            continue
        if part.startswith("**"):
            out.append(("b", part[2:-2]))
        elif part.startswith("`"):
            out.append(("c", part[1:-1]))
        elif part.startswith("*") and part.endswith("*") and len(part) > 2:
            out.append(("i", part[1:-1]))
        else:
            out.append(("t", part))
    return out


def cell_text(v, lang):
    return resolve(v, lang) if isinstance(v, dict) else v


def build_pdf(lang, out, spec=None):
    spec = spec or GUIDE_SPEC
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import (KeepTogether, ListFlowable, ListItem, PageBreak, Paragraph,
                                    SimpleDocTemplate, Spacer, Table, TableStyle, XPreformatted)

    fdir = "/usr/share/fonts/truetype/dejavu/"
    for name, f in (("DV", "DejaVuSans.ttf"), ("DVB", "DejaVuSans-Bold.ttf"), ("DVM", "DejaVuSansMono.ttf")):
        pdfmetrics.registerFont(TTFont(name, fdir + f))
    pdfmetrics.registerFontFamily("DV", normal="DV", bold="DVB")

    c = lambda rgb: colors.Color(*(v / 255 for v in rgb))
    ACC, LT = c(ACCENT), c(LIGHT)
    W = A4[0] - 30 * mm

    st = {
        "title": ParagraphStyle("t", fontName="DVB", fontSize=20, leading=25, textColor=ACC),
        "subtitle": ParagraphStyle("st", fontName="DV", fontSize=13, leading=17, textColor=colors.HexColor("#444")),
        "h1": ParagraphStyle("h1", fontName="DVB", fontSize=13, leading=17, textColor=ACC, spaceBefore=6, spaceAfter=6),
        "h2": ParagraphStyle("h2", fontName="DVB", fontSize=10, leading=13, textColor=ACC, spaceBefore=8, spaceAfter=3),
        "body": ParagraphStyle("b", fontName="DV", fontSize=8.8, leading=12.2, spaceAfter=4),
        "cell": ParagraphStyle("c", fontName="DV", fontSize=8, leading=10.4),
        "hdr": ParagraphStyle("hd", fontName="DVB", fontSize=8, leading=10, textColor=colors.white),
        "code": ParagraphStyle("code", fontName="DVM", fontSize=7.2, leading=9.4),
        "note": ParagraphStyle("n", fontName="DV", fontSize=8.3, leading=11.2),
        "q": ParagraphStyle("q", fontName="DVB", fontSize=8.8, leading=12, textColor=ACC, spaceBefore=4),
        "toc": ParagraphStyle("toc", fontName="DV", fontSize=9, leading=13),
    }

    def esc(s):
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def md(text):
        out = []
        for kind, s in tokens(text):
            s = esc(s)
            if kind == "b":
                out.append(f"<b>{s}</b>")
            elif kind == "i":
                out.append(f'<font color="#1F3A5F">{s}</font>')
            elif kind == "c":
                out.append(f'<font name="DVM" size="7.6" color="#8a2c0d">{s}</font>')
            else:
                out.append(s)
        return "".join(out)

    def code_block(code):
        lines = []
        for line in code_loc(code, lang).split("\n"):
            if len(line) > CODE_MAX:
                print(f"  [uyarı] kod satırı {len(line)} karakter: {line[:60]}…", file=sys.stderr)
            pos = line.find("# ")
            if pos == 0 or (pos > 0 and line[pos - 1] == " "):
                lines.append(esc(line[:pos]) + f'<font color="#6b7785">{esc(line[pos:])}</font>')
            else:
                lines.append(esc(line))
        t = Table([[XPreformatted("\n".join(lines), st["code"])]], colWidths=[W])
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F3F5F8")),
                               ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9d1dc")),
                               ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                               ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
        return t

    def note_box(text):
        bold, rest = text.split(":", 1)
        t = Table([[Paragraph(f"<b>{esc(bold)}:</b>{md(rest)}", st["note"])]], colWidths=[W])
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), c(NOTE_BG)),
                               ("LINEBEFORE", (0, 0), (0, -1), 3, c(NOTE_BORDER)),
                               ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                               ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
        return t

    def table(header, rows, widths):
        data = [[Paragraph(md(h), st["hdr"]) for h in header]]
        data += [[Paragraph(md(cell_text(v, lang)) if i else f"<b>{md(cell_text(v, lang))}</b>", st["cell"])
                  for i, v in enumerate(r)] for r in rows]
        t = Table(data, colWidths=[w * mm for w in widths], repeatRows=1)
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), ACC), ("BACKGROUND", (0, 1), (0, -1), LT),
                               ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#b9c3d0")),
                               ("VALIGN", (0, 0), (-1, -1), "TOP"),
                               ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
        return t

    def bullets(items, start="•"):
        return ListFlowable([ListItem(Paragraph(md(x), st["body"]), leftIndent=12) for x in items],
                            bulletType="bullet", start=start, leftIndent=12, bulletFontName="DV",
                            bulletFontSize=9 if start == "•" else 10)

    sections = localize(resolve(spec['sections'], lang), lang)
    story = [Spacer(1, 6 * mm), Paragraph(resolve(spec['title'], lang), st["title"]), Spacer(1, 2 * mm),
             Paragraph(resolve(spec['subtitle'], lang), st["subtitle"]), Spacer(1, 3 * mm),
             Table([[""]], colWidths=[W], rowHeights=[1.2 * mm],
                   style=TableStyle([("BACKGROUND", (0, 0), (-1, -1), ACC)])),
             Spacer(1, 5 * mm), Paragraph(TOC_LABEL[lang], st["h2"])]
    story += [Paragraph(esc(s["title"]), st["toc"]) for s in sections]
    story.append(Spacer(1, 4 * mm))

    for si, sec in enumerate(sections):
        if si in spec['breaks']:
            story.append(PageBreak())
        head = [Paragraph(esc(sec["title"]), st["h1"])]
        for b in sec["blocks"]:
            t = b["type"]
            if t == "sub":
                fl = [Paragraph(md(b["title"]), st["h2"])]
            elif t == "para":
                fl = [Paragraph(md(b["text"]), st["body"])]
            elif t == "code":
                fl = [code_block(b["code"]), Spacer(1, 3 * mm)]
            elif t == "note":
                fl = [note_box(b["text"]), Spacer(1, 3 * mm)]
            elif t == "bullets":
                fl = [bullets(b["items"]), Spacer(1, 2 * mm)]
            elif t == "checklist":
                fl = [bullets(b["items"], start=CHECK)]
            elif t == "table":
                fl = [table(b["header"], b["rows"], b["widths"]), Spacer(1, 3 * mm)]
            elif t == "faq":
                fl = []
                for q, a in b["items"]:
                    fl.append(KeepTogether([Paragraph(md(q), st["q"]), Paragraph(md(a), st["body"])]))
            if t == "sub":
                head += fl
                continue
            story.append(KeepTogether(head + fl[:1]))
            story += fl[1:]
            head = []
        story += head

    conf, page, ver = (resolve(UI[k], lang) for k in ("confidential", "page", "version"))
    footer = f"{resolve(spec['title'], lang)} — {resolve(spec['subtitle'], lang)}"

    def on_page(cv, doc):
        cv.saveState()
        cv.setStrokeColor(colors.HexColor("#b9c3d0"))
        cv.setLineWidth(0.4)
        cv.line(15 * mm, 13 * mm, A4[0] - 15 * mm, 13 * mm)
        cv.setFont("DV", 7)
        cv.setFillColor(colors.HexColor("#666"))
        cv.drawString(15 * mm, 9 * mm, footer)
        cv.drawRightString(A4[0] - 15 * mm, 9 * mm, f"{conf}  ·  {ver} {VERSION}  ·  {page} {doc.page}")
        cv.restoreState()

    doc = SimpleDocTemplate(str(out), pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm,
                            topMargin=14 * mm, bottomMargin=18 * mm, title=footer, subject="SCA",
                            lang="tr-TR" if lang == "tr" else "en-US")
    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)


def build_docx(lang, out, spec=None):
    spec = spec or GUIDE_SPEC
    from docx import Document
    from docx.enum.text import WD_BREAK
    from docx.oxml import parse_xml
    from docx.oxml.ns import nsdecls, qn
    from docx.shared import Mm, Pt, RGBColor

    doc = Document()
    s0 = doc.sections[0]
    s0.page_width, s0.page_height = Mm(210), Mm(297)
    s0.left_margin = s0.right_margin = Mm(15)
    s0.top_margin, s0.bottom_margin = Mm(14), Mm(16)
    normal = doc.styles["Normal"]
    normal.font.name = "Calibri"
    normal.font.size = Pt(9.5)
    normal.paragraph_format.space_after = Pt(4)

    acc = RGBColor(*ACCENT)
    hexc = lambda rgb: "%02X%02X%02X" % rgb

    def shade(el, rgb):
        el.append(parse_xml(f'<w:shd {nsdecls("w")} w:val="clear" w:color="auto" w:fill="{hexc(rgb)}"/>'))

    def add_md(p, text, size=None, color=None):
        for kind, s in tokens(text):
            r = p.add_run(s)
            if size:
                r.font.size = Pt(size)
            if color:
                r.font.color.rgb = RGBColor(*color)
            if kind == "b":
                r.bold = True
            elif kind == "i":
                r.italic = True
            elif kind == "c":
                r.font.name = "Consolas"
                r.font.size = Pt((size or 9.5) - 0.8)
                r.font.color.rgb = RGBColor(0x8A, 0x2C, 0x0D)
        return p

    def heading(text, lvl):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(10 if lvl == 1 else 7)
        p.paragraph_format.space_after = Pt(3)
        p.paragraph_format.keep_with_next = True
        r = p.add_run(text)
        r.bold = True
        r.font.size = Pt(13 if lvl == 1 else 10.5)
        r.font.color.rgb = acc

    def fixed_widths(t, widths_mm):
        t.autofit = False
        t._tbl.tblPr.append(parse_xml(f'<w:tblLayout {nsdecls("w")} w:type="fixed"/>'))
        for gc, w in zip(t._tbl.tblGrid.findall(qn("w:gridCol")), widths_mm):
            gc.set(qn("w:w"), str(int(w * 56.7)))
        for row in t.rows:
            for i, w in enumerate(widths_mm):
                row.cells[i].width = Mm(w)

    def keep_whole(t):
        t.rows[0]._tr.get_or_add_trPr().append(parse_xml(f'<w:cantSplit {nsdecls("w")}/>'))

    def code_block(code):
        t = doc.add_table(rows=1, cols=1)
        t.style = "Table Grid"
        keep_whole(t)
        cell = t.rows[0].cells[0]
        shade(cell._tc.get_or_add_tcPr(), (0xF3, 0xF5, 0xF8))
        p = cell.paragraphs[0]
        p.paragraph_format.space_after = Pt(0)
        lines = code_loc(code, lang).split("\n")
        for i, line in enumerate(lines):
            pos = line.find("# ")
            parts = [(line, None)]
            if pos == 0 or (pos > 0 and line[pos - 1] == " "):
                parts = [(line[:pos], None), (line[pos:], (0x6B, 0x77, 0x85))]
            for txt, col in parts:
                if not txt:
                    continue
                r = p.add_run(txt)
                r.font.name = "Consolas"
                r.font.size = Pt(7.5)
                if col:
                    r.font.color.rgb = RGBColor(*col)
            if i < len(lines) - 1:
                p.add_run().add_break(WD_BREAK.LINE)
        fixed_widths(t, [180])
        doc.add_paragraph().paragraph_format.space_after = Pt(0)

    def note_box(text):
        bold, rest = text.split(":", 1)
        t = doc.add_table(rows=1, cols=1)
        keep_whole(t)
        cell = t.rows[0].cells[0]
        tcPr = cell._tc.get_or_add_tcPr()
        shade(tcPr, NOTE_BG)
        tcPr.append(parse_xml(f'<w:tcBorders {nsdecls("w")}><w:left w:val="single" w:sz="24" '
                              f'w:color="{hexc(NOTE_BORDER)}"/></w:tcBorders>'))
        p = cell.paragraphs[0]
        r = p.add_run(bold + ":")
        r.bold = True
        r.font.size = Pt(8.5)
        add_md(p, rest, size=8.5)
        fixed_widths(t, [180])
        doc.add_paragraph().paragraph_format.space_after = Pt(0)

    def table(header, rows, widths):
        t = doc.add_table(rows=1, cols=len(header))
        t.style = "Table Grid"
        for i, h in enumerate(header):
            cell = t.rows[0].cells[i]
            shade(cell._tc.get_or_add_tcPr(), ACCENT)
            add_md(cell.paragraphs[0], h, size=8.5, color=(255, 255, 255)).runs[0].bold = True
        t.rows[0]._tr.get_or_add_trPr().append(parse_xml(f'<w:tblHeader {nsdecls("w")}/>'))
        for r in rows:
            cells = t.add_row().cells
            for i, v in enumerate(r):
                p = add_md(cells[i].paragraphs[0], cell_text(v, lang), size=8.5)
                p.paragraph_format.space_after = Pt(1)
                if i == 0:
                    for run in p.runs:
                        run.bold = True
                    shade(cells[0]._tc.get_or_add_tcPr(), LIGHT)
        fixed_widths(t, widths)
        doc.add_paragraph().paragraph_format.space_after = Pt(0)

    def bullet_list(items, check=False):
        for x in items:
            p = doc.add_paragraph(style="List Bullet")
            if check:
                p.style = doc.styles["Normal"]
                p.paragraph_format.left_indent = Mm(6)
                p.paragraph_format.first_line_indent = Mm(-6)
                p.add_run(CHECK + "  ").font.size = Pt(11)
            add_md(p, x)

    sections = localize(resolve(spec['sections'], lang), lang)
    p = doc.add_paragraph()
    r = p.add_run(resolve(spec['title'], lang))
    r.bold, r.font.size, r.font.color.rgb = True, Pt(20), acc
    p = doc.add_paragraph()
    r = p.add_run(resolve(spec['subtitle'], lang))
    r.font.size, r.font.color.rgb = Pt(13), RGBColor(0x44, 0x44, 0x44)
    p._p.get_or_add_pPr().append(parse_xml(f'<w:pBdr {nsdecls("w")}><w:bottom w:val="single" w:sz="18" '
                                           f'w:space="6" w:color="{hexc(ACCENT)}"/></w:pBdr>'))
    heading(TOC_LABEL[lang], 2)
    for s in sections:
        doc.add_paragraph(s["title"]).paragraph_format.space_after = Pt(1)

    for si, sec in enumerate(sections):
        if si in spec['breaks']:
            doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)
        heading(sec["title"], 1)
        for b in sec["blocks"]:
            t = b["type"]
            if t == "sub":
                heading(b["title"], 2)
            elif t == "para":
                p = add_md(doc.add_paragraph(), b["text"])
                p.paragraph_format.keep_with_next = b["text"].rstrip().endswith(":")
            elif t == "code":
                code_block(b["code"])
            elif t == "note":
                note_box(b["text"])
            elif t == "bullets":
                bullet_list(b["items"])
            elif t == "checklist":
                bullet_list(b["items"], check=True)
            elif t == "table":
                table(b["header"], b["rows"], b["widths"])
            elif t == "faq":
                for q, a in b["items"]:
                    qp = add_md(doc.add_paragraph(), q)
                    qp.paragraph_format.keep_with_next = True
                    qp.paragraph_format.space_before = Pt(6)
                    for run in qp.runs:
                        run.bold = True
                        run.font.color.rgb = acc
                    add_md(doc.add_paragraph(), a)

    conf, page, ver = (resolve(UI[k], lang) for k in ("confidential", "page", "version"))
    fp = s0.footer.paragraphs[0]
    run = fp.add_run(f"{resolve(spec['title'], lang)} — {resolve(spec['subtitle'], lang)}   ·   {conf}   ·   {ver} {VERSION}   ·   {page} ")
    run.font.size = Pt(7)
    run.font.color.rgb = RGBColor(0x66, 0x66, 0x66)
    r = fp.add_run()
    r.font.size = Pt(7)
    for x in (f'<w:fldChar {nsdecls("w")} w:fldCharType="begin"/>',
              f'<w:instrText {nsdecls("w")} xml:space="preserve"> PAGE </w:instrText>',
              f'<w:fldChar {nsdecls("w")} w:fldCharType="end"/>'):
        r._r.append(parse_xml(x))

    cp = doc.core_properties
    cp.title = f"{resolve(spec['title'], lang)} — {resolve(spec['subtitle'], lang)}"
    cp.subject = "SCA"
    cp.language = "tr-TR" if lang == "tr" else "en-US"
    cp.created = cp.modified = datetime.combine(date.today(), time())
    doc.save(str(out))


if __name__ == "__main__":
    outdir = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    outdir.mkdir(parents=True, exist_ok=True)
    names = {"tr": "SCA_Hizmeti_Veri_Hazirlama_Kilavuzu_TR", "en": "SCA_Service_Data_Preparation_Guide_EN"}
    for lang, base in names.items():
        build_pdf(lang, outdir / f"{base}.pdf")
        build_docx(lang, outdir / f"{base}.docx")
        print("ok", lang)
