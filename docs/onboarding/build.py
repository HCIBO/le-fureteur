import re
import sys
from datetime import date, datetime, time
from pathlib import Path

from content import LEVELS, OPTS, SECTIONS, SUBTITLE, TITLE, UI, VERSION, L, resolve

INLINE = re.compile(r"L:([^|]+?)\|([^)\n]+)")


def loc(s, lang):
    return INLINE.sub(lambda m: m.group(1) if lang == "tr" else m.group(2), s)


CODE_INLINE = re.compile(r"L:([^|\n]+)\|([^\n]+)")


def loc_code(s, lang):
    return CODE_INLINE.sub(lambda m: m.group(1) if lang == "tr" else m.group(2), s)


def opts_for(row, lang):
    o = row.get("opts", "vyu")
    o = OPTS[o] if isinstance(o, str) else o
    return resolve(o, lang)


ACCENT = (0x1F, 0x3A, 0x5F)
LIGHT = (0xE8, 0xEE, 0xF5)
NOTE_BG = (0xFF, 0xF4, 0xE0)
NOTE_BORDER = (0xE0, 0x9A, 0x2B)
LEVEL_COLORS = {"Z": (0xB0, 0x2A, 0x2A), "K": (0xB3, 0x6B, 0x00), "O": (0x3B, 0x6E, 0x3B),
                "S1": (0x4A, 0x5A, 0x6A), "S2": (0x2E, 0x7D, 0x32), "S3": (0x1F, 0x3A, 0x5F)}
ANSWER_BG = (0xE8, 0xF1, 0xFB)

FORM_SPEC = {
    "title": TITLE, "subtitle": SUBTITLE, "sections": SECTIONS, "breaks": (1, 2, 3), "legend_at": 1,
    "legend": [
        ("Z", L("Eksikse analiz başlatılamaz / kapsam daraltılır",
                "If missing, analysis cannot start / scope is reduced")),
        ("K", L("İlgili teknoloji / durum sizde varsa zorunludur",
                "Mandatory if the related technology / situation applies")),
        ("O", L("Sonuçların kapsamını ve doğruluğunu artırır", "Increases coverage and accuracy of results")),
    ],
}


def build_pdf(lang, out, spec=FORM_SPEC):
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import (Flowable, KeepTogether, ListFlowable, ListItem, PageBreak,
                                    Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle)

    fdir = "/usr/share/fonts/truetype/dejavu/"
    pdfmetrics.registerFont(TTFont("DV", fdir + "DejaVuSans.ttf"))
    pdfmetrics.registerFont(TTFont("DVB", fdir + "DejaVuSans-Bold.ttf"))
    pdfmetrics.registerFont(TTFont("DVM", fdir + "DejaVuSansMono.ttf"))
    pdfmetrics.registerFontFamily("DV", normal="DV", bold="DVB")

    c = lambda rgb: colors.Color(*(v / 255 for v in rgb))
    ACC, LT = c(ACCENT), c(LIGHT)

    st = {
        "title": ParagraphStyle("t", fontName="DVB", fontSize=20, leading=25, textColor=ACC),
        "subtitle": ParagraphStyle("st", fontName="DV", fontSize=13, leading=17, textColor=colors.HexColor("#444")),
        "h1": ParagraphStyle("h1", fontName="DVB", fontSize=13.5, leading=17, textColor=ACC,
                             spaceBefore=4, spaceAfter=6),
        "h2": ParagraphStyle("h2", fontName="DVB", fontSize=10.5, leading=14, textColor=ACC,
                             spaceBefore=8, spaceAfter=4),
        "body": ParagraphStyle("b", fontName="DV", fontSize=9, leading=12.5, alignment=TA_LEFT, spaceAfter=5),
        "cell": ParagraphStyle("c", fontName="DV", fontSize=8, leading=10),
        "cellb": ParagraphStyle("cb", fontName="DVB", fontSize=8, leading=10),
        "hint": ParagraphStyle("h", fontName="DV", fontSize=6.8, leading=8.6, textColor=colors.HexColor("#5a5a5a")),
        "hdr": ParagraphStyle("hd", fontName="DVB", fontSize=7.8, leading=9.5, textColor=colors.white),
        "mono": ParagraphStyle("m", fontName="DVM", fontSize=6.8, leading=8.6),
        "note": ParagraphStyle("n", fontName="DV", fontSize=8.3, leading=11.2),
        "ans_q": ParagraphStyle("aq", fontName="DVB", fontSize=10, leading=13.5, textColor=ACC, spaceAfter=3),
        "code": ParagraphStyle("code", fontName="DVM", fontSize=7.2, leading=9.4),
    }

    W = A4[0] - 30 * mm
    counter = {"n": 0}

    class Radio(Flowable):

        def __init__(self, name, options, width, line=4.3 * mm):
            super().__init__()
            self.name, self.options, self.width, self.line = name, options, width, line
            self.height = line * len(options)

        def draw(self):
            cv = self.canv
            for i, label in enumerate(self.options):
                y = self.height - (i + 1) * self.line + 0.6 * mm
                cv.acroForm.radio(name=self.name, value=f"o{i}", selected=False, buttonStyle="check",
                                  shape="square", size=3.4 * mm, x=0, y=y, borderWidth=0.8,
                                  borderColor=ACC, fillColor=colors.white, textColor=ACC,
                                  fieldFlags="radio", relative=True, tooltip=label)
                cv.setFont("DV", 7.2)
                cv.setFillColor(colors.black)
                cv.drawString(4.6 * mm, y + 0.9 * mm, label)

    class Field(Flowable):
        def __init__(self, name, width, height):
            super().__init__()
            self.name, self.width, self.height = name, width, height

        def draw(self):
            multi = self.height > 7 * mm
            self.canv.acroForm.textfield(name=self.name, x=0, y=0, width=self.width, height=self.height,
                                         borderWidth=0.5, borderColor=colors.HexColor("#9aa7b8"),
                                         fillColor=colors.HexColor("#F7F9FC"), textColor=colors.black,
                                         fontName="Helvetica", fontSize=8 if multi else 9,
                                         fieldFlags="multiline" if multi else "", relative=True)

    def fname(prefix):
        counter["n"] += 1
        return f"{prefix}_{counter['n']}"

    def level_par(code):
        col = "#%02x%02x%02x" % LEVEL_COLORS[code]
        return Paragraph(f'<font color="{col}" size="7.3"><b>{resolve(LEVELS[code], lang)}</b></font>', st["cell"])

    def item_cell(row):
        parts = [Paragraph(row["text"], st["cell"])]
        if row.get("hint"):
            parts.append(Paragraph(row["hint"], st["hint"]))
        return parts

    base_ts = [
        ("FONT", (0, 0), (-1, -1), "DV", 8),
        ("BACKGROUND", (0, 0), (-1, 0), ACC),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#b9c3d0")),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]

    def items_table(rows):
        cw = [17 * mm, 71 * mm, 26 * mm, 30 * mm, W - 144 * mm]
        hdr = [Paragraph(resolve(UI[k], lang), st["hdr"])
               for k in ("col_id", "col_item", "col_level", "col_status", "col_note")]
        data, ts = [hdr], list(base_ts)
        for i, r in enumerate(rows, start=1):
            if r.get("field"):
                h = (r.get("lines", 1) * 5 + 3) * mm
                data.append([Paragraph(f"<b>{r['id']}</b>", st["cell"]), item_cell(r), level_par(r["level"]),
                             Field(r["id"], cw[3] + cw[4] - 8, h), ""])
                ts.append(("SPAN", (3, i), (4, i)))
            else:
                data.append([Paragraph(f"<b>{r['id']}</b>", st["cell"]), item_cell(r), level_par(r["level"]),
                             Radio(r["id"], opts_for(r, lang), cw[3] - 8),
                             Field(r["id"] + "_note", cw[4] - 8, 11 * mm)])
            if i % 2 == 0:
                ts.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#F8FAFC")))
        return Table(data, colWidths=cw, repeatRows=1, style=TableStyle(ts))

    def eco_table(rows):
        cw = [30 * mm, 74 * mm, 44 * mm, W - 148 * mm]
        hdr = [Paragraph(resolve(UI[k], lang), st["hdr"]) for k in ("col_tech", "col_files", "col_cmd", "col_status")]
        data, ts = [hdr], list(base_ts)
        m, lk = resolve(UI["manifest"], lang), resolve(UI["lock"], lang)
        for i, (tech, man, lock, cmd) in enumerate(rows, start=1):
            br = lambda s: loc(s, lang).replace("\n", "<br/>")
            files = [Paragraph(f"<b>{m}:</b> {br(man)}", st["cell"]),
                     Paragraph(f"<b>{lk}:</b> {br(lock)}", st["cell"])]
            cmd_style = st["mono"] if not cmd.startswith("L:") else st["hint"]
            data.append([Paragraph(f"<b>{br(tech)}</b>", st["cell"]), files, Paragraph(br(cmd), cmd_style),
                         Radio(fname("eco"), resolve(OPTS["eco"], lang), cw[3] - 8)])
            if i % 2 == 0:
                ts.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#F8FAFC")))
        return Table(data, colWidths=cw, repeatRows=1, style=TableStyle(ts))

    def fields_table(labels):
        cw = [58 * mm, W - 58 * mm]
        data = []
        for lb in labels:
            tall = isinstance(lb, dict)
            text = lb["label"] if tall else lb
            data.append([Paragraph(f"<b>{text}</b>", st["cell"]),
                         Field(fname("gen"), cw[1] - 8, (16 if tall else 6) * mm)])
        ts = list(base_ts)
        ts[1] = ("BACKGROUND", (0, 0), (0, -1), LT)
        return Table(data, colWidths=cw, style=TableStyle(ts))

    def compare_table(header, rows, widths=None):
        n = len(header)
        cw = [w * mm for w in widths] if widths else [36 * mm] + [(W - 36 * mm) / (n - 1)] * (n - 1)
        data = [[Paragraph(h, st["hdr"]) for h in header]]
        data += [[Paragraph(f"<b>{v}</b>" if i == 0 else v, st["cell"]) for i, v in enumerate(r)] for r in rows]
        ts = list(base_ts) + [("BACKGROUND", (0, 1), (0, -1), LT), ("VALIGN", (0, 0), (-1, -1), "TOP")]
        return Table(data, colWidths=cw, repeatRows=1, style=TableStyle(ts))

    def note_box(text):
        bold, rest = text.split(":", 1)
        t = Table([[Paragraph(f"<b>{bold}:</b>{rest}", st["note"])]], colWidths=[W])
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), c(NOTE_BG)),
                               ("LINEBEFORE", (0, 0), (0, -1), 3, c(NOTE_BORDER)),
                               ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                               ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
        return t

    def answer_box(title, text):
        t = Table([[[Paragraph(f"<b>{title}</b>", st["ans_q"]), Paragraph(text, st["note"])]]], colWidths=[W])
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), c(ANSWER_BG)),
                               ("LINEBEFORE", (0, 0), (0, -1), 3, ACC),
                               ("LEFTPADDING", (0, 0), (-1, -1), 9), ("RIGHTPADDING", (0, 0), (-1, -1), 9),
                               ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7)]))
        return t

    def code_block(code):
        from reportlab.platypus import XPreformatted
        esc = lambda x: x.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        lines = []
        for line in loc_code(code, lang).split("\n"):
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

    def legend():
        data = [[level_par(code), Paragraph(resolve(text, lang), st["cell"])] for code, text in spec["legend"]]
        return Table(data, colWidths=[27 * mm, W - 27 * mm],
                     style=TableStyle(base_ts[2:] + [("BACKGROUND", (0, 0), (0, -1), LT)]))

    story = []
    story += [Spacer(1, 6 * mm), Paragraph(resolve(spec["title"], lang), st["title"]), Spacer(1, 2 * mm),
              Paragraph(resolve(spec["subtitle"], lang), st["subtitle"]), Spacer(1, 3 * mm)]
    story.append(Table([[""]], colWidths=[W], rowHeights=[1.2 * mm],
                       style=TableStyle([("BACKGROUND", (0, 0), (-1, -1), ACC)])))
    story.append(Spacer(1, 5 * mm))

    for si, sec in enumerate(resolve(spec["sections"], lang)):
        if si in spec["breaks"]:
            story.append(PageBreak())
        start = len(story)
        story.append(Paragraph(sec["title"], st["h1"]))
        for b in sec["blocks"]:
            t = b["type"]
            if t == "para":
                story.append(Paragraph(b["text"], st["body"]))
                if si == spec["legend_at"] and b is sec["blocks"][0]:
                    story += [legend(), Spacer(1, 3 * mm)]
            elif t == "sub":
                story.append(Paragraph(b["title"], st["h2"]))
            elif t == "table":
                story += [Spacer(1, 2 * mm), compare_table(b["header"], b["rows"], b.get("widths")),
                          Spacer(1, 4 * mm)]
            elif t == "answer":
                story += [answer_box(b["title"], b["text"]), Spacer(1, 4 * mm)]
            elif t == "code":
                lead = []
                while story and isinstance(story[-1], Paragraph) and len(lead) < 3:
                    lead.insert(0, story.pop())
                story += [KeepTogether(lead + [code_block(b["code"])]), Spacer(1, 3 * mm)]
            elif t == "note":
                story += [note_box(b["text"]), Spacer(1, 3 * mm)]
            elif t == "fields":
                story += [fields_table(b["rows"]), Spacer(1, 2 * mm)]
            elif t == "items":
                story += [items_table(b["rows"]), Spacer(1, 3 * mm)]
            elif t == "eco":
                story += [eco_table(b["rows"]), Spacer(1, 3 * mm)]
            elif t == "bigfield":
                story += [Field(b["name"], W, b["lines"] * 6 * mm), Spacer(1, 3 * mm)]
            elif t == "bullets":
                story.append(ListFlowable([ListItem(Paragraph(x, st["body"]), leftIndent=10) for x in b["items"]],
                                          bulletType="bullet", start="•", leftIndent=10, bulletFontName="DV"))
        if si == len(spec["sections"]) - 1:
            story[start:] = [KeepTogether(story[start:])]

    conf, page, ver = (resolve(UI[k], lang) for k in ("confidential", "page", "version"))
    footer_title = f"{resolve(spec['title'], lang)} — {resolve(spec['subtitle'], lang)}"

    def on_page(cv, doc):
        cv.saveState()
        cv.setStrokeColor(colors.HexColor("#b9c3d0"))
        cv.setLineWidth(0.4)
        cv.line(15 * mm, 13 * mm, A4[0] - 15 * mm, 13 * mm)
        cv.setFont("DV", 7)
        cv.setFillColor(colors.HexColor("#666"))
        right = f"{conf}  ·  {ver} {VERSION}  ·  {page} {doc.page}"
        room = A4[0] - 30 * mm - cv.stringWidth(right, "DV", 7) - 6 * mm
        left = footer_title
        if cv.stringWidth(left, "DV", 7) > room:
            left = re.sub(r"\s*\([^)]*\)\s*$", "", left)
        cv.drawString(15 * mm, 9 * mm, left)
        cv.drawRightString(A4[0] - 15 * mm, 9 * mm, right)
        cv.restoreState()

    doc = SimpleDocTemplate(str(out), pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm,
                            topMargin=14 * mm, bottomMargin=18 * mm,
                            title=footer_title,
                            subject="SCA", lang="tr-TR" if lang == "tr" else "en-US")
    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)


def build_docx(lang, out, spec=FORM_SPEC):
    from docx import Document
    from docx.enum.table import WD_TABLE_ALIGNMENT
    from docx.enum.text import WD_BREAK
    from docx.oxml import parse_xml
    from docx.oxml.ns import nsdecls, qn
    from docx.shared import Mm, Pt, RGBColor

    doc = Document()
    sec0 = doc.sections[0]
    sec0.page_width, sec0.page_height = Mm(210), Mm(297)
    for side in ("left_margin", "right_margin"):
        setattr(sec0, side, Mm(15))
    sec0.top_margin, sec0.bottom_margin = Mm(14), Mm(16)

    normal = doc.styles["Normal"]
    normal.font.name = "Calibri"
    normal.font.size = Pt(9.5)
    normal.paragraph_format.space_after = Pt(4)

    acc = RGBColor(*ACCENT)
    hexc = lambda rgb: "%02X%02X%02X" % rgb

    W14 = 'xmlns:w14="http://schemas.microsoft.com/office/word/2010/wordml"'

    def shade(cell, rgb):
        cell._tc.get_or_add_tcPr().append(parse_xml(f'<w:shd {nsdecls("w")} w:val="clear" w:color="auto" '
                                                    f'w:fill="{hexc(rgb)}"/>'))

    def set_widths(table, widths_mm):
        table.autofit = False
        tblPr = table._tbl.tblPr
        tblPr.append(parse_xml(f'<w:tblLayout {nsdecls("w")} w:type="fixed"/>'))
        for gc, w in zip(table._tbl.tblGrid.findall(qn("w:gridCol")), widths_mm):
            gc.set(qn("w:w"), str(int(w * 56.7)))
        for row in table.rows:
            for i, w in enumerate(widths_mm):
                row.cells[i].width = Mm(w)

    def header_row(table):
        tr = table.rows[0]._tr
        tr.get_or_add_trPr().append(parse_xml(f'<w:tblHeader {nsdecls("w")}/>'))
        for cell in table.rows[0].cells:
            shade(cell, ACCENT)
            for p in cell.paragraphs:
                for r in p.runs:
                    r.font.color.rgb = RGBColor(255, 255, 255)
                    r.font.bold = True

    def no_split(table):
        for row in table.rows:
            row._tr.get_or_add_trPr().append(parse_xml(f'<w:cantSplit {nsdecls("w")}/>'))

    def write(cell_or_par, text, bold=False, size=None, color=None, mono=False, new=False):
        p = cell_or_par if hasattr(cell_or_par, "add_run") else (
            cell_or_par.add_paragraph() if new else cell_or_par.paragraphs[0])
        p.paragraph_format.space_after = Pt(1)
        lines = text.split("\n")
        for i, line in enumerate(lines):
            r = p.add_run(line)
            r.bold = bold
            if size:
                r.font.size = Pt(size)
            if color:
                r.font.color.rgb = RGBColor(*color)
            if mono:
                r.font.name = "Consolas"
            if i < len(lines) - 1:
                r.add_break(WD_BREAK.LINE)
        return p

    def checkbox(paragraph, label):
        sdt = parse_xml(
            f'<w:sdt {nsdecls("w")} {W14}><w:sdtPr><w14:checkbox><w14:checked w14:val="0"/>'
            '<w14:checkedState w14:val="2612" w14:font="MS Gothic"/>'
            '<w14:uncheckedState w14:val="2610" w14:font="MS Gothic"/></w14:checkbox></w:sdtPr>'
            '<w:sdtContent><w:r><w:rPr><w:rFonts w:ascii="MS Gothic" w:eastAsia="MS Gothic" '
            'w:hAnsi="MS Gothic" w:hint="eastAsia"/><w:sz w:val="20"/></w:rPr><w:t>☐</w:t></w:r>'
            '</w:sdtContent></w:sdt>')
        paragraph._p.append(sdt)
        r = paragraph.add_run(" " + label)
        r.font.size = Pt(8)

    def options_cell(cell, options):
        for i, o in enumerate(options):
            p = cell.paragraphs[0] if i == 0 else cell.add_paragraph()
            p.paragraph_format.space_after = Pt(0)
            checkbox(p, o)

    def level_text(cell, code):
        write(cell, resolve(LEVELS[code], lang), bold=True, size=7.5, color=LEVEL_COLORS[code])

    def heading(text, lvl):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(10 if lvl == 1 else 7)
        p.paragraph_format.space_after = Pt(4)
        p.paragraph_format.keep_with_next = True
        r = p.add_run(text)
        r.bold = True
        r.font.size = Pt(14 if lvl == 1 else 11)
        r.font.color.rgb = acc

    def items_table(rows):
        widths = [17, 70, 25, 31, 37]
        t = doc.add_table(rows=1, cols=5)
        t.style = "Table Grid"
        t.alignment = WD_TABLE_ALIGNMENT.CENTER
        for i, k in enumerate(("col_id", "col_item", "col_level", "col_status", "col_note")):
            write(t.rows[0].cells[i], resolve(UI[k], lang), size=8)
        for r in rows:
            cells = t.add_row().cells
            write(cells[0], r["id"], bold=True, size=8)
            write(cells[1], r["text"], size=8.5)
            if r.get("hint"):
                write(cells[1], r["hint"], size=7.5, color=(0x5A, 0x5A, 0x5A), new=True)
            level_text(cells[2], r["level"])
            if r.get("field"):
                merged = cells[3].merge(cells[4])
                shade(merged, (0xF7, 0xF9, 0xFC))
                for _ in range(r.get("lines", 1) - 1):
                    merged.add_paragraph()
            else:
                options_cell(cells[3], opts_for(r, lang))
                shade(cells[4], (0xF7, 0xF9, 0xFC))
        set_widths(t, widths)
        header_row(t)
        no_split(t)
        doc.add_paragraph()

    def eco_table(rows):
        widths = [30, 72, 46, 32]
        t = doc.add_table(rows=1, cols=4)
        t.style = "Table Grid"
        for i, k in enumerate(("col_tech", "col_files", "col_cmd", "col_status")):
            write(t.rows[0].cells[i], resolve(UI[k], lang), size=8)
        m, lk = resolve(UI["manifest"], lang), resolve(UI["lock"], lang)
        for tech, man, lock, cmd in rows:
            cells = t.add_row().cells
            write(cells[0], loc(tech, lang), bold=True, size=8)
            p = write(cells[1], m + ": ", bold=True, size=8)
            write(p, loc(man, lang).replace("\n", " "), size=8)
            p2 = write(cells[1], lk + ": ", bold=True, size=8, new=True)
            write(p2, loc(lock, lang).replace("\n", " "), size=8)
            is_text = cmd.startswith("L:")
            write(cells[2], loc(cmd, lang), size=7.5, mono=not is_text,
                  color=(0x5A, 0x5A, 0x5A) if is_text else None)
            options_cell(cells[3], resolve(OPTS["eco"], lang))
        set_widths(t, widths)
        header_row(t)
        no_split(t)
        doc.add_paragraph()

    def fields_table(labels):
        t = doc.add_table(rows=0, cols=2)
        t.style = "Table Grid"
        for lb in labels:
            cells = t.add_row().cells
            tall = isinstance(lb, dict)
            write(cells[0], lb["label"] if tall else lb, bold=True, size=8.5)
            if tall:
                for _ in range(4):
                    cells[1].add_paragraph()
            shade(cells[0], LIGHT)
            shade(cells[1], (0xF7, 0xF9, 0xFC))
        set_widths(t, [58, 122])
        doc.add_paragraph()

    def compare_table(header, rows, widths=None):
        n = len(header)
        t = doc.add_table(rows=1, cols=n)
        t.style = "Table Grid"
        for i, h in enumerate(header):
            write(t.rows[0].cells[i], h, size=8.5)
        for r in rows:
            cells = t.add_row().cells
            write(cells[0], r[0], bold=True, size=8.5)
            shade(cells[0], LIGHT)
            for i in range(1, n):
                write(cells[i], r[i], size=8.5)
        set_widths(t, widths or [36] + [144 / (n - 1)] * (n - 1))
        header_row(t)
        no_split(t)
        doc.add_paragraph()

    def note_box(text):
        bold, rest = text.split(":", 1)
        t = doc.add_table(rows=1, cols=1)
        cell = t.rows[0].cells[0]
        shade(cell, NOTE_BG)
        tcPr = cell._tc.get_or_add_tcPr()
        tcPr.append(parse_xml(f'<w:tcBorders {nsdecls("w")}><w:left w:val="single" w:sz="24" '
                              f'w:color="{hexc(NOTE_BORDER)}"/></w:tcBorders>'))
        p = write(cell, bold + ":", bold=True, size=8.5)
        write(p, rest, size=8.5)
        set_widths(t, [180])
        doc.add_paragraph()

    def legend():
        t = doc.add_table(rows=0, cols=2)
        t.style = "Table Grid"
        for code, text in spec["legend"]:
            cells = t.add_row().cells
            level_text(cells[0], code)
            shade(cells[0], LIGHT)
            write(cells[1], resolve(text, lang), size=8.5)
        set_widths(t, [27, 153])
        doc.add_paragraph()

    def answer_box(title, text):
        t = doc.add_table(rows=1, cols=1)
        cell = t.rows[0].cells[0]
        shade(cell, ANSWER_BG)
        cell._tc.get_or_add_tcPr().append(parse_xml(
            f'<w:tcBorders {nsdecls("w")}><w:left w:val="single" w:sz="24" w:color="{hexc(ACCENT)}"/></w:tcBorders>'))
        write(cell, title, bold=True, size=10.5, color=ACCENT)
        write(cell, text, size=9, new=True)
        no_split(t)
        set_widths(t, [180])
        doc.add_paragraph()

    def code_block(code):
        t = doc.add_table(rows=1, cols=1)
        t.style = "Table Grid"
        cell = t.rows[0].cells[0]
        shade(cell, (0xF3, 0xF5, 0xF8))
        p = cell.paragraphs[0]
        p.paragraph_format.space_after = Pt(0)
        lines = loc_code(code, lang).split("\n")
        for i, line in enumerate(lines):
            pos = line.find("# ")
            parts = [(line, None)]
            if pos == 0 or (pos > 0 and line[pos - 1] == " "):
                parts = [(line[:pos], None), (line[pos:], (0x6B, 0x77, 0x85))]
            for txt, col in parts:
                if txt:
                    r = p.add_run(txt)
                    r.font.name, r.font.size = "Consolas", Pt(7.5)
                    if col:
                        r.font.color.rgb = RGBColor(*col)
            if i < len(lines) - 1:
                p.add_run().add_break(WD_BREAK.LINE)
        no_split(t)
        set_widths(t, [180])
        doc.add_paragraph()

    p = doc.add_paragraph()
    r = p.add_run(resolve(spec["title"], lang))
    r.bold, r.font.size, r.font.color.rgb = True, Pt(20), acc
    p = doc.add_paragraph()
    r = p.add_run(resolve(spec["subtitle"], lang))
    r.font.size, r.font.color.rgb = Pt(13), RGBColor(0x44, 0x44, 0x44)
    p.paragraph_format.space_after = Pt(2)
    pPr = p._p.get_or_add_pPr()
    pPr.append(parse_xml(f'<w:pBdr {nsdecls("w")}><w:bottom w:val="single" w:sz="18" w:space="6" '
                         f'w:color="{hexc(ACCENT)}"/></w:pBdr>'))
    doc.add_paragraph()

    for si, sec in enumerate(resolve(spec["sections"], lang)):
        if si in spec["breaks"]:
            doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)
        heading(sec["title"], 1)
        for b in sec["blocks"]:
            t = b["type"]
            if t == "para":
                p = doc.add_paragraph(b["text"])
                p.paragraph_format.keep_with_next = b["text"].rstrip().endswith(":")
                if si == spec["legend_at"] and b is sec["blocks"][0]:
                    legend()
            elif t == "sub":
                heading(b["title"], 2)
            elif t == "table":
                compare_table(b["header"], b["rows"], b.get("widths"))
            elif t == "answer":
                answer_box(b["title"], b["text"])
            elif t == "code":
                code_block(b["code"])
            elif t == "note":
                note_box(b["text"])
            elif t == "fields":
                fields_table(b["rows"])
            elif t == "items":
                items_table(b["rows"])
            elif t == "eco":
                eco_table(b["rows"])
            elif t == "bigfield":
                tb = doc.add_table(rows=1, cols=1)
                tb.style = "Table Grid"
                cell = tb.rows[0].cells[0]
                shade(cell, (0xF7, 0xF9, 0xFC))
                for _ in range(b["lines"] - 1):
                    cell.add_paragraph()
                set_widths(tb, [180])
                doc.add_paragraph()
            elif t == "bullets":
                for x in b["items"]:
                    doc.add_paragraph(x, style="List Bullet")

    conf, page, ver = (resolve(UI[k], lang) for k in ("confidential", "page", "version"))
    fp = sec0.footer.paragraphs[0]
    full_title = f"{resolve(spec['title'], lang)} — {resolve(spec['subtitle'], lang)}"
    run = fp.add_run(f"{full_title}   ·   {conf}   ·   {ver} {VERSION}   ·   {page} ")
    run.font.size = Pt(7)
    run.font.color.rgb = RGBColor(0x66, 0x66, 0x66)
    r = fp.add_run()
    r.font.size = Pt(7)
    for x in (f'<w:fldChar {nsdecls("w")} w:fldCharType="begin"/>',
              f'<w:instrText {nsdecls("w")} xml:space="preserve"> PAGE </w:instrText>',
              f'<w:fldChar {nsdecls("w")} w:fldCharType="end"/>'):
        r._r.append(parse_xml(x))

    cp = doc.core_properties
    cp.title = full_title
    cp.subject = "SCA"
    cp.language = "tr-TR" if lang == "tr" else "en-US"
    cp.created = cp.modified = datetime.combine(date.today(), time())
    doc.save(str(out))


if __name__ == "__main__":
    outdir = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    outdir.mkdir(parents=True, exist_ok=True)
    names = {"tr": "SCA_Hizmeti_On_Gereksinimler_TR", "en": "SCA_Service_Prerequisites_EN"}
    for lang, base in names.items():
        build_pdf(lang, outdir / f"{base}.pdf")
        build_docx(lang, outdir / f"{base}.docx")
        print("ok", lang)
