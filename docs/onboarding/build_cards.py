import sys
from pathlib import Path

from build import build_docx, build_pdf
from cards_content import CARDS
from content import resolve
from guide_content import localize

if __name__ == "__main__":
    outdir = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    outdir.mkdir(parents=True, exist_ok=True)
    for card in CARDS:
        for lang, base in zip(("tr", "en"), card["file"]):
            spec = dict(card, sections=localize(resolve(card["sections"], lang), lang))
            build_pdf(lang, outdir / f"{base}.pdf", spec)
            build_docx(lang, outdir / f"{base}.docx", spec)
            print("ok", base)
