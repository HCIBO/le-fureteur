import sys
from pathlib import Path

from build_guide import build_docx, build_pdf
from ops_content import SECTIONS, SUBTITLE, TITLE

SPEC = {"title": TITLE, "subtitle": SUBTITLE, "sections": SECTIONS, "breaks": (2, 4, 5, 7, 10)}

if __name__ == "__main__":
    out = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    out.mkdir(parents=True, exist_ok=True)
    build_pdf("tr", out / "SCA_Operasyon_ve_Kullanim_Rehberi.pdf", SPEC)
    build_docx("tr", out / "SCA_Operasyon_ve_Kullanim_Rehberi.docx", SPEC)
    print("ok")
