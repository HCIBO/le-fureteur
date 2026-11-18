import json
import pathlib
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
FRONT = HERE.parent
ROOT = FRONT.parent
sys.path.insert(0, str(ROOT))
from scakit.catalog import T

LANGS = ("en", "fr", "de")


def code_keys() -> set[str]:
    js = r'''
const ts = require(process.argv[1] + "/node_modules/typescript");
const fs = require("fs"), path = require("path");
const keys = new Set();
function walk(d) { for (const f of fs.readdirSync(d)) { const p = path.join(d, f);
  if (fs.statSync(p).isDirectory()) { if (!/^(locales|guide)$/.test(f)) walk(p); } else if (/\.tsx?$/.test(f)) scan(p); } }
function scan(file) { const sf = ts.createSourceFile(file, fs.readFileSync(file, "utf8"), ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  (function v(n) { if (ts.isCallExpression(n) && n.expression.getText(sf) === "t" && n.arguments[0] && ts.isStringLiteral(n.arguments[0])) keys.add(n.arguments[0].text); ts.forEachChild(n, v); })(sf); }
walk(process.argv[1] + "/src");
console.log(JSON.stringify([...keys]));
'''
    out = subprocess.run(["node", "-e", js, str(FRONT)], capture_output=True, text=True, check=True).stdout
    return set(json.loads(out))


def server_keys() -> set[str]:
    import ast
    root = ROOT
    keys: set[str] = {"Python", "Arayüz (npm)", "İşletim sistemi"}
    try:
        from scakit.server import notify, settings_store
        keys |= {d for _, (_, _, d) in settings_store.SCHEMA.items()} | set(settings_store.GROUPS)
        keys |= set(notify.EVENT_LABEL.values())
    except ImportError as ex:
        print(f"  ! could not import server modules ({ex}); scanning error messages only")
    for f in (root / "scakit" / "server").glob("*.py"):
        for n in ast.walk(ast.parse(f.read_text(encoding="utf-8"))):
            if not isinstance(n, ast.Call):
                continue
            name = getattr(n.func, "id", "")
            if name == "HTTPException" and len(n.args) > 1 and isinstance(n.args[1], ast.Constant):
                keys.add(n.args[1].value)
            elif name == "_not_found" and n.args and isinstance(n.args[0], ast.Constant):
                keys.add(f"{n.args[0].value} bulunamadı")
            elif name in ("TargetError", "NotifyError", "JiraError", "AuthError") and n.args and isinstance(n.args[0], ast.Constant):
                keys.add(n.args[0].value)
            elif name == "dict" or not isinstance(n.func, ast.Name):
                continue
    for f in (root / "scakit" / "server").glob("sysinfo.py"):
        for n in ast.walk(ast.parse(f.read_text(encoding="utf-8"))):
            if isinstance(n, ast.Dict):
                for k, v in zip(n.keys, n.values):
                    if isinstance(k, ast.Constant) and k.value in ("purpose", "fix") and isinstance(v, ast.Constant):
                        keys.add(v.value)
    return keys


TR_CHARS = re.compile(r"[çğıöşüÇĞİÖŞÜ]|(?i:\b(?:ve|bir|ile|yok|daha|veya|bulgu\w*|tarama\w*|hedef\w*|dosya\w*|kayit|hata\w*|"
                      r"gecersiz|gerekli|yeni|eski|sayfa\w*|istek\w*|sunucu\w*|olarak|tekrar|deneyin|ayar\w*|parola\w*|"
                      r"proje(?!ct)\w*|kanal\w*|zafiyet\w*|surum\w*|yetki\w*|izin\w*|silin\w*|eklen\w*|bekle\w*|iptal|"
                      r"alan(?!ce)\w*|adres\w*|anahtar\w*|kullan\w*|yukle\w*|indir(?!ect)\w*|guncel\w*|onay\w*|talep\w*|"
                      r"kural\w*|rapor\w*|bildirim\w*|organizasyon\w*|ekip\w*|rol(?!e|l)\w*|mesaj\w*|yorum\w*|kuyruk\w*)\b)")
REGEX_LIKE = re.compile(r"\(\?|\\[bdswS]|^\^|\S\|\S|\[\^")
NOT_SHOWN = {"log", "print", "exit", "SystemExit", "add_argument", "add_parser", "ArgumentParser",
             "compile", "search", "match", "sub", "findall", "fullmatch", "split"}


def _call_name(f) -> str:
    return f.attr if isinstance(f, __import__("ast").Attribute) else getattr(f, "id", "")


def backend_texts() -> list[tuple[str, str, int]]:
    import ast
    out = []
    for p in sorted((ROOT / "scakit").rglob("*.py")):
        rel = p.relative_to(ROOT)
        if rel.parts[1] == "report" or rel.name in ("capture_client.py", "ci_client.py", "catalog.py", "messages.py"):
            continue
        tree = ast.parse(p.read_text(encoding="utf-8"))
        skip = set()
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and _call_name(n.func) in NOT_SHOWN:
                skip |= {id(c) for c in ast.walk(n)}
            if isinstance(n, ast.Compare) and any(isinstance(o, (ast.In, ast.NotIn, ast.Eq, ast.NotEq)) for o in n.ops):
                skip |= {id(c) for c in [n.left, *n.comparators] if isinstance(c, ast.Constant)}
            if isinstance(n, ast.JoinedStr):
                skip |= {id(c) for c in n.values if isinstance(c, ast.Constant)}
        for n in ast.walk(tree):
            if id(n) in skip:
                continue
            if isinstance(n, ast.JoinedStr):
                text = "".join(v.value.replace("{", "{{").replace("}", "}}") if isinstance(v, ast.Constant) else "{}"
                               for v in n.values)
                lit = "".join(v.value for v in n.values if isinstance(v, ast.Constant))
            elif isinstance(n, ast.Constant) and isinstance(n.value, str):
                text = lit = n.value
            else:
                continue
            if TR_CHARS.search(lit) and not REGEX_LIKE.search(lit):
                out.append((text, str(rel), n.lineno))
    return out


def _shape(s: str) -> str:
    return re.sub(r"\{[^{}]*\}", "{}", s)


def main():
    extra = server_keys()
    if "--keys" in sys.argv:
        extra |= set(json.loads(pathlib.Path(sys.argv[sys.argv.index("--keys") + 1]).read_text()))
    needed = code_keys() | extra
    missing = sorted(k for k in needed if k not in T)
    shapes = {_shape(k) for k in T}
    backend = [(t, f, n) for t, f, n in backend_texts() if _shape(t) not in shapes]
    for i, lang in enumerate(LANGS):
        d = {k: v[i] for k, v in sorted(T.items()) if v[i] and v[i] != k}
        body = json.dumps(d, ensure_ascii=False, indent=1)
        (FRONT / "src" / "locales" / f"{lang}.ts").write_text(
            f"const d: Record<string, string> = {body};\nexport default d;\n", encoding="utf-8")
    bad = [(k, LANGS[i]) for k, v in T.items() for i in range(3)
           if v[i] and set(re.findall(r"\{\w+\}", k)) != set(re.findall(r"\{\w+\}", v[i]))]
    print(f"{len(T)} translations, {len(needed)} texts in the UI code; missing {len(missing)}; "
          f"untranslated server texts {len(backend)}; placeholder errors {len(bad)}")
    for k in missing:
        print("  MISSING:", json.dumps(k, ensure_ascii=False))
    for t, f, n in backend:
        print(f"  SERVER TEXT: {f}:{n}", json.dumps(t, ensure_ascii=False))
    for k, l in bad:
        print("  PLACEHOLDER:", l, json.dumps(k, ensure_ascii=False))
    return 1 if (missing or backend or bad) else 0


if __name__ == "__main__":
    sys.exit(main())
