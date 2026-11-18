import json
import pathlib
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
FRONT = HERE.parent
sys.path.insert(0, str(HERE))
from translations import T

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
    root = FRONT.parent
    sys.path.insert(0, str(root))
    keys: set[str] = {"Python", "Arayüz (npm)", "İşletim sistemi"}
    try:
        from scakit.server import notify, settings_store
        keys |= {d for _, (_, _, d) in settings_store.SCHEMA.items()} | set(settings_store.GROUPS)
        keys |= set(notify.EVENT_LABEL.values())
    except ImportError as ex:
        print(f"  ! sunucu modülleri yüklenemedi ({ex}); yalnızca hata mesajları taranıyor")
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


def main():
    extra = server_keys()
    if "--keys" in sys.argv:
        extra |= set(json.loads(pathlib.Path(sys.argv[sys.argv.index("--keys") + 1]).read_text()))
    needed = code_keys() | extra
    missing = sorted(k for k in needed if k not in T)
    for i, lang in enumerate(LANGS):
        d = {k: v[i] for k, v in sorted(T.items()) if v[i] and v[i] != k}
        body = json.dumps(d, ensure_ascii=False, indent=1)
        (FRONT / "src" / "locales" / f"{lang}.ts").write_text(
            f"const d: Record<string, string> = {body};\nexport default d;\n", encoding="utf-8")
    bad = [(k, LANGS[i]) for k, v in T.items() for i in range(3)
           if v[i] and set(re.findall(r"\{\w+\}", k)) != set(re.findall(r"\{\w+\}", v[i]))]
    print(f"{len(T)} çeviri, koddaki {len(needed)} metin; eksik {len(missing)}; yer tutucu hatası {len(bad)}")
    for k in missing:
        print("  EKSİK:", json.dumps(k, ensure_ascii=False))
    for k, l in bad:
        print("  YER TUTUCU:", l, json.dumps(k, ensure_ascii=False))
    return 1 if (missing or bad) else 0


if __name__ == "__main__":
    sys.exit(main())
