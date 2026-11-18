from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .analysis import apply_suppressions, detect_type, ingest, match_engagement
from .engagement import Engagement
from .vulndb.db import DEFAULT_ECOSYSTEMS, VulnDB, download_all, update_from_dir, update_online


def log(msg: str):
    print(msg, file=sys.stderr, flush=True)


def cmd_init(a):
    e = Engagement.create(a.dir, a.name, a.client or "", a.lang)
    log(f"Engagement oluşturuldu: {e.path}")


def cmd_add(a):
    eng = Engagement(a.dir)
    ingest(eng, a.inputs, kind=a.type, target=a.target, os_eco=a.os, dev=a.dev,
           web={"max_pages": a.max_pages, "delay": a.delay, "probe": not a.no_probe, "headers": a.header or [],
                "verify_tls": not a.insecure, "browser_tls": a.browser_tls, "external_assets": not a.no_external}, log=log)


def cmd_suppress(a):
    from datetime import date
    eng = Engagement(a.dir)
    if a.list:
        for r in eng.suppressions():
            log(f"  {r['id']:22} {r.get('component', '*'):40} {r['kind']:15} {r['reason']}")
        return
    if not a.id or not a.reason:
        log("--id ve --reason zorunlu (ör. --id CVE-2021-44228 --component org.apache.logging.log4j:log4j-core "
            "--kind accepted-risk --reason 'WAF ile azaltıldı, 2026-12 yükseltme')")
        sys.exit(1)
    eng.add_suppression({"id": a.id, "component": a.component or "*", "kind": a.kind, "reason": a.reason,
                         "by": a.by or "", "date": date.today().isoformat(), "expires": a.expires or ""})
    log(f"  eklendi: {a.id} ({a.kind}). `scakit match` ile yeniden eşleştirin.")


def cmd_match(a):
    eng = Engagement(a.dir)
    db = VulnDB(a.db)
    comps = eng.inventory.sorted_components()
    findings, notes = match_engagement(eng, db)
    suppressed = notes["suppressed"]
    if suppressed:
        log(f"  {len(suppressed)} bulgu kabul edilen risk / yanlış pozitif olarak ayrıldı")
    sev = {}
    for f in findings:
        sev[f.severity] = sev.get(f.severity, 0) + 1
    log(f"{len(comps)} bileşen → {len(findings)} bulgu "
        + " ".join(f"{k}={v}" for k, v in sorted(sev.items())) + f" KEV={sum(f.kev for f in findings)}")
    if notes.get("no_db_coverage"):
        log(f"  Veritabanında kapsamı olmayan ekosistemler: {', '.join(notes['no_db_coverage'])}")


def cmd_report(a):
    from .report import data as rdata
    from .report import render
    eng = Engagement(a.dir)
    findings, fdoc = eng.load_findings()
    if not fdoc:
        log("Önce `scakit match` çalıştırın.")
        sys.exit(1)
    lang = a.lang or eng.meta.get("lang", "tr")
    d = rdata.build(eng, findings, fdoc)
    out = eng.path / "reports"
    out.mkdir(exist_ok=True)
    base = f"SCA_{''.join(ch if ch.isalnum() else '_' for ch in eng.meta.get('name', 'rapor'))}_{lang.upper()}"
    written = []
    for fmt in a.formats.split(","):
        fmt = fmt.strip()
        if fmt == "html":
            p = out / f"{base}.html"
            p.write_text(render.to_html(d, lang), encoding="utf-8")
        elif fmt == "md":
            p = out / f"{base}.md"
            p.write_text(render.to_markdown(d, lang), encoding="utf-8")
        elif fmt == "cdx":
            p = out / f"{base.rsplit('_', 1)[0]}.cdx.json"
            p.write_text(render.to_cyclonedx(d), encoding="utf-8")
        elif fmt == "spdx":
            p = out / f"{base.rsplit('_', 1)[0]}.spdx.json"
            p.write_text(render.to_spdx(d), encoding="utf-8")
        elif fmt in ("pdf", "docx"):
            from .report import document
            p = out / f"{base}.{fmt}"
            try:
                (document.to_pdf if fmt == "pdf" else document.to_docx)(d, lang, p)
            except ImportError as ex:
                log(f"  ! {fmt} için gerekli paket yok ({ex.name}): pip install reportlab python-docx")
                continue
        elif fmt == "csv":
            p = out / f"{base}_findings.csv"
            p.write_text(render.to_csv(d, lang), encoding="utf-8-sig")
        else:
            log(f"  ! bilinmeyen format: {fmt}")
            continue
        written.append(p)
    for p in written:
        log(f"  {p}")


def cmd_policy(a):
    import json
    eng = Engagement(a.dir)
    p = eng.path / "license_policy.json"
    doc = json.loads(p.read_text()) if p.exists() else {"allowed": [], "review": [], "denied": []}
    for key in ("allowed", "review", "denied"):
        vals = getattr(a, key)
        if vals:
            items = [v.strip() for v in vals.split(",") if v.strip()]
            for other in ("allowed", "review", "denied"):
                doc[other] = [x for x in doc[other] if x.lower() not in {i.lower() for i in items}]
            doc[key] = sorted(set(doc[key]) | set(items))
    p.write_text(json.dumps(doc, indent=1))
    for key in ("allowed", "review", "denied"):
        log(f"  {key:8} {', '.join(doc[key]) or '—'}")
    log("  (listede olmayan lisanslar kategori varsayılanına göre değerlendirilir)")


def cmd_enrich(a):
    from .supplychain import enrich_online, offline_checks, read_internal_list
    eng = Engagement(a.dir)
    comps = eng.inventory.sorted_components()
    internal = read_internal_list(a.internal) if a.internal else []
    notes = offline_checks(comps, internal)
    if a.online:
        log("Çevrimiçi zenginleştirme: paket adları/sürümleri deps.dev, npm ve PyPI'ye gönderilir.")
        notes += enrich_online(comps, internal, log)
        eng.meta["online_enrichment"] = ["deps.dev", "registry.npmjs.org", "pypi.org"]
        (eng.path / "engagement.json").write_text(__import__("json").dumps(eng.meta, indent=1, ensure_ascii=False))
    for kind, loc, det in notes:
        eng.inventory.observe(kind, "", loc, det)
    eng.save()
    kinds = {}
    for n in notes:
        kinds[n[0]] = kinds.get(n[0], 0) + 1
    log(f"  gözlemler: {kinds or 'yok'}")


def cmd_server(a):
    if a.server_cmd == "init":
        import getpass

        from .server.db import SessionLocal, init_db
        from .server.models import User
        from .server.security import hash_password, password_problem
        init_db()
        db = SessionLocal()
        if db.query(User).filter_by(email=a.email.lower()).first():
            log(f"{a.email} zaten kayıtlı.")
            return
        pw = a.password or getpass.getpass("Admin parolası: ")
        if (p := password_problem(pw)):
            log(f"Hata: {p}")
            sys.exit(1)
        db.add(User(email=a.email.lower(), name="Yönetici", password_hash=hash_password(pw), role="admin"))
        db.commit()
        log(f"Admin oluşturuldu: {a.email}")
    elif a.server_cmd == "run":
        import uvicorn
        uvicorn.run("scakit.server.app:create_app", factory=True, host=a.host, port=a.port, proxy_headers=True,
                    forwarded_allow_ips=a.forwarded_allow_ips)
    elif a.server_cmd in ("backup", "restore"):
        import getpass
        import os

        from .server import backup as bk
        pw = os.environ.get("SCAKIT_BACKUP_PASSPHRASE")
        if not pw and a.encrypt:
            pw = getpass.getpass("Yedek parolası: ")
            if a.server_cmd == "backup" and pw != getpass.getpass("Parola (tekrar): "):
                log("Hata: parolalar eşleşmiyor")
                sys.exit(1)
        try:
            if a.server_cmd == "backup":
                out = Path(a.path or f"le-fureteur-yedek-{__import__('datetime').date.today().isoformat()}.lfbk")
                if not pw:
                    log("! Uyarı: yedek ŞİFRESİZ (müşteri kodu ve gizli anahtar içerir). Şifrelemek için --encrypt "
                        "veya SCAKIT_BACKUP_PASSPHRASE kullanın.")
                bk.backup(out.resolve(), pw, include_files=not a.db_only, log=log)
            else:
                if not a.path:
                    log("Hata: geri yüklenecek yedek dosyasını verin")
                    sys.exit(1)
                src = Path(a.path)
                if bk.is_encrypted(src) and not pw:
                    pw = getpass.getpass("Yedek parolası: ")
                bk.restore(src, pw, force=a.force, log=log)
        except bk.BackupError as ex:
            log(f"Hata: {ex}")
            sys.exit(1)
    elif a.server_cmd == "worker":
        from .server.worker import main as worker_main
        worker_main(concurrency=a.concurrency)


def cmd_db(a):
    if a.db_cmd == "download":
        download_all(a.dir, a.ecosystems.split(",") if a.ecosystems else None, log, nvd=not a.no_nvd)
        return
    try:
        db = VulnDB(a.db)
    except RuntimeError as ex:
        sys.exit(str(ex))
    if a.db_cmd == "update":
        if a.from_dir:
            update_from_dir(db, a.from_dir, log)
        else:
            update_online(db, a.ecosystems.split(",") if a.ecosystems else None, log=log, nvd=not a.no_nvd)
    st = db.stats()
    log(f"Veritabanı: {db.path}")
    log(f"  OSV kayıt: {st['vulns']}  EPSS: {st['epss']}  KEV: {st['kev']}")
    for eco, n in sorted(st["by_ecosystem"].items()):
        log(f"    {eco:14} {n}")
    for k, v in sorted(db.meta().items()):
        log(f"  {k}: {v.get('updated', '')}")


def main(argv=None):
    args = sys.argv[1:] if argv is None else list(argv)
    if args[:1] == ["capture"]:
        from .capture_client import main as capture_main
        sys.exit(capture_main(args[1:]))
    if args[:1] == ["ci"]:
        from .ci_client import main as ci_main
        sys.exit(ci_main(args[1:]))
    ap = argparse.ArgumentParser(prog="scakit", description="Whitebox + blackbox Software Composition Analysis")
    ap.add_argument("--version", action="version", version=f"scakit {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init", help="yeni engagement klasörü")
    p.add_argument("dir")
    p.add_argument("--name", required=True)
    p.add_argument("--client")
    p.add_argument("--lang", default="tr", choices=["tr", "en", "fr", "de"])
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("add", help="girdi tara ve envantere ekle")
    p.add_argument("dir")
    p.add_argument("inputs", nargs="+")
    p.add_argument("--target", help="uygulama / hedef adı")
    p.add_argument("--type", default="auto",
                   choices=["auto", "source", "web", "apk", "ipa", "desktop", "image", "archive", "list", "sbom"])
    p.add_argument("--dev", action="store_true", help="geliştirme / test bağımlılıklarını dahil et (WB-41)")
    p.add_argument("--os", help="OS paket listesi için ekosistem (ör. Debian:12, Alpine:v3.19)")
    p.add_argument("--max-pages", type=int, default=25, help="web: taranacak en fazla sayfa")
    p.add_argument("--delay", type=float, default=0.5, help="web: istekler arası bekleme (sn)")
    p.add_argument("--no-probe", action="store_true", help="web: açık bağımlılık dosyası denemesi yapma")
    p.add_argument("--header", action="append", help="web: ek HTTP başlığı (ör. 'Cookie: s=...')")
    p.add_argument("--insecure", action="store_true", help="web: TLS doğrulamasını kapat")
    p.add_argument("--no-external", action="store_true", help="web: başka sunuculardaki (CDN) JS/CSS dosyalarını indirme")
    p.add_argument("--browser-tls", choices=["auto", "off", "chrome", "firefox", "safari", "edge"],
                   default="auto", help="web: HTTP istemcisi (auto: WAF engelinde tarayıcı uyumlu TLS'e kendiliğinden geçer)")
    p.set_defaults(func=cmd_add)

    p = sub.add_parser("match", help="envanteri zafiyet veritabanıyla eşleştir")
    p.add_argument("dir")
    p.add_argument("--db")
    p.set_defaults(func=cmd_match)

    p = sub.add_parser("report", help="rapor üret")
    p.add_argument("dir")
    p.add_argument("--lang", choices=["tr", "en", "fr", "de"])
    p.add_argument("--formats", default="html,pdf,docx,cdx,csv", help="html,md,pdf,docx,cdx,spdx,csv")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("server", help="web arayüzü sunucusu (init / run / worker)")
    p.add_argument("server_cmd", choices=["init", "run", "worker", "backup", "restore"])
    p.add_argument("path", nargs="?", help="backup: çıktı dosyası · restore: yedek dosyası")
    p.add_argument("--encrypt", action="store_true", help="backup/restore: parolayı sor (şifreli yedek)")
    p.add_argument("--db-only", action="store_true", help="backup: yalnızca veritabanı (yüklemeler / çıktılar hariç)")
    p.add_argument("--force", action="store_true", help="restore: dolu kurulumun üzerine yaz")
    p.add_argument("--email", default="admin@localhost", help="init: admin e-postası")
    p.add_argument("--password", help="init: admin parolası (verilmezse sorulur)")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8800)
    p.add_argument("--forwarded-allow-ips", default="127.0.0.1", help="ters vekil (nginx) adresleri")
    p.add_argument("--concurrency", type=int, default=int(__import__("os").environ.get("SCAKIT_WORKER_CONCURRENCY", 1)),
                   help="worker: aynı anda çalışacak iş sayısı")
    p.set_defaults(func=cmd_server)

    sub.add_parser("capture", help="WAF / bot koruması arkasındaki site için tarayıcıyla kayıt al ve yükle (scakit capture --help)")
    sub.add_parser("ci", help="CI/CD: sunucuya yükle, tara, politika kapısına göre çıkış kodu ver (scakit ci --help)")

    p = sub.add_parser("suppress", help="kabul edilen risk / yanlış pozitif kaydı (form WB-43)")
    p.add_argument("dir")
    p.add_argument("--id", help="zafiyet kimliği (CVE / GHSA / ...); '*' tüm zafiyetler")
    p.add_argument("--component", help="bileşen adı, isteğe bağlı @sürüm (ör. lodash@4.17.20)")
    p.add_argument("--kind", default="accepted-risk", choices=["accepted-risk", "false-positive", "not-affected"])
    p.add_argument("--reason")
    p.add_argument("--by", help="onaylayan kişi")
    p.add_argument("--expires", help="geçerlilik sonu (YYYY-AA-GG)")
    p.add_argument("--list", action="store_true")
    p.set_defaults(func=cmd_suppress)

    p = sub.add_parser("policy", help="lisans politikası (form WB-40): SPDX kimlikleri, virgülle")
    p.add_argument("dir")
    p.add_argument("--allowed")
    p.add_argument("--review")
    p.add_argument("--denied")
    p.set_defaults(func=cmd_policy)

    p = sub.add_parser("enrich", help="tedarik zinciri kontrolleri (varsayılan çevrimdışı)")
    p.add_argument("dir")
    p.add_argument("--internal", help="kurum içi paket adları CSV (form WB-31)")
    p.add_argument("--online", action="store_true",
                   help="deps.dev / npm / PyPI sorgula (paket adları dış servislere gönderilir)")
    p.set_defaults(func=cmd_enrich)

    p = sub.add_parser("db", help="zafiyet veritabanı işlemleri")
    p.add_argument("db_cmd", choices=["update", "download", "status"])
    p.add_argument("dir", nargs="?", help="download: hedef klasör")
    p.add_argument("--db")
    p.add_argument("--ecosystems", help="virgülle ayrılmış (varsayılan: " + ",".join(DEFAULT_ECOSYSTEMS) + ")")
    p.add_argument("--from-dir", help="update: önceden indirilmiş klasörden içe aktar (air-gapped)")
    p.add_argument("--no-nvd", action="store_true", help="NVD ürün verisini indirme (sunucu / native bileşenler)")
    p.set_defaults(func=cmd_db)

    a = ap.parse_args(argv)
    try:
        a.func(a)
    except FileNotFoundError as ex:
        if "Engagement bulunamadı" in str(ex):
            log(f"Hata: '{a.dir}' bir engagement klasörü değil. Önce oluşturun:\n"
                f"  scakit init {a.dir} --name \"İş adı\" --client \"Müşteri\"")
        else:
            log(f"Hata: dosya / klasör bulunamadı: {ex.filename or ex}")
        sys.exit(1)


if __name__ == "__main__":
    main()
