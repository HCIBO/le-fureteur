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
    log(f"Engagement created: {e.path}")


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
        log("--id and --reason are required (e.g. --id CVE-2021-44228 --component org.apache.logging.log4j:log4j-core "
            "--kind accepted-risk --reason 'Mitigated by WAF, upgrade planned 2026-12')")
        sys.exit(1)
    eng.add_suppression({"id": a.id, "component": a.component or "*", "kind": a.kind, "reason": a.reason,
                         "by": a.by or "", "date": date.today().isoformat(), "expires": a.expires or ""})
    log(f"  added: {a.id} ({a.kind}). Run `scakit match` to re-match.")


def cmd_match(a):
    eng = Engagement(a.dir)
    db = VulnDB(a.db)
    comps = eng.inventory.sorted_components()
    findings, notes = match_engagement(eng, db)
    suppressed = notes["suppressed"]
    if suppressed:
        log(f"  {len(suppressed)} findings set aside as accepted risk / false positive")
    sev = {}
    for f in findings:
        sev[f.severity] = sev.get(f.severity, 0) + 1
    log(f"{len(comps)} components → {len(findings)} findings "
        + " ".join(f"{k}={v}" for k, v in sorted(sev.items())) + f" KEV={sum(f.kev for f in findings)}")
    if notes.get("no_db_coverage"):
        log(f"  Ecosystems not covered by the database: {', '.join(notes['no_db_coverage'])}")


def cmd_report(a):
    from .report import data as rdata
    from .report import render
    eng = Engagement(a.dir)
    findings, fdoc = eng.load_findings()
    if not fdoc:
        log("Run `scakit match` first.")
        sys.exit(1)
    lang = a.lang or eng.meta.get("lang", "tr")
    d = rdata.build(eng, findings, fdoc)
    out = eng.path / "reports"
    out.mkdir(exist_ok=True)
    base = f"SCA_{''.join(ch if ch.isalnum() else '_' for ch in eng.meta.get('name', 'report'))}_{lang.upper()}"
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
                log(f"  ! missing package for {fmt} ({ex.name}): pip install reportlab python-docx")
                continue
        elif fmt == "csv":
            p = out / f"{base}_findings.csv"
            p.write_text(render.to_csv(d, lang), encoding="utf-8-sig")
        else:
            log(f"  ! unknown format: {fmt}")
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
    log("  (licenses not listed are evaluated by their category default)")


def cmd_enrich(a):
    from .supplychain import enrich_online, offline_checks, read_internal_list
    eng = Engagement(a.dir)
    comps = eng.inventory.sorted_components()
    internal = read_internal_list(a.internal) if a.internal else []
    notes = offline_checks(comps, internal)
    if a.online:
        log("Online enrichment: package names / versions are sent to deps.dev, npm and PyPI.")
        notes += enrich_online(comps, internal, log)
        eng.meta["online_enrichment"] = ["deps.dev", "registry.npmjs.org", "pypi.org"]
        (eng.path / "engagement.json").write_text(__import__("json").dumps(eng.meta, indent=1, ensure_ascii=False))
    for kind, loc, det in notes:
        eng.inventory.observe(kind, "", loc, det)
    eng.save()
    kinds = {}
    for n in notes:
        kinds[n[0]] = kinds.get(n[0], 0) + 1
    log(f"  observations: {kinds or 'none'}")


def cmd_server(a):
    if a.server_cmd == "init":
        import getpass

        from .server.db import SessionLocal, init_db
        from .server.models import User
        from .messages import translate
        from .server.security import hash_password, password_problem
        init_db()
        db = SessionLocal()
        if db.query(User).filter_by(email=a.email.lower()).first():
            log(f"{a.email} already exists.")
            return
        pw = a.password or getpass.getpass("Admin password: ")
        if (p := password_problem(pw)):
            log(f"Error: {translate(p, 'en')}")
            sys.exit(1)
        db.add(User(email=a.email.lower(), name="Administrator", password_hash=hash_password(pw), role="admin"))
        db.commit()
        log(f"Admin created: {a.email}")
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
            pw = getpass.getpass("Backup passphrase: ")
            if a.server_cmd == "backup" and pw != getpass.getpass("Passphrase (again): "):
                log("Error: passphrases do not match")
                sys.exit(1)
        try:
            if a.server_cmd == "backup":
                out = Path(a.path or f"le-fureteur-backup-{__import__('datetime').date.today().isoformat()}.lfbk")
                if not pw:
                    log("! Warning: the backup is NOT encrypted (it contains customer code and the secret key). Use --encrypt "
                        "or SCAKIT_BACKUP_PASSPHRASE to encrypt it.")
                bk.backup(out.resolve(), pw, include_files=not a.db_only, log=log)
            else:
                if not a.path:
                    log("Error: specify the backup file to restore")
                    sys.exit(1)
                src = Path(a.path)
                if bk.is_encrypted(src) and not pw:
                    pw = getpass.getpass("Backup passphrase: ")
                bk.restore(src, pw, force=a.force, log=log)
        except bk.BackupError as ex:
            log(f"Error: {ex}")
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
        from .messages import translate
        sys.exit(translate(str(ex), "en"))
    if a.db_cmd == "update":
        if a.from_dir:
            update_from_dir(db, a.from_dir, log)
        else:
            update_online(db, a.ecosystems.split(",") if a.ecosystems else None, log=log, nvd=not a.no_nvd)
    st = db.stats()
    log(f"Database: {db.path}")
    log(f"  OSV records: {st['vulns']}  EPSS: {st['epss']}  KEV: {st['kev']}")
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

    p = sub.add_parser("init", help="create a new engagement folder")
    p.add_argument("dir")
    p.add_argument("--name", required=True)
    p.add_argument("--client")
    p.add_argument("--lang", default="en", choices=["en", "fr", "de", "tr"], help="report language")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("add", help="scan inputs and add them to the inventory")
    p.add_argument("dir")
    p.add_argument("inputs", nargs="+")
    p.add_argument("--target", help="application / target name")
    p.add_argument("--type", default="auto",
                   choices=["auto", "source", "web", "apk", "ipa", "desktop", "image", "archive", "list", "sbom"])
    p.add_argument("--dev", action="store_true", help="include development / test dependencies")
    p.add_argument("--os", help="ecosystem for OS package lists (e.g. Debian:12, Alpine:v3.19)")
    p.add_argument("--max-pages", type=int, default=25, help="web: maximum number of pages to crawl")
    p.add_argument("--delay", type=float, default=0.5, help="web: delay between requests (seconds)")
    p.add_argument("--no-probe", action="store_true", help="web: do not probe for exposed dependency files")
    p.add_argument("--header", action="append", help="web: extra HTTP header (e.g. 'Cookie: s=...')")
    p.add_argument("--insecure", action="store_true", help="web: disable TLS verification")
    p.add_argument("--no-external", action="store_true", help="web: do not download JS / CSS files hosted on other servers (CDN)")
    p.add_argument("--browser-tls", choices=["auto", "off", "chrome", "firefox", "safari", "edge"],
                   default="auto", help="web: HTTP client (auto: switches to browser-compatible TLS when blocked by a WAF)")
    p.set_defaults(func=cmd_add)

    p = sub.add_parser("match", help="match the inventory against the vulnerability database")
    p.add_argument("dir")
    p.add_argument("--db")
    p.set_defaults(func=cmd_match)

    p = sub.add_parser("report", help="generate reports")
    p.add_argument("dir")
    p.add_argument("--lang", choices=["en", "fr", "de", "tr"], help="report language (default: engagement language)")
    p.add_argument("--formats", default="html,pdf,docx,cdx,csv", help="html,md,pdf,docx,cdx,spdx,csv")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("server", help="web interface server (init / run / worker / backup / restore)")
    p.add_argument("server_cmd", choices=["init", "run", "worker", "backup", "restore"])
    p.add_argument("path", nargs="?", help="backup: output file · restore: backup file")
    p.add_argument("--encrypt", action="store_true", help="backup / restore: ask for a passphrase (encrypted backup)")
    p.add_argument("--db-only", action="store_true", help="backup: database only (without uploads / outputs)")
    p.add_argument("--force", action="store_true", help="restore: overwrite an existing installation")
    p.add_argument("--email", default="admin@localhost", help="init: admin e-mail")
    p.add_argument("--password", help="init: admin password (prompted if omitted)")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8800)
    p.add_argument("--forwarded-allow-ips", default="127.0.0.1", help="reverse proxy (nginx) addresses")
    p.add_argument("--concurrency", type=int, default=int(__import__("os").environ.get("SCAKIT_WORKER_CONCURRENCY", 1)),
                   help="worker: number of jobs to run at the same time")
    p.set_defaults(func=cmd_server)

    sub.add_parser("capture", help="record a site behind a WAF / bot protection with a browser and upload it (scakit capture --help)")
    sub.add_parser("ci", help="CI/CD: upload to the server, scan, exit according to the policy gate (scakit ci --help)")

    p = sub.add_parser("suppress", help="record an accepted risk / false positive / not affected decision")
    p.add_argument("dir")
    p.add_argument("--id", help="vulnerability ID (CVE / GHSA / ...); '*' for all vulnerabilities")
    p.add_argument("--component", help="component name, optionally @version (e.g. lodash@4.17.20)")
    p.add_argument("--kind", default="accepted-risk", choices=["accepted-risk", "false-positive", "not-affected"])
    p.add_argument("--reason")
    p.add_argument("--by", help="approved by")
    p.add_argument("--expires", help="expiry date (YYYY-MM-DD)")
    p.add_argument("--list", action="store_true")
    p.set_defaults(func=cmd_suppress)

    p = sub.add_parser("policy", help="license policy: comma-separated SPDX identifiers")
    p.add_argument("dir")
    p.add_argument("--allowed")
    p.add_argument("--review")
    p.add_argument("--denied")
    p.set_defaults(func=cmd_policy)

    p = sub.add_parser("enrich", help="supply-chain checks (offline by default)")
    p.add_argument("dir")
    p.add_argument("--internal", help="CSV of internal package names")
    p.add_argument("--online", action="store_true",
                   help="query deps.dev / npm / PyPI (package names are sent to external services)")
    p.set_defaults(func=cmd_enrich)

    p = sub.add_parser("db", help="vulnerability database operations")
    p.add_argument("db_cmd", choices=["update", "download", "status"])
    p.add_argument("dir", nargs="?", help="download: target folder")
    p.add_argument("--db")
    p.add_argument("--ecosystems", help="comma-separated (default: " + ",".join(DEFAULT_ECOSYSTEMS) + ")")
    p.add_argument("--from-dir", help="update: import from a previously downloaded folder (air-gapped)")
    p.add_argument("--no-nvd", action="store_true", help="skip NVD product data (server / native components)")
    p.set_defaults(func=cmd_db)

    a = ap.parse_args(argv)
    try:
        a.func(a)
    except FileNotFoundError as ex:
        if "Engagement not found" in str(ex):
            log(f"Error: '{a.dir}' is not an engagement folder. Create it first:\n"
                f"  scakit init {a.dir} --name \"Engagement name\" --client \"Customer\"")
        else:
            log(f"Error: file / folder not found: {ex.filename or ex}")
        sys.exit(1)
    except ValueError as ex:
        from .messages import translate
        log(f"Error: {translate(str(ex), 'en')}")
        sys.exit(1)


if __name__ == "__main__":
    main()
