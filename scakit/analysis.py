from __future__ import annotations

import tarfile
import zipfile
from pathlib import Path
from .safeio import SafeZipFile, budget


class Canceled(Exception):
    pass


def detect_type(inp: str) -> str:
    if inp.startswith(("http://", "https://")):
        return "web"
    p = Path(inp)
    low = p.name.lower()
    if p.is_dir():
        return "source"
    if low.endswith((".har", ".json", ".xml")):
        from .collectors.blackbox.traffic import sniff as traffic_sniff
        if traffic_sniff(p):
            return "traffic"
    if low.endswith((".json", ".xml", ".spdx", ".tv", ".txt", ".cdx")):
        from .collectors.sbom import sniff
        if sniff(p):
            return "sbom"
    if low.endswith((".apk", ".aab", ".apks", ".xapk")):
        return "apk"
    if low.endswith(".ipa"):
        return "ipa"
    from .collectors.blackbox.desktop import INSTALLER_EXT
    if low.endswith(INSTALLER_EXT):
        return "desktop"
    if low.endswith((".jar", ".war", ".ear", ".aar")):
        return "archive"
    if low.endswith((".7z", ".rar", ".zst", ".tar.zst", ".lz", ".lzma", ".cab", ".arj", ".ace")):
        raise ValueError("Bu arşiv biçimi desteklenmiyor (7z / rar / zst); ZIP veya TAR (gz, bz2, xz) olarak yeniden paketleyin")
    if low.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")):
        try:
            with tarfile.open(p) as tf:
                names = set(tf.getnames()[:2000])
            if "manifest.json" in names or "index.json" in names or "oci-layout" in names:
                return "image"
        except tarfile.TarError:
            pass
        return "source"
    if low.endswith(".zip"):
        try:
            with SafeZipFile(p) as zf:
                names = zf.namelist()
            if "AndroidManifest.xml" in names or any(n.startswith("base/manifest/") for n in names):
                return "apk"
        except zipfile.BadZipFile:
            pass
        return "source"
    return "list"


def ingest(eng, inputs, *, kind: str = "auto", target: str | None = None, os_eco: str | None = None,
           dev: bool = False, web: dict | None = None, log=print, should_cancel=None, on_input=None) -> None:
    web = {"max_pages": 25, "delay": 0.5, "probe": True, "headers": [], "verify_tls": True, **(web or {})}
    queue = [(inp, kind) for inp in inputs]
    while queue:
        if should_cancel and should_cancel():
            raise Canceled()
        inp, forced = queue.pop(0)
        if on_input:
            on_input("started", inp)
        try:
            with budget():
                res = _ingest_one(eng, inp, forced, queue, target, os_eco, dev, web, log)
        except Exception as ex:
            if on_input:
                from .safeio import UnsafeInput
                on_input("error", inp, reason=str(ex)[:300] if isinstance(ex, (UnsafeInput, ValueError)) else type(ex).__name__)
            raise
        if on_input and res:
            on_input("done", inp, **res)
    eng.inventory.finalize()
    eng.save()
    log(f"Inventory: {len(eng.inventory.components)} components")


def _ingest_one(eng, inp, forced, queue, target, os_eco, dev, web, log):
    k = forced if forced != "auto" else detect_type(inp)
    tgt = target or (Path(inp).name if not inp.startswith("http") else inp.split("/")[2])
    log(f"[{k}] {inp} (target: {tgt})")
    notes, comps, nested = [], [], []
    if k == "source":
        from .collectors.whitebox import scan_directory, scan_source_archive
        if Path(inp).is_dir():
            from .collectors.blackbox.desktop import scan_binaries
            comps, notes = scan_directory(inp, target=tgt, os_eco=os_eco, include_dev=dev, extra=nested)
            bc, bn = scan_binaries(Path(inp), tgt)
            comps += bc
            notes += bn
            from .usage import annotate, collect_imports
            imp = collect_imports(inp)
            if imp["files"]:
                st = annotate(comps, imp)
                eng.merge_usage(imp["go_calls"], {"target": tgt, "files": imp["files"], **st})
                log(f"  usage analysis: {imp['files']} source files, {st['imported']} components imported, "
                    f"{st['not-imported']} with no direct import")
        else:
            comps, notes = scan_source_archive(inp, target=tgt, os_eco=os_eco, include_dev=dev)
    elif k == "sbom":
        from .collectors.sbom import scan_sbom
        comps, notes = scan_sbom(inp, target=tgt)
    elif k == "archive":
        from .collectors.whitebox.jvm import scan_archive
        comps = scan_archive(Path(inp).read_bytes(), Path(inp).name, tgt)
    elif k == "list":
        from .collectors.whitebox import _sniff_text
        text = Path(inp).read_text(errors="replace")
        comps, _eco = _sniff_text(text, Path(inp).name.lower(), Path(inp).name, tgt, os_eco)
        if not comps:
            log("  ! File type not recognised. For an OS package list, specify the operating system (e.g. Debian:12).")
    elif k == "image":
        from .collectors.whitebox.container import scan_image
        comps, notes = scan_image(inp, target=tgt, include_dev=dev)
    elif k == "web":
        from .collectors.blackbox.web import scan_web
        comps, notes = scan_web(inp, target=tgt, evidence_dir=eng.evidence_dir, max_pages=web["max_pages"],
                                delay=web["delay"], probe=web["probe"], headers=web["headers"],
                                verify_tls=web["verify_tls"], log=log, login=web.get("login"),
                                on_waf=web.get("on_waf"), browser_tls=web.get("browser_tls"),
                                external_assets=web.get("external_assets", True), egress=web.get("egress"),
                                on_access=web.get("on_access"))
    elif k == "traffic":
        from .collectors.blackbox.traffic import scan_traffic
        comps, notes = scan_traffic(inp, target=tgt, evidence_dir=eng.evidence_dir, log=log)
    elif k == "apk":
        from .collectors.blackbox.apk import scan_apk
        comps, notes = scan_apk(inp, target=tgt, log=log)
    elif k == "ipa":
        from .collectors.blackbox.ipa import scan_ipa
        comps, notes = scan_ipa(inp, target=tgt, log=log)
    elif k == "desktop":
        from .collectors.blackbox.desktop import scan_desktop
        comps, notes = scan_desktop(inp, target=tgt, include_dev=dev, log=log)
    else:
        log(f"  ! type '{k}' is not supported in this version.")
        return
    added = eng.inventory.add(comps)
    for n in notes:
        eng.inventory.observe(n[0], tgt, n[1], n[2] if len(n) > 2 else "")
    eng.record_run(k, inp, tgt, added, len(comps))
    log(f"  {len(comps)} detections, {added} new components")
    queue += [(str(sub), "auto") for sub in nested]
    return {"kind": k, "detections": len(comps), "new": added, "nested": len(nested)}


def apply_suppressions(findings, rules):
    keep, out = [], []
    for f in findings:
        _, name, ver = f.component_key.split("|")
        rule = None
        for r in rules:
            ids = {f.vuln_id, *f.aliases}
            if r.get("id") not in ("*", None) and r["id"] not in ids:
                continue
            cname, _, cver = (r.get("component") or "*").partition("@")
            if cname not in ("*", "") and cname.lower() != name.lower():
                continue
            if cver and cver != ver:
                continue
            rule = r
            break
        if rule:
            out.append({**f.to_dict(), "suppression": rule})
        else:
            keep.append(f)
    return keep, out


def match_engagement(eng, db, extra_rules=None):
    from .matcher import match_inventory, priority_key
    comps = eng.inventory.sorted_components()
    findings, notes = match_inventory(comps, db, go_calls=eng.go_calls())
    findings.sort(key=priority_key)
    findings, suppressed = apply_suppressions(findings, eng.suppressions() + list(extra_rules or []))
    notes["suppressed"] = suppressed
    eng.save_findings(findings, notes, db.meta())
    return findings, notes
