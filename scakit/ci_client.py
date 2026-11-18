#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import tempfile
import time
import uuid
import zipfile
from pathlib import Path
from urllib import error, request

EXCLUDE_DIRS = {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env", "__pycache__", ".tox", ".mypy_cache",
                ".pytest_cache", ".idea", ".vscode", ".gradle", ".terraform", "bower_components", ".next", ".nuxt"}
EXCLUDE_EXT = {".pyc", ".class", ".o", ".so", ".dll", ".exe", ".png", ".jpg", ".jpeg", ".gif", ".mp4", ".zip",
               ".pdf", ".iso", ".tar", ".gz"}
KEEP_EXT_ALWAYS = {".jar", ".war", ".ear"}


def log(msg: str) -> None:
    print(f"[le-fureteur] {msg}", flush=True)


def build_zip(root: Path, extra_exclude: list[str]) -> Path:
    tmp = Path(tempfile.mkstemp(suffix=".zip")[1])
    count = 0
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zf:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS and d not in extra_exclude]
            for fn in filenames:
                p = Path(dirpath) / fn
                ext = p.suffix.lower()
                rel = p.relative_to(root).as_posix()
                if (ext in EXCLUDE_EXT and ext not in KEEP_EXT_ALWAYS) or any(rel.startswith(x) for x in extra_exclude):
                    continue
                try:
                    if p.is_symlink() or p.stat().st_size > 200 * 1024 * 1024:
                        continue
                except OSError:
                    continue
                zf.write(p, rel)
                count += 1
    log(f"{count} files packaged ({tmp.stat().st_size // 1024} KB)")
    return tmp


class Client:
    def __init__(self, url: str, token: str, cacert: str | None, insecure: bool):
        if not url.lower().startswith(("http://", "https://")):
            raise SystemExit("--url must start with http:// or https://")
        self.url = url.rstrip("/")
        self.token = token
        self.ctx = ssl.create_default_context(cafile=cacert) if cacert else ssl.create_default_context()
        if insecure:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    def call(self, method: str, path: str, body=None, headers=None, raw: bool = False):
        h = {"Authorization": f"Bearer {self.token}", "User-Agent": "le-fureteur-ci", **(headers or {})}
        req = request.Request(self.url + path, data=body, method=method, headers=h)
        try:
            with request.urlopen(req, context=self.ctx, timeout=300) as r:
                data = r.read()
        except error.HTTPError as ex:
            detail = ex.read().decode("utf-8", "replace")[:500]
            try:
                detail = json.loads(detail).get("detail", detail)
            except ValueError:
                pass
            raise SystemExit(self._fail(f"HTTP {ex.code} {path}: {detail}"))
        except error.URLError as ex:
            raise SystemExit(self._fail(f"Could not connect to the server ({self.url}): {ex.reason}"))
        return data if raw else json.loads(data.decode("utf-8"))

    @staticmethod
    def _fail(msg: str) -> int:
        log("ERROR: " + msg)
        return 2

    def upload(self, fields: dict, file_path: Path):
        boundary = uuid.uuid4().hex
        body = Path(tempfile.mkstemp(suffix=".multipart")[1])
        with open(body, "wb") as out:
            for k, v in fields.items():
                out.write(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode())
            out.write(f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{file_path.name}\"\r\n"
                      f"Content-Type: application/octet-stream\r\n\r\n".encode())
            with open(file_path, "rb") as src:
                while chunk := src.read(1 << 20):
                    out.write(chunk)
            out.write(f"\r\n--{boundary}--\r\n".encode())
        try:
            with open(body, "rb") as fh:
                return self.call("POST", "/api/ci/scan", body=fh, headers={
                    "Content-Type": f"multipart/form-data; boundary={boundary}",
                    "Content-Length": str(body.stat().st_size)})
        finally:
            body.unlink(missing_ok=True)


def default_ref() -> str:
    for k in ("GITHUB_SHA", "CI_COMMIT_SHA", "GIT_COMMIT", "BUILD_SOURCEVERSION", "BITBUCKET_COMMIT"):
        if os.environ.get(k):
            branch = os.environ.get("GITHUB_REF_NAME") or os.environ.get("CI_COMMIT_REF_NAME") or \
                os.environ.get("BRANCH_NAME") or os.environ.get("BUILD_SOURCEBRANCHNAME") or ""
            return f"{branch}@{os.environ[k][:12]}" if branch else os.environ[k][:12]
    return ""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="lf_ci", description="Le Fureteur CI scan")
    ap.add_argument("--url", default=os.environ.get("LF_URL"), help="server address (LF_URL)")
    ap.add_argument("--token", default=os.environ.get("LF_TOKEN"), help="API token (LF_TOKEN)")
    ap.add_argument("--project", type=int, default=int(os.environ["LF_PROJECT"]) if os.environ.get("LF_PROJECT") else None,
                    help="project number (LF_PROJECT)")
    ap.add_argument("--target", default=os.environ.get("LF_TARGET") or "", help="target name (default: folder name)")
    ap.add_argument("--path", default=".", help="folder to scan (default: .)")
    ap.add_argument("--file", help="upload a single file instead of a folder (SBOM, lock file, JAR, image .tar, APK ...)")
    ap.add_argument("--exclude", action="append", default=[], help="folder / path prefix to exclude")
    ap.add_argument("--fail-on", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"], help="severity threshold")
    ap.add_argument("--kev", choices=["true", "false"], help="fail on actively exploited (KEV) findings")
    ap.add_argument("--license", choices=["true", "false"], help="fail on denied licenses")
    ap.add_argument("--new-only", action="store_true", help="only findings new in this scan affect the gate")
    ap.add_argument("--sarif", help="write a SARIF file here (GitHub / GitLab code scanning)")
    ap.add_argument("--timeout", type=int, default=1800, help="maximum wait (seconds)")
    ap.add_argument("--no-fail", action="store_true", help="exit 0 even if the gate fails (report only)")
    ap.add_argument("--cacert", help="internal CA certificate (PEM)")
    ap.add_argument("--insecure", action="store_true", help="disable TLS verification (not recommended)")
    ap.add_argument("--ref", default=default_ref(), help="branch / commit reference")
    a = ap.parse_args(argv)
    if not (a.url and a.token and a.project):
        log("ERROR: --url, --token and --project (or LF_URL, LF_TOKEN, LF_PROJECT) are required")
        return 2

    c = Client(a.url, a.token, a.cacert, a.insecure)
    root = Path(a.path).resolve()
    if a.file:
        upload, cleanup = Path(a.file), False
    else:
        upload, cleanup = build_zip(root, a.exclude), True
    target = a.target or root.name or "ci"
    fields = {"project_id": a.project, "target": target, "ref": a.ref}
    for k, v in (("fail_on", a.fail_on), ("fail_on_kev", a.kev), ("fail_on_license", a.license),
                 ("new_only", "true" if a.new_only else None)):
        if v:
            fields[k] = v
    try:
        res = c.upload(fields, upload)
    finally:
        if cleanup:
            upload.unlink(missing_ok=True)
    log(f"scan #{res['scan_id']} started (target: {target}) — {res['ui_url']}")

    start, last = time.time(), None
    while True:
        st = c.call("GET", res["status_url"])
        if st["status"] != last or st["status"] == "running":
            if st["status"] != last:
                log(f"status: {st['status']}")
            last = st["status"]
        if st["status"] in ("done", "failed", "canceled"):
            break
        if time.time() - start > a.timeout:
            log("ERROR: timed out")
            return 2
        time.sleep(5)
    if st["status"] != "done":
        log(f"ERROR: scan {st['status']}: {st.get('error') or ''}")
        return 2

    s, g = st["summary"] or {}, st["gate"]
    sev = g["counts"]["severity"]
    log(f"{s.get('components', 0)} components, {g['counts']['findings']} open findings — "
        + ", ".join(f"{k} {sev.get(k, 0)}" for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW"))
        + f", KEV {g['counts']['kev']} | new {s.get('new', 0)}, fixed {s.get('fixed', 0)}")
    if a.sarif:
        Path(a.sarif).write_bytes(c.call("GET", res["sarif_url"], raw=True))
        log(f"SARIF written: {a.sarif}")
    pol = g["policy"]
    log(f"policy: fail_on={pol['fail_on']} kev={pol['fail_on_kev']} license={pol['fail_on_license']} "
        f"new_only={pol['new_only']}")
    if g["passed"]:
        log("RESULT: PASSED")
        return 0
    for r in g["reasons"]:
        detail = f" (threshold {r['threshold']})" if r.get("threshold") else ""
        log(f"  ✗ {r['rule']}{detail}: {r['count']}")
    log("RESULT: FAILED" + (" (--no-fail: exiting with 0 anyway)" if a.no_fail else ""))
    return 0 if a.no_fail else 1


if __name__ == "__main__":
    sys.exit(main())
