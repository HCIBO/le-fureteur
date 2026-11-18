#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from urllib.parse import urldefrag, urljoin, urlparse

SECRET_REQ = {"cookie", "authorization", "proxy-authorization", "x-api-key", "x-auth-token", "x-csrf-token",
              "x-xsrf-token", "api-key", "apikey", "x-amz-security-token"}
SECRET_RESP = {"set-cookie", "set-cookie2", "authorization", "www-authenticate"}
SKIP = re.compile(r"(log-?out|sign-?out|log-?off|cikis|çıkış|deconnexion|abmelden|delete|remove|destroy|unsubscribe)", re.I)
SKIP_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".pdf", ".zip", ".mp4", ".mp3", ".woff",
            ".woff2", ".ttf", ".doc", ".docx", ".xls", ".xlsx", ".exe", ".dmg", ".xml", ".rss", ".atom", ".json",
            ".txt", ".csv", ".gz", ".tar", ".apk", ".ipa", ".msi")
KEEP_TYPES = ("text/html", "javascript", "ecmascript", "text/css", "application/json", "text/plain", "xml")
MAX_BODY = 8 * 1024 * 1024
MAX_TOTAL = 400 * 1024 * 1024
CHALLENGE = re.compile(r"just a moment|attention required|checking your browser|verify you are human|"
                       r"bir dakika|güvenlik doğrulaması|access denied|captcha", re.I)


def api(server: str, ticket: str, path: str, data: bytes | None = None, ctype: str | None = None) -> dict:
    if not server.lower().startswith(("http://", "https://")):
        sys.exit("--server http:// veya https:// ile başlamalı")
    req = urllib.request.Request(server.rstrip("/") + "/api" + path, data=data, method="POST" if data else "GET")
    req.add_header("Authorization", f"Bearer {ticket}")
    req.add_header("User-Agent", "lf-capture/1.0")
    if ctype:
        req.add_header("Content-Type", ctype)
    try:
        with urllib.request.urlopen(req, timeout=300) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            msg = json.loads(e.read()).get("detail")
        except Exception:
            msg = e.reason
        sys.exit(f"Sunucu hatası ({e.code}): {msg}")


class Recorder:

    def __init__(self):
        self.entries, self.total = [], 0

    def on_response(self, resp):
        try:
            ctype = (resp.headers.get("content-type") or "").lower()
            status = resp.status
            if not (300 <= status < 400) and not any(k in ctype for k in KEEP_TYPES):
                return
            body = b""
            if not (300 <= status < 400):
                try:
                    body = resp.body()[:MAX_BODY]
                except Exception:
                    body = b""
            if self.total + len(body) > MAX_TOTAL:
                return
            self.total += len(body)
            import base64
            self.entries.append({
                "request": {"method": resp.request.method, "url": resp.url, "headers": []},
                "response": {"status": status,
                             "headers": [{"name": k, "value": v} for k, v in resp.headers.items() if k.lower() not in SECRET_RESP],
                             "content": {"mimeType": ctype, "encoding": "base64", "text": base64.b64encode(body).decode()}}})
        except Exception:
            pass

    def write(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"log": {"version": "1.2", "creator": {"name": "lf-capture"}, "entries": self.entries}}, f)


def sanitize(path: str) -> None:
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    for e in doc.get("log", {}).get("entries", []):
        req, resp = e.get("request") or {}, e.get("response") or {}
        req["headers"] = [h for h in req.get("headers") or [] if str(h.get("name", "")).lower() not in SECRET_REQ]
        req["cookies"] = []
        req.pop("postData", None)
        resp["headers"] = [h for h in resp.get("headers") or [] if str(h.get("name", "")).lower() not in SECRET_RESP]
        resp["cookies"] = []
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f)


def blocked(page) -> bool:
    try:
        return bool(CHALLENGE.search(page.title() or "")) or page.locator("iframe[src*='challenges.cloudflare.com']").count() > 0
    except Exception:
        return False


def wait_human(page, timeout: int = 600) -> bool:
    if not blocked(page):
        return True
    print("\n>>> Tarayıcı penceresinde doğrulamayı tamamlayın (en fazla 10 dakika bekleniyor)...", flush=True)
    end = time.time() + timeout
    while time.time() < end:
        time.sleep(2)
        if not blocked(page):
            print(">>> Doğrulama geçildi, devam ediliyor.", flush=True)
            time.sleep(2)
            return True
    return False


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Le Fureteur tarayıcı yardımcısı")
    ap.add_argument("--server", required=True, help="Le Fureteur adresi (ör. https://fureteur.firma.local)")
    ap.add_argument("--ticket", default=os.environ.get("LF_CAPTURE_TICKET"), help="Arayüzden alınan bilet (lfc_...)")
    ap.add_argument("--max-pages", type=int, help="Gezilecek en fazla sayfa (varsayılan: hedef ayarı)")
    a = ap.parse_args(argv)
    if not a.ticket:
        sys.exit("--ticket gerekli (Le Fureteur → tarama sayfası → Tarayıcı yardımcısı)")
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        sys.exit("Playwright kurulu değil. Kurulum:\n  python3 -m pip install playwright\n  python3 -m playwright install --with-deps chromium\n"
                 "(Ubuntu 24.04'te pip 'externally-managed' derse: python3 -m venv ~/.lf && ~/.lf/bin/pip install playwright "
                 "&& ~/.lf/bin/python -m playwright install --with-deps chromium; ardından ~/.lf/bin/python lf_capture.py ...)")
    info = api(a.server, a.ticket, "/capture/info")
    if info.get("used"):
        sys.exit("Bu bilet zaten kullanılmış; arayüzden yeni bilet üretin.")
    start, host = info["url"], urlparse(info["url"]).hostname
    max_pages, delay = a.max_pages or info["max_pages"], max(1.0, float(info["delay"]))
    print(f"Hedef: {start}  ·  en fazla {max_pages} sayfa  ·  sayfa arası {delay:.0f} sn")
    har = os.path.join(tempfile.mkdtemp(prefix="lf-capture-"), "capture.har")
    rec, n = Recorder(), 0
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=os.environ.get("LF_CAPTURE_HEADLESS") == "1")
        ctx = browser.new_context()
        ctx.on("response", rec.on_response)
        page = ctx.new_page()

        def alive() -> bool:
            return browser.is_connected() and not page.is_closed()

        try:
            page.goto(start, wait_until="domcontentloaded", timeout=60000)
            if not wait_human(page):
                print("Doğrulama tamamlanmadı; o ana kadarki kayıt yüklenecek.")
            queue, seen = [page.url], set()
            while queue and n < max_pages and alive():
                url = urldefrag(queue.pop(0))[0]
                if url in seen:
                    continue
                seen.add(url)
                if n:
                    time.sleep(delay)
                    try:
                        page.goto(url, wait_until="domcontentloaded", timeout=45000)
                    except Exception as ex:
                        if not alive():
                            break
                        print(f"  ! atlandı: {url} ({type(ex).__name__})")
                        continue
                    if not wait_human(page):
                        break
                try:
                    page.wait_for_load_state("networkidle", timeout=10000)
                except Exception:
                    pass
                if not alive():
                    break
                n += 1
                print(f"  [{n}/{max_pages}] {page.url}", flush=True)
                try:
                    hrefs = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
                except Exception:
                    hrefs = []
                for href in hrefs:
                    u = urldefrag(urljoin(page.url, href))[0]
                    pu = urlparse(u)
                    if pu.scheme in ("http", "https") and pu.hostname == host and u not in seen \
                            and not SKIP.search(u) and not pu.path.lower().endswith(SKIP_EXT):
                        queue.append(u)
        except KeyboardInterrupt:
            print("\nDurduruldu; o ana kadarki kayıt yüklenecek.")
        except Exception as ex:
            print(f"\nTarayıcı kapandı veya hata oluştu ({type(ex).__name__}); o ana kadarki kayıt yüklenecek.")
        finally:
            try:
                browser.close()
            except Exception:
                pass
    if not rec.entries:
        sys.exit("Kaydedilecek yanıt toplanamadı; yükleme yapılmadı.")
    rec.write(har)
    sanitize(har)
    size = os.path.getsize(har)
    print(f"Kayıt: {n} sayfa, {len(rec.entries)} yanıt, {size / 1024 / 1024:.1f} MB — çerez / yetki bilgisi içermez. Yükleniyor...")
    boundary = uuid.uuid4().hex
    with open(har, "rb") as f:
        body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"capture.har\"\r\n"
                f"Content-Type: application/json\r\n\r\n").encode() + f.read() + f"\r\n--{boundary}--\r\n".encode()
    res = api(a.server, a.ticket, "/capture/upload", body, f"multipart/form-data; boundary={boundary}")
    os.remove(har)
    print(f"Tamam. Tarama başladı: {a.server.rstrip('/')}{res['path']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
