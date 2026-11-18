from __future__ import annotations

import hashlib
import json
import re
import time
from collections import deque
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urldefrag, urljoin, urlparse

from ..common import comp
from . import fingerprints as fp
from . import signatures as sig

UA = "scakit/0.1 (authorized software composition analysis)"
MAX_ASSET = 8 * 1024 * 1024
MAX_REQUESTS = 400
MAX_EXTERNAL_ASSETS = 80
TRACKERS = re.compile(r"(^|\.)(googletagmanager\.com|google-analytics\.com|analytics\.google\.com|doubleclick\.net|"
                      r"googlesyndication\.com|googleadservices\.com|facebook\.net|facebook\.com|hotjar\.com|clarity\.ms|"
                      r"segment\.com|segment\.io|hs-scripts\.com|hs-analytics\.net|hubspot\.com|intercom\.io|"
                      r"intercomcdn\.com|tiktok\.com|snapchat\.com|ads\.linkedin\.com|twitter\.com|"
                      r"yandex\.ru|mc\.yandex\.com|criteo\.(?:com|net)|taboola\.com|outbrain\.com|newrelic\.com|"
                      r"nr-data\.net|google\.com|gstatic\.com|recaptcha\.net|hcaptcha\.com|challenges\.cloudflare\.com)$", re.I)
PROBE_FILES = ["package.json", "package-lock.json", "yarn.lock", "composer.json", "composer.lock", "Gemfile.lock",
               "requirements.txt", "Pipfile.lock", "poetry.lock", "asset-manifest.json"]
CHUNK_REF = re.compile(r"[\"'`]((?:/|\./)?(?:static/js|_next/static/chunks|_next/static/[\w-]+|assets|js|dist|build)"
                       r"/[\w\-./~@]+?\.m?js)[\"'`]")
SKIP_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".pdf", ".zip", ".mp4", ".woff", ".woff2",
            ".ttf", ".eot", ".mp3", ".doc", ".docx", ".xls", ".xlsx", ".css", ".js", ".map", ".json", ".xml")


class _PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.scripts: list[tuple[str, bool]] = []
        self.styles: list[str] = []
        self.links: list[str] = []
        self.inline: list[str] = []
        self._in_script = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "script":
            if a.get("src"):
                self.scripts.append((a["src"], bool(a.get("integrity"))))
            else:
                self._in_script = True
        elif tag == "link":
            rel = (a.get("rel") or "").lower()
            href = a.get("href")
            if href and ("stylesheet" in rel):
                self.styles.append(href)
            elif href and ("modulepreload" in rel or (rel == "preload" and a.get("as") == "script")):
                self.scripts.append((href, bool(a.get("integrity"))))
        elif tag == "a" and a.get("href"):
            self.links.append(a["href"])

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_script = False

    def handle_data(self, data):
        if self._in_script and data.strip():
            self.inline.append(data)


_WAF_BODY = [
    ("cloudflare", re.compile(r"cf-chl-|cf_chl_opt|challenge-platform|Just a moment\.\.\.|Attention Required! \| Cloudflare", re.I)),
    ("imperva", re.compile(r"Incapsula incident ID|_Incapsula_Resource|Imperva", re.I)),
    ("akamai", re.compile(r"Reference&#32;&#35;[0-9a-f.]+|Access Denied.{0,200}errors\.edgesuite\.net", re.I | re.S)),
    ("aws-waf", re.compile(r"Request blocked\..{0,300}(cloudfront|aws)", re.I | re.S)),
    ("sucuri", re.compile(r"Sucuri WebSite Firewall|sucuri\.net/privacy-policy", re.I)),
    ("f5-asm", re.compile(r"The requested URL was rejected\. Please consult with your administrator", re.I)),
    ("perimeterx", re.compile(r"px-captcha|_pxCaptcha|perimeterx", re.I)),
    ("datadome", re.compile(r"captcha-delivery\.com|datadome", re.I)),
]


_CHALLENGE_200 = re.compile(r"<title>\s*(?:just a moment|attention required|security check|security verification|"
                            r"verify you are human|checking your browser|access denied|are you a robot)[^<]*</title>|"
                            r"RecaptchaChallengePageUi|/cdn-cgi/challenge-platform/h/|captcha-delivery\.com|px-captcha",
                            re.I)


def detect_waf(status: int, headers, body: bytes) -> str | None:
    h = {k.lower(): v for k, v in headers.items()}
    if h.get("cf-mitigated") == "challenge":
        return "cloudflare"
    if "x-amzn-waf-action" in h:
        return "aws-waf"
    if "x-datadome" in h and status in (401, 403, 405):
        return "datadome"
    if status == 200 and len(body) < 300_000:
        text = body[:65536].decode("utf-8", "replace")
        if _CHALLENGE_200.search(text):
            return next((v for v, rx in _WAF_BODY if rx.search(text)), "captcha")
        return None
    if status not in (401, 403, 405, 406, 429, 503):
        return None
    text = body[:65536].decode("utf-8", "replace")
    for vendor, rx in _WAF_BODY:
        if rx.search(text):
            return vendor
    server = h.get("server", "").lower()
    for key, vendor in (("cloudflare", "cloudflare"), ("akamaighost", "akamai"), ("sucuri", "sucuri"),
                        ("bigip", "f5-asm"), ("awselb", "aws-waf")):
        if key in server and status in (403, 503):
            return vendor
    if "x-iinfo" in h or "x-cdn" in h and "incapsula" in h.get("x-cdn", "").lower():
        return "imperva"
    if status == 429:
        return "rate-limit"
    return None


def _allow_proxy(url: str) -> None:
    try:
        from ...server.guard import allow_proxy
    except ImportError:
        return
    p = urlparse(url)
    allow_proxy(p.hostname, p.port or (1080 if p.scheme.startswith("socks") else 8080))


class WebScanner:
    def __init__(self, start_url, target, evidence_dir: Path | None, max_pages=25, delay=0.5, probe=True,
                 headers=None, verify_tls=True, log=None, login=None, on_waf=None, browser_tls=None,
                 external_assets=True, egress=None, on_access=None):
        import requests
        self.on_waf = on_waf
        self.waf_hits: dict[str, int] = {}
        self.waf_samples: list[dict] = []

        self.start = start_url
        self.host = urlparse(start_url).hostname
        self.target = target or self.host
        self.max_pages, self.delay, self.probe = max_pages, delay, probe
        self.log = log or (lambda m: None)
        from .browser_tls import PROFILES, available
        self.verify_tls = verify_tls
        self.external_assets, self.external_count = external_assets, 0
        self.on_access = on_access
        self.access_hits: dict[str, int] = {}
        self.access_samples: list[dict] = []
        self.site_adopted = False
        self.start_login = False
        eg = egress or {}
        self.proxies: list[tuple[str, str]] = list(eg.get("proxies") or [])
        mode = eg.get("mode") or "auto"
        self.auto_egress = mode == "auto" and bool(self.proxies)
        self.proxy = next(((n, u) for n, u in self.proxies if n == mode), None)
        self.egress_tried: list[str] = []
        self.extra_headers = [(k.strip(), v.strip()) for k, _, v in (h.partition(":") for h in headers or [])]
        self.tls_profile = browser_tls if browser_tls in PROFILES else None
        self.auto_tls = browser_tls in (None, "auto") and available()
        if self.tls_profile:
            self._use_browser_tls(self.tls_profile)
        else:
            self._use_requests()
        self.requests = 0
        self.req_log: list[dict] = []
        self.comps = []
        self.notes = []
        self.ev_dir = (evidence_dir / "web" / (self.host or "host")) if evidence_dir else None
        self.seen_assets: set[str] = set()
        self.script_dirs: set[str] = set()
        self.platforms: set[str] = set()
        self.wp_plugins: set[str] = set()
        self.wp_themes: set[str] = set()
        self.headers_seen: set[tuple] = set()
        self.login = login
        self.skip_re = re.compile(r"(log-?out|sign-?out|log-?off|oturumu-?kapat|cikis|çıkış|deconnexion|abmelden|"
                                  r"delete|remove|destroy|/sil\b|unsubscribe)", re.I) if (login or headers) else None

    def _use_requests(self):
        import requests
        from .browser_tls import available
        if self.proxy and self.proxy[1].startswith("socks") and available():
            return self._use_browser_tls("chrome")
        self.s = requests.Session()
        self.s.trust_env = False
        self.s.headers["User-Agent"] = UA
        for k, v in self.extra_headers:
            self.s.headers[k] = v
        self.s.verify = self.verify_tls
        if self.proxy:
            self.s.proxies = {"http": self.proxy[1], "https": self.proxy[1]}
            _allow_proxy(self.proxy[1])

    def _use_browser_tls(self, profile: str):
        from .browser_tls import BrowserTLSSession
        self.s = BrowserTLSSession(profile, self.verify_tls, proxy=self.proxy[1] if self.proxy else None)
        for k, v in self.extra_headers:
            self.s.headers[k] = v
        self.tls_profile = profile
        self.log(f"  HTTP istemcisi: tarayıcı uyumlu TLS ({profile})")

    def _rebuild_session(self):
        try:
            self.s.close()
        except Exception:
            pass
        if self.tls_profile:
            self._use_browser_tls(self.tls_profile)
        else:
            self._use_requests()
        if self.login:
            self.do_login()

    def _next_egress(self, reason: str) -> bool:
        if not self.auto_egress:
            return False
        left = [p for p in self.proxies if p[0] not in self.egress_tried]
        if not left:
            return False
        self.proxy = left[0]
        self.egress_tried.append(left[0][0])
        self.log(f"  erişim engeli ({reason}); '{left[0][0]}' çıkış noktası üzerinden yeniden deneniyor")
        self._rebuild_session()
        return True

    def _access(self, kind: str, url: str, detail: str = "", status=None):
        self.access_hits[kind] = self.access_hits.get(kind, 0) + 1
        if len(self.access_samples) < 5:
            self.access_samples.append({"url": url, "kind": kind, "detail": detail, "status": status})

    def _report_access(self, n_pages: int):
        from .access import PRIORITY
        if not self.access_hits:
            return
        hits = dict(self.access_hits)
        if not self.start_login:
            hits.pop("login_required", None)
        if not hits:
            return
        total = sum(hits.values())
        kind = min(hits, key=lambda k: PRIORITY.index(k) if k in PRIORITY else 99)
        severe = n_pages == 0 or kind == "login_required" or total >= max(1, self.requests // 2)
        info = {"issue": kind, "counts": hits, "samples": self.access_samples, "pages": n_pages,
                "requests": self.requests, "severe": severe, "egress": self.proxy[0] if self.proxy else None,
                "egress_tried": self.egress_tried, "detail": next((s["detail"] for s in self.access_samples
                                                                   if s["kind"] == kind), "")}
        if severe:
            self.log(f"  ! erişim engeli: {kind} ({info['detail']})")
        if self.on_access:
            self.on_access(info)

    def in_scope(self, url: str) -> bool:
        p = urlparse(url)
        return p.scheme in ("http", "https") and p.hostname == self.host

    def get(self, url: str, max_bytes=MAX_ASSET, external=False, _retry=True):
        if self.requests >= MAX_REQUESTS:
            return None
        if self.requests:
            time.sleep(self.delay)
        self.requests += 1
        try:
            if self.proxy and not self.tls_profile:
                try:
                    from ...server.guard import checked_ips
                    pu = urlparse(url)
                    checked_ips(pu.hostname, pu.port or (443 if pu.scheme == "https" else 80))
                except ImportError:
                    pass
            r = self.s.get(url, timeout=20, allow_redirects=True, stream=True)
            if hasattr(r, "raw") and hasattr(r.raw, "read"):
                body = r.raw.read(max_bytes + 1, decode_content=True)
            else:
                buf = bytearray()
                for chunk in r.iter_content():
                    buf += chunk
                    if len(buf) > max_bytes:
                        break
                body = bytes(buf[:max_bytes + 1])
            r.close()
        except Exception as e:
            from .access import classify_error
            kind = classify_error(e)
            self.req_log.append({"url": url, "error": str(e)[:200], "access": kind})
            if not external:
                self._access(kind, url, str(e)[:160])
                if kind in ("timeout", "reset", "refused") and self.requests <= 3 and self._next_egress(kind):
                    return self.get(url, max_bytes, external)
            return None
        vendor = detect_waf(r.status_code, r.headers, body)
        if not external:
            from .access import captcha_kind, classify_response, same_site
            final_host = urlparse(str(r.url)).hostname
            if (not self.site_adopted and self.requests <= 2 and final_host != self.host
                    and same_site(self.host, final_host) and 200 <= r.status_code < 400):
                self.log(f"  {self.host} → {final_host} yönlendirmesi: tarama {final_host} üzerinden sürüyor")
                self.host, self.site_adopted = final_host, True
            acc = classify_response(r.status_code, r.headers, body, str(r.url), self.host)
            if acc:
                self._access(acc[0], url, acc[1], r.status_code)
                if acc[0] == "login_required" and urldefrag(url)[0] == urldefrag(self.start)[0]:
                    self.start_login = True
                if acc[0] in ("geo_block", "ip_block") and self._next_egress(acc[0]):
                    return self.get(url, max_bytes, external)
            elif vendor == "captcha":
                self._access("captcha", url, captcha_kind(body[:65536].decode("utf-8", "replace")) or "", r.status_code)
        if r.status_code in (429, 503) and _retry and (r.status_code == 429 or r.headers.get("retry-after")):
            ra = r.headers.get("retry-after", "")
            wait = min(int(ra), 30) if ra.isdigit() else max(5.0, self.delay * 4)
            self.delay = min(max(self.delay * 2, 1.0), 10.0)
            self.req_log.append({"url": url, "status": r.status_code, "retry_after": wait})
            self.log(f"  {'hız sınırı' if r.status_code == 429 else 'geçici kapalı'} ({r.status_code}): {wait:.0f} sn beklenip yeniden deneniyor; bekleme {self.delay:.1f} sn'ye çıkarıldı")
            time.sleep(wait)
            return self.get(url, max_bytes, external, _retry=False)
        if vendor and vendor != "rate-limit" and self.auto_tls and not self.tls_profile:
            self.req_log.append({"url": url, "status": r.status_code, "waf": vendor, "retry": "browser-tls"})
            self.log(f"  {vendor} engeli görüldü; tarayıcı uyumlu TLS'e otomatik geçiliyor")
            self.s.close()
            self._use_browser_tls("chrome")
            if self.login:
                self.do_login()
            return self.get(url, max_bytes, external)
        if vendor:
            self.waf_hits[vendor] = self.waf_hits.get(vendor, 0) + 1
            if len(self.waf_samples) < 5:
                self.waf_samples.append({"url": url, "status": r.status_code, "vendor": vendor})
        final_ok = self.in_scope(r.url) or (external and urlparse(str(r.url)).hostname == urlparse(url).hostname)
        self.req_log.append({"url": url, "final": r.url, "status": r.status_code, "bytes": len(body),
                             "sha256": hashlib.sha256(body).hexdigest(), "content_type": r.headers.get("content-type", "")})
        if not final_ok:
            return None
        return r, body[:max_bytes]

    def save_evidence(self, url: str, body: bytes, suffix: str) -> str:
        if not self.ev_dir:
            return url
        self.ev_dir.mkdir(parents=True, exist_ok=True)
        name = hashlib.sha1(url.encode()).hexdigest()[:12] + suffix
        (self.ev_dir / name).write_bytes(body)
        return url

    def add(self, eco, name, ver, method, loc, detail="", confidence="medium", estimated=False):
        self.comps.append(comp(eco, name, ver, method, loc, detail=detail, target=self.target,
                               confidence=confidence if ver else "low", estimated=estimated))

    def check_headers(self, r):
        for hname, rules in sig.HEADER_RULES.items():
            val = r.headers.get(hname)
            if not val or (hname, val) in self.headers_seen:
                continue
            self.headers_seen.add((hname, val))
            for rx, eco, name in rules:
                m = rx.search(val)
                if m:
                    ver = m.group(1) if m.groups() else None
                    self.add(eco, name, ver, "header", r.url, detail=f"{hname}: {val}")
                    if ver:
                        self.notes.append(("version-header", r.url, f"{hname}: {val}"))

    def analyze_text(self, url: str, text: str, kind: str):
        hits = sig.scan_js(text)
        for name, ver, snippet in hits:
            self.add("npm", name, ver, "signature", url, detail=snippet)
        return bool(hits)

    def analyze_sourcemap(self, js_url: str, js_text: str, r):
        m = re.search(r"//[#@] sourceMappingURL=([^\s'\"]+)\s*$", js_text[-2000:])
        ref = r.headers.get("SourceMap") or r.headers.get("X-SourceMap") or (m.group(1) if m else None)
        if not ref or ref.startswith("data:"):
            return
        map_url = urljoin(js_url, ref)
        if not self.in_scope(map_url) or map_url in self.seen_assets:
            return
        self.seen_assets.add(map_url)
        res = self.get(map_url, max_bytes=64 * 1024 * 1024)
        if not res or res[0].status_code != 200:
            return
        try:
            sm = json.loads(res[1])
        except ValueError:
            return
        sources = [s for s in sm.get("sources") or [] if isinstance(s, str)]
        if not sources:
            return
        self.save_evidence(map_url, res[1], ".map")
        self.notes.append(("sourcemap-exposed", map_url, f"{len(sources)} kaynak dosya"))
        pkgs = sig.analyze_sourcemap(sm)
        for name, vers in sorted(pkgs.items()):
            if vers:
                for v in sorted(vers):
                    self.add("npm", name, v, "sourcemap", map_url, detail="source map")
            else:
                self.add("npm", name, None, "sourcemap", map_url, detail="source map (sürüm yok)")

    def fetch_asset(self, url: str, has_sri: bool, page_url: str, is_script: bool = True):
        url = urldefrag(url)[0]
        if url in self.seen_assets:
            return []
        self.seen_assets.add(url)
        cdn = sig.cdn_match(url)
        if cdn:
            self.add("npm", cdn[0], cdn[1], "cdn-url", url, detail=f"sayfa: {page_url}")
        external = not self.in_scope(url)
        if external:
            if is_script and not has_sri:
                self.notes.append(("missing-sri", url, f"sayfa: {page_url}"))
            host = urlparse(url).hostname or ""
            if (cdn or not self.external_assets or self.external_count >= MAX_EXTERNAL_ASSETS
                    or urlparse(url).scheme not in ("http", "https") or TRACKERS.search(host)):
                return []
            self.external_count += 1
        if (m := sig.WP_VER.search(url)):
            self.add("generic", "wordpress", m.group(1), "query-version", url, confidence="low", estimated=True)
        res = self.get(url, external=external)
        if not res or res[0].status_code != 200:
            return []
        r, body = res
        text = body.decode("utf-8", "replace")
        if self.analyze_text(url, text, "js" if is_script else "css"):
            self.save_evidence(url, body, ".js" if is_script else ".css")
        new = []
        if is_script:
            self.script_dirs.add(url.rsplit("/", 1)[0] + "/")
            self.analyze_sourcemap(url, text, r)
            lm = sig.LICENSE_REF.search(text[:3000]) or sig.LICENSE_REF.search(text[-3000:])
            if lm:
                lic_url = urljoin(url, lm.group(1))
                same = urlparse(lic_url).hostname == urlparse(url).hostname
                if (self.in_scope(lic_url) or (external and same)) and lic_url not in self.seen_assets:
                    self.seen_assets.add(lic_url)
                    lres = self.get(lic_url, external=external)
                    if lres and lres[0].status_code == 200:
                        ltext = lres[1].decode("utf-8", "replace")
                        if self.analyze_text(lic_url, ltext, "license"):
                            self.save_evidence(lic_url, lres[1], ".LICENSE.txt")
            for ref in CHUNK_REF.findall(text)[:200]:
                cands = [urljoin(self.start, "/" + ref.lstrip("./"))]
                if not ref.startswith("/"):
                    cands.append(urljoin(url, ref))
                for u in cands:
                    if self.in_scope(u) and u not in self.seen_assets and u not in new:
                        new.append(u)
        return new

    def probe_error_page(self):
        import secrets
        url = urljoin(self.start, f"/scakit-{secrets.token_hex(6)}")
        res = self.get(url, max_bytes=512 * 1024)
        if not res:
            return
        r, body = res
        self.check_headers(r)
        text = body.decode("utf-8", "replace")
        for eco, name, ver, snip in fp.scan_body(text):
            self.add(eco, name, ver, "error-page", url, detail=f"HTTP {r.status_code}: {snip}")
            if ver:
                self.notes.append(("version-error-page", url, f"{name} {ver}"))

    def probe_platforms(self):
        for plat in sorted(self.platforms):
            for path in fp.PROBES.get(plat, []):
                self._probe_version(urljoin(self.start, path), plat)
        if "wordpress" in self.platforms:
            for slug in sorted(self.wp_plugins)[:20]:
                self._probe_wp_ext(f"/wp-content/plugins/{slug}/readme.txt", slug, "wordpress-plugin",
                                   re.compile(r"Stable tag:\s*(\d[\w.]*)", re.I))
            for slug in sorted(self.wp_themes)[:5]:
                self._probe_wp_ext(f"/wp-content/themes/{slug}/style.css", slug, "wordpress-theme",
                                   re.compile(r"^\s*Version:\s*(\d[\w.]*)", re.I | re.M))

    def _probe_version(self, url: str, plat: str):
        if url in self.seen_assets:
            return
        self.seen_assets.add(url)
        res = self.get(url, max_bytes=2 * 1024 * 1024)
        if not res or res[0].status_code != 200:
            return
        text = res[1].decode("utf-8", "replace")
        if text.lstrip()[:15].lower().startswith(("<!doctype html", "<html")):
            return
        for eco, name, ver, snip in fp.scan_body(text):
            self.add(eco, name, ver, "cms-version", url, detail=snip)
            if ver:
                self.save_evidence(url, res[1], "-" + url.rstrip("/").rsplit("/", 1)[-1])
                self.notes.append(("version-disclosure", url, f"{name} {ver}"))

    def _probe_wp_ext(self, path: str, slug: str, kind: str, rx):
        url = urljoin(self.start, path)
        if url in self.seen_assets:
            return
        self.seen_assets.add(url)
        res = self.get(url, max_bytes=256 * 1024)
        if not res or res[0].status_code != 200:
            return
        m = rx.search(res[1].decode("utf-8", "replace"))
        if m:
            self.add("generic", f"{kind}:{slug}", m.group(1), "cms-version", url, detail=m.group(0)[:80])

    def probe_license_manifests(self):
        dirs = sorted(self.script_dirs | {urljoin(self.start, "/")})
        for d in dirs[:10]:
            for fn in sig.LICENSE_MANIFESTS:
                url = urljoin(d, fn)
                if url in self.seen_assets or not self.in_scope(url):
                    continue
                self.seen_assets.add(url)
                res = self.get(url, max_bytes=16 * 1024 * 1024)
                if not res or res[0].status_code != 200:
                    continue
                body = res[1].decode("utf-8", "replace")
                if body.lstrip()[:1] in ("<", "") or "html" in res[0].headers.get("content-type", "").lower():
                    continue
                pkgs = sig.parse_license_manifest(body)
                if not pkgs:
                    continue
                self.save_evidence(url, res[1], "-" + fn)
                self.notes.append(("license-manifest", url, f"{len(pkgs)} paket"))
                for name, lic, ver in pkgs:
                    self.comps.append(comp("npm", name, ver, "license-manifest", url, detail=lic, target=self.target,
                                           confidence="medium" if ver else "low", licenses=[lic] if lic else None))
                for name, ver, _ in sig.scan_js(body):
                    self.add("npm", name, ver, "signature", url)

    def probe_files(self):
        from ..whitebox import js as wjs, others as wo, python as wpy

        parsers = {"package.json": wjs.parse_package_json, "package-lock.json": wjs.parse_package_lock,
                   "yarn.lock": wjs.parse_yarn_lock, "composer.lock": wo.parse_composer_lock,
                   "Gemfile.lock": wo.parse_gemfile_lock, "requirements.txt": wpy.parse_requirements,
                   "Pipfile.lock": wpy.parse_pipfile_lock, "poetry.lock": wpy.parse_poetry_lock}
        bases = {urljoin(self.start, "/")}
        p = urlparse(self.start).path
        if p and p != "/":
            bases.add(urljoin(self.start, p if p.endswith("/") else p.rsplit("/", 1)[0] + "/"))
        extra_js = []
        for base in sorted(bases):
            for fn in PROBE_FILES:
                url = urljoin(base, fn)
                res = self.get(url, max_bytes=16 * 1024 * 1024)
                if not res or res[0].status_code != 200:
                    continue
                body = res[1].decode("utf-8", "replace")
                if body.lstrip()[:1] in ("<", "") or "html" in res[0].headers.get("content-type", "").lower():
                    continue
                if fn == "asset-manifest.json":
                    try:
                        files = json.loads(body).get("files", {})
                        extra_js += [urljoin(base, v) for v in files.values() if isinstance(v, str) and v.endswith(".js")]
                    except (ValueError, AttributeError):
                        pass
                    continue
                if fn == "composer.json":
                    continue
                found = parsers[fn](body, url, self.target)
                if found:
                    for c in found:
                        c.evidence[0].method = "exposed-file"
                    self.comps += found
                    self.save_evidence(url, res[1], "-" + fn)
                    self.notes.append(("exposed-file", url, f"{len(found)} bileşen"))
        return extra_js

    def do_login(self):
        L = self.login
        url = L["login_url"]
        action = L.get("action_url") or url
        if not (self.in_scope(url) and self.in_scope(action)):
            raise RuntimeError("Giriş adresi hedefle aynı makinede olmalı")
        data = {L["username_field"]: L["username"], L["password_field"]: L["password"], **(L.get("extra") or {})}
        if L.get("csrf_field"):
            r0 = self.s.get(url, timeout=20)
            self.requests += 1
            m = re.search(r'<input[^>]*name=["\']' + re.escape(L["csrf_field"]) + r'["\'][^>]*>', r0.text, re.I)
            val = re.search(r'value=["\']([^"\']*)', m.group(0)) if m else None
            if not val:
                raise RuntimeError(f"Giriş sayfasında '{L['csrf_field']}' alanı bulunamadı")
            data[L["csrf_field"]] = val.group(1)
        if L.get("format") == "json":
            r = self.s.post(action, json=data, timeout=20, allow_redirects=True)
        else:
            r = self.s.post(action, data=data, timeout=20, allow_redirects=True)
        self.requests += 1
        body = r.text[:500_000]
        ok = r.status_code < 400 and self.in_scope(r.url)
        if L.get("success_text"):
            ok = ok and L["success_text"] in body
        if L.get("failure_text") and L["failure_text"] in body:
            ok = False
        self.req_log.append({"url": action, "login": True, "status": r.status_code, "final": r.url})
        if not ok:
            raise RuntimeError(f"Form ile giriş başarısız (HTTP {r.status_code}); kullanıcı bilgilerini ve "
                               "başarı / hata metnini kontrol edin")
        self.log(f"  giriş başarılı ({len(self.s.cookies)} çerez)")

    def run(self):
        if self.login:
            self.do_login()
        pages = deque(getattr(self, "seeds", None) or [self.start])
        seen_pages = set()
        asset_queue: deque = deque()
        n_pages = 0
        while pages and n_pages < self.max_pages:
            url = urldefrag(pages.popleft())[0]
            if url in seen_pages or not self.in_scope(url):
                continue
            seen_pages.add(url)
            res = self.get(url, max_bytes=4 * 1024 * 1024)
            if not res:
                continue
            r, body = res
            n_pages += 1
            self.check_headers(r)
            ctype = r.headers.get("content-type", "")
            if "html" not in ctype.lower():
                continue
            html = body.decode(r.encoding or "utf-8", "replace")
            pp = _PageParser()
            try:
                pp.feed(html)
            except Exception:
                pass
            for eco, name, ver, snip in fp.scan_body(html):
                self.add(eco, name, ver, "body-banner", r.url, detail=snip)
            self.platforms |= fp.detect_platforms(html, r.headers)
            plugins, themes = fp.wp_extensions(html)
            self.wp_plugins |= plugins
            self.wp_themes |= themes
            for g in sig.META_GENERATOR.findall(html):
                for rx, eco, name in sig.GENERATOR_RULES:
                    m = rx.search(g)
                    if m:
                        self.add(eco, name, m.group(1) if m.groups() and m.group(1) else None, "meta-generator", r.url,
                                 detail=g)
            for txt in pp.inline:
                self.analyze_text(r.url, txt, "inline")
            if "/_next/" in html:
                self.add("npm", "next", None, "signature", r.url, detail="/_next/ yolları")
            for src, sri in pp.scripts:
                asset_queue.append((urljoin(r.url, src), sri, r.url, True))
            for href in pp.styles:
                asset_queue.append((urljoin(r.url, href), True, r.url, False))
            for href in pp.links:
                u = urldefrag(urljoin(r.url, href))[0]
                if self.in_scope(u) and not urlparse(u).path.lower().endswith(SKIP_EXT) and \
                        not (self.skip_re and self.skip_re.search(u)):
                    pages.append(u)
            while asset_queue:
                a_url, sri, page, is_script = asset_queue.popleft()
                for u in self.fetch_asset(a_url, sri, page, is_script):
                    asset_queue.append((u, True, page, True))
        for plat in sorted(self.platforms):
            if not any(c.name.lower() in (plat, f"microsoft-{plat}") for c in self.comps):
                self.add("generic", "microsoft-sharepoint" if plat == "sharepoint" else plat, None, "platform",
                         self.start, detail="platform işaretleri (başlık / sayfa içeriği)")
        if self.probe:
            self.probe_error_page()
            self.probe_platforms()
            self.probe_license_manifests()
            for u in self.probe_files():
                for nu in self.fetch_asset(u, True, self.start, True):
                    self.fetch_asset(nu, True, self.start, True)
        if self.ev_dir:
            self.ev_dir.mkdir(parents=True, exist_ok=True)
            (self.ev_dir / "requests.json").write_text(json.dumps(self.req_log, indent=1))
        self.s.close()
        self.log(f"  {n_pages} sayfa, {self.requests} istek, {len(self.comps)} tespit")
        self._report_access(n_pages)
        if self.waf_hits:
            vendor = max(self.waf_hits, key=self.waf_hits.get)
            blocked = sum(self.waf_hits.values())
            info = {"vendor": vendor, "blocked": blocked, "requests": self.requests, "pages": n_pages,
                    "components": len(self.comps), "samples": self.waf_samples, "browser_tls": self.tls_profile,
                    "severe": n_pages == 0 or blocked >= max(1, self.requests // 2)}
            self.log(f"  ! WAF / bot koruması: {vendor} — {blocked}/{self.requests} istek engellendi veya sorguya çekildi")
            self.notes.append(f"WAF / bot koruması tespit edildi ({vendor}): {blocked}/{self.requests} istek engellendi; "
                              "sonuçlar eksik olabilir. Tarayıcı IP'sini veya bir tarama başlığını WAF'ta izin listesine "
                              "ekleyin ya da kaynak kod / SBOM yükleyin.")
            if self.on_waf:
                self.on_waf(info)
        return self.comps, _dedupe_notes(self.notes)


def _dedupe_notes(notes):
    seen, out = set(), []
    for n in notes:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def scan_web(url, target="", evidence_dir=None, max_pages=25, delay=0.5, probe=True, headers=None,
             verify_tls=True, log=None, login=None, on_waf=None, browser_tls=None, external_assets=True,
             egress=None, on_access=None):
    return WebScanner(url, target, Path(evidence_dir) if evidence_dir else None, max_pages, delay, probe, headers,
                      verify_tls, log, login=login, on_waf=on_waf, browser_tls=browser_tls,
                      external_assets=external_assets, egress=egress, on_access=on_access).run()
