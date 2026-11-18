from __future__ import annotations

from urllib.parse import urljoin, urlparse

PROFILES = ("chrome", "firefox", "safari", "edge")
MAX_REDIRECTS = 10


def available() -> bool:
    try:
        import curl_cffi
        return True
    except ImportError:
        return False


class BrowserTLSSession:
    def __init__(self, profile: str = "chrome", verify: bool = True, proxy: str | None = None):
        if profile not in PROFILES:
            raise ValueError("Geçersiz tarayıcı profili")
        try:
            from curl_cffi import requests as cr
        except ImportError as ex:
            raise RuntimeError("Tarayıcı uyumlu TLS için curl_cffi kurulu olmalı: pip install 'scakit[browser-tls]'") from ex
        self.proxy = proxy
        self._s = cr.Session(impersonate=profile, verify=verify, trust_env=False,
                             **({"proxies": {"http": proxy, "https": proxy}} if proxy else {}))
        self.headers: dict[str, str] = {}
        self.profile = profile

    @property
    def cookies(self):
        return self._s.cookies

    def _pin(self, url: str) -> dict:
        from curl_cffi import CurlOpt
        from ...server.guard import checked_ips
        p = urlparse(url)
        if p.scheme not in ("http", "https") or not p.hostname:
            raise ValueError(f"Desteklenmeyen adres: {url[:100]}")
        port = p.port or (443 if p.scheme == "https" else 80)
        ips = checked_ips(p.hostname, port)
        opts = {CurlOpt.PROTOCOLS_STR: b"http,https", CurlOpt.REDIR_PROTOCOLS_STR: b"http,https"}
        if ips and not self.proxy:
            addrs = ",".join(f"[{ip}]" if ":" in ip else ip for ip in ips)
            opts[CurlOpt.RESOLVE] = [f"{p.hostname}:{port}:{addrs}".encode()]
        return opts

    def request(self, method: str, url: str, allow_redirects: bool = True, timeout=20, stream=False, **kw):
        for _ in range(MAX_REDIRECTS + 1):
            self._s.curl_options = self._pin(url)
            r = self._s.request(method, url, headers=self.headers or None, allow_redirects=False, timeout=timeout,
                                stream=stream, **kw)
            loc = r.headers.get("location")
            if not (allow_redirects and loc and r.status_code in (301, 302, 303, 307, 308)):
                return r
            r.close()
            url = urljoin(str(r.url), loc)
            if r.status_code == 303 or (r.status_code in (301, 302) and method.upper() == "POST"):
                method = "GET"
                kw.pop("data", None)
                kw.pop("json", None)
        raise RuntimeError("Çok fazla yönlendirme")

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def post(self, url, **kw):
        return self.request("POST", url, **kw)

    def close(self):
        self._s.close()
