from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
JQ = b"/*! jQuery v1.12.4 | (c) jQuery Foundation | jquery.org/license */\n!function(){}();"
CH = b"""<html><head><title>Just a moment...</title></head><body>Verifying...
<script>setTimeout(function(){document.cookie="cleared=1; path=/"; location.reload();}, 1500);</script></body></html>"""
def page(title, links):
    a = "".join(f'<a href="{l}">{l}</a> ' for l in links)
    return f'<html><head><title>{title}</title><script src="/js/jquery.min.js"></script><script src="/js/app.js"></script></head><body>{a}</body></html>'.encode()
PAGES = {"/": page("Ana sayfa", ["/urunler", "/hakkinda", "/logout"]), "/urunler": page("Ürünler", ["/", "/urun/1"]),
         "/hakkinda": page("Hakkında", ["/"]), "/urun/1": page("Ürün 1", ["/urunler"])}
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        if "cleared=1" not in (self.headers.get("Cookie") or ""):
            return self._out(403, "text/html", CH, {"Server": "cloudflare", "cf-mitigated": "challenge"})
        if self.path == "/logout":
            raise SystemExit("logout must not be visited")
        if self.path == "/js/jquery.min.js":
            return self._out(200, "application/javascript", JQ)
        if self.path == "/js/app.js":
            return self._out(200, "application/javascript", b"/*! lodash lodash.com/license | Underscore.js 1.8.3 */ var VERSION='4.17.15';")
        body = PAGES.get(self.path)
        self._out(200 if body else 404, "text/html; charset=utf-8", body or b"yok", {"Server": "cloudflare"})
    def _out(self, code, ct, body, extra=None):
        self.send_response(code); self.send_header("Content-Type", ct); self.send_header("Content-Length", str(len(body)))
        self.send_header("Set-Cookie", "tracking=SECRETSET; path=/")
        for k, v in (extra or {}).items(): self.send_header(k, v)
        self.end_headers(); self.wfile.write(body)
ThreadingHTTPServer(("127.0.0.1", 8777), H).serve_forever()
