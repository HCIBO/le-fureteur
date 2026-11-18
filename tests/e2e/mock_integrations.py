import json, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
LOG = sys.argv[1]
lock = threading.Lock()
issues = {"n": 0}

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _rec(self, body):
        with lock, open(LOG, "a") as f:
            f.write(json.dumps({"method": self.command, "path": self.path, "headers": dict(self.headers), "body": body.decode("utf-8", "replace")}) + "\n")
    def _send(self, code, obj=None):
        data = json.dumps(obj).encode() if obj is not None else b""
        self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    def do_GET(self):
        self._rec(b"")
        if not self.headers.get("Authorization"):
            return self._send(401, {"errorMessages": ["auth required"]})
        if self.path == "/rest/api/2/myself":
            return self._send(200, {"displayName": "Jira Bot", "emailAddress": "bot@acme.test"})
        if self.path.startswith("/rest/api/2/project/"):
            return self._send(200, {"key": self.path.rsplit("/", 1)[-1], "name": "Güvenlik"})
        self._send(404, {"errorMessages": ["not found"]})
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self._rec(body)
        if self.path == "/rest/api/2/issue":
            issues["n"] += 1
            return self._send(201, {"key": f"SEC-{issues['n']}", "id": str(1000 + issues["n"])})
        if self.path.endswith("/comment"):
            return self._send(201, {"id": "1"})
        self._send(200, {"ok": True})

ThreadingHTTPServer(("127.0.0.1", 8899), H).serve_forever()
