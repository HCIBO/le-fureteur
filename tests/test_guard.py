import http.server
import threading
import unittest

import requests

from scakit.server import guard


def _serve(host, handler):
    s = http.server.HTTPServer((host, 0), handler)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s


class Quiet(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass


class GuardTest(unittest.TestCase):
    def test_internal_variants_blocked(self):
        class Ok(Quiet):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
        s = _serve("127.0.0.1", Ok)
        p = s.server_port
        for u in (f"http://127.0.0.1:{p}/", f"http://localhost:{p}/", f"http://0x7f000001:{p}/",
                  f"http://2130706433:{p}/", f"http://[::ffff:127.0.0.1]:{p}/"):
            with guard.outbound_guard(), self.assertRaises(requests.ConnectionError) as cm:
                requests.get(u, timeout=3)
            self.assertIn("engellendi", str(cm.exception), u)
        self.assertEqual(requests.get(f"http://127.0.0.1:{p}/", timeout=3).status_code, 200)
        with guard.outbound_guard(enabled=False):
            self.assertEqual(requests.get(f"http://127.0.0.1:{p}/", timeout=3).status_code, 200)

    def test_redirect_hop_blocked_before_request(self):
        hits = []

        class Internal(Quiet):
            def do_GET(self):
                hits.append(self.path)
                self.send_response(200)
                self.end_headers()
        b = _serve("127.0.0.2", Internal)

        class Redirector(Quiet):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.2:{b.server_port}/secret")
                self.end_headers()
        a = _serve("127.0.0.1", Redirector)
        orig = guard._bad_ip
        guard._bad_ip = lambda ip: ip == "127.0.0.2"
        try:
            with guard.outbound_guard(), self.assertRaises(requests.ConnectionError):
                requests.get(f"http://127.0.0.1:{a.server_port}/", timeout=3)
        finally:
            guard._bad_ip = orig
        self.assertEqual(hits, [])


@unittest.skipUnless(__import__("importlib").util.find_spec("curl_cffi"), "curl_cffi kurulu değil")
class BrowserTLSGuardTest(unittest.TestCase):
    def test_internal_blocked_and_pinned(self):
        from scakit.collectors.blackbox.browser_tls import BrowserTLSSession

        class Ok(Quiet):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
        s = _serve("127.0.0.1", Ok)
        p = s.server_port
        sess = BrowserTLSSession("chrome")
        for u in (f"http://127.0.0.1:{p}/", f"http://localhost:{p}/", f"http://0x7f000001:{p}/"):
            with guard.outbound_guard(), self.assertRaises(guard.BlockedAddress):
                sess.get(u)
        self.assertEqual(sess.get(f"http://127.0.0.1:{p}/").status_code, 200)
        with self.assertRaises(ValueError):
            sess.get("file:///etc/passwd")
        import socket
        orig_bad, orig_gai = guard._bad_ip, socket.getaddrinfo
        guard._bad_ip = lambda ip: False
        socket.getaddrinfo = lambda h, *a, **k: orig_gai("127.0.0.1" if h == "pin.invalid" else h, *a, **k)
        try:
            with guard.outbound_guard():
                self.assertEqual(sess.get(f"http://pin.invalid:{p}/").status_code, 200)
        finally:
            guard._bad_ip, socket.getaddrinfo = orig_bad, orig_gai

    def test_redirect_hop_blocked_before_request(self):
        from scakit.collectors.blackbox.browser_tls import BrowserTLSSession
        hits = []

        class Internal(Quiet):
            def do_GET(self):
                hits.append(self.path)
                self.send_response(200)
                self.end_headers()
        b = _serve("127.0.0.2", Internal)

        class Redirector(Quiet):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.2:{b.server_port}/secret")
                self.end_headers()
        a = _serve("127.0.0.1", Redirector)
        orig = guard._bad_ip
        guard._bad_ip = lambda ip: ip == "127.0.0.2"
        try:
            with guard.outbound_guard(), self.assertRaises(guard.BlockedAddress):
                BrowserTLSSession("chrome").get(f"http://127.0.0.1:{a.server_port}/")
        finally:
            guard._bad_ip = orig
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
