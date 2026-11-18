import functools
import http.server
import io
import threading
import unittest
import zipfile

from scakit.collectors.blackbox.apk import scan_apk
from scakit.collectors.blackbox.signatures import cdn_match, packages_from_paths
from scakit.collectors.blackbox.web import scan_web
from scakit.collectors.whitebox import scan_directory
from scakit.collectors.whitebox.container import scan_image
from scakit.inventory import Inventory

from .helpers import FIX, make_dex


def index(comps):
    return {(c.ecosystem, c.name, c.version): c for c in comps}


class WhiteboxTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        comps, cls.notes = scan_directory(FIX / "app", target="t")
        inv = Inventory()
        inv.add(comps)
        inv.finalize()
        cls.inv = inv
        cls.c = index(inv.components.values())
        cls.dev, _ = scan_directory(FIX / "app", include_dev=True)

    def has(self, eco, name, ver):
        self.assertIn((eco, name, ver), self.c, f"{eco} {name} {ver} yok")
        return self.c[(eco, name, ver)]

    def test_npm(self):
        lod = self.has("npm", "lodash", "4.17.20")
        self.assertTrue(lod.direct)
        self.assertEqual(self.has("npm", "qs", "6.7.0").parents, ["express"])
        self.has("npm", "axios", "0.21.0")
        self.has("npm", "@babel/core", "7.12.3")
        self.has("npm", "jsonwebtoken", "8.5.1")
        self.has("npm", "react-dom", "18.2.0")
        self.assertNotIn(("npm", "jest", "29.0.0"), self.c)
        self.assertIn(("npm", "jest", "29.0.0"), index(self.dev))
        self.assertFalse(any(k[1] == "local-lib" for k in self.c))

    def test_python(self):
        self.has("PyPI", "Django", "3.2.0")
        self.has("PyPI", "PyYAML", "5.3")
        self.has("PyPI", "Jinja2", "2.10")
        self.has("PyPI", "urllib3", "1.26.4")
        self.assertEqual(self.has("PyPI", "requests", None).confidence, "low")

    def test_jvm(self):
        log4j = self.has("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1")
        self.assertTrue(log4j.direct)
        self.assertEqual({e.method for e in log4j.evidence}, {"command-output", "jar-meta", "manifest"})
        self.assertEqual(self.has("Maven", "org.apache.logging.log4j:log4j-api", "2.14.1").parents,
                         ["org.apache.logging.log4j:log4j-core@2.14.1"])
        self.has("Maven", "com.squareup.okhttp3:okhttp", "4.9.0")
        self.has("Maven", "org.bouncycastle:bcprov-jdk15on", "1.68")
        self.assertEqual(self.has("Maven", "commons-text", "1.9").confidence, "medium")
        self.assertNotIn(("Maven", "junit:junit", "4.12"), self.c)

    def test_others(self):
        self.has("Go", "github.com/gin-gonic/gin", "1.7.0")
        self.assertFalse(self.has("Go", "golang.org/x/text", "0.3.6").direct)
        self.has("Packagist", "symfony/http-kernel", "5.4.0")
        self.has("NuGet", "Newtonsoft.Json", "12.0.3")
        self.has("crates.io", "smallvec", "1.6.0")
        self.assertNotIn(("crates.io", "app", "0.1.0"), self.c)
        self.has("RubyGems", "nokogiri", "1.13.10")
        self.has("Pub", "http", "0.13.3")
        self.assertNotIn(("Pub", "flutter", "0.0.0"), self.c)
        self.has("CocoaPods", "Firebase", "8.0.0")
        self.has("SwiftURL", "github.com/apple/swift-nio", "2.29.0")

    def test_rootfs(self):
        ssl = self.has("Debian:11", "openssl", "1.1.1n-0+deb11u3")
        self.assertIn("binary=libssl1.1", [e.detail for e in ssl.evidence])
        self.has("Debian:11", "zlib", "1:1.2.11.dfsg-2+deb11u1")
        self.assertFalse(any(k[1] == "removed-pkg" for k in self.c))


class ContainerTest(unittest.TestCase):
    def test_docker_and_oci(self):
        for f in ("image-docker.tar", "image-oci.tar"):
            comps, notes = scan_image(str(FIX / f))
            got = {(c.ecosystem, c.name, c.version) for c in comps}
            self.assertEqual(got, {("npm", "minimist", "1.2.0"), ("npm", "@scope/x", "1.0.0"),
                                   ("Alpine:v3.12", "openssl", "1.1.1g-r0"), ("Alpine:v3.12", "musl", "1.1.24-r9")}, f)


class BlackboxTest(unittest.TestCase):
    def test_cdn(self):
        self.assertEqual(cdn_match("https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.2/dist/umd/popper.min.js"),
                         ("@popperjs/core", "2.9.2"))
        self.assertEqual(cdn_match("https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.3.1/js/b.js"),
                         ("bootstrap", "4.3.1"))
        self.assertEqual(cdn_match("https://code.jquery.com/ui/1.12.1/jquery-ui.min.js"), ("jquery-ui", "1.12.1"))
        self.assertEqual(cdn_match("/static/vendor/jquery-1.12.4.min.js"), ("jquery", "1.12.4"))
        self.assertIsNone(cdn_match("https://example.com/app.js"))

    def test_requirement_text_is_not_version(self):
        from scakit.collectors.blackbox.signatures import scan_js
        self.assertEqual(scan_js('throw"Responsive requires DataTables 1.10.3 or newer";'), [])
        self.assertEqual(scan_js('alert("ColReorder requires DataTables 1.10.8 or greater")'), [])
        self.assertEqual([x[:2] for x in scan_js('/*! DataTables 1.10.19\n * ©2008-2018 SpryMedia */')],
                         [("datatables.net", "1.10.19")])
        self.assertEqual([x[:2] for x in scan_js('n.DataTable.version="1.10.21";')], [("datatables.net", "1.10.21")])

    def test_body_banners(self):
        from scakit.collectors.blackbox.fingerprints import detect_platforms, scan_body
        got = lambda t: [(e, n, v) for e, n, v, _ in scan_body(t)]
        self.assertEqual(got("<h3>Apache Tomcat/9.0.41</h3>"), [("generic", "apache-tomcat", "9.0.41")])
        self.assertEqual(got("<tr><th>Django Version:</th>\n<td>3.2.4</td></tr>"), [("PyPI", "django", "3.2.4")])
        self.assertEqual(got("<hr><center>nginx/1.18.0</center>"), [("generic", "nginx", "1.18.0")])
        self.assertEqual(got("Drupal 7.98, 2023-06-07\n---"), [("generic", "drupal", "7.98")])
        self.assertEqual(got('<meta name="ajs-version-number" content="7.13.0"> confluence'),
                         [("generic", "confluence", "7.13.0")])
        self.assertEqual(got('<app-root ng-version="15.2.9">'), [("npm", "@angular/core", "15.2.9")])
        self.assertEqual(detect_platforms("<link href='/sites/default/files/x.css'>", {}), {"drupal"})
        self.assertEqual(detect_platforms("", {"X-Pingback": "x"}), {"wordpress"})
        self.assertEqual(detect_platforms("", {"SPRequestGuid": "x"}), {"sharepoint"})
        self.assertEqual(got('var _spPageContextInfo={"siteClientTag":"0$$16.0.10417.20175"}'),
                         [("generic", "microsoft-sharepoint", "16.0.10417.20175")])

    def test_sourcemap_paths(self):
        p = packages_from_paths(["webpack:///./node_modules/.pnpm/@babel+runtime@7.10.0/node_modules/@babel/runtime/x.js",
                                 "../node_modules/lodash-es/merge.js"])
        self.assertEqual(p["@babel/runtime"], {"7.10.0"})
        self.assertEqual(p["lodash-es"], set())

    def test_web(self):
        class Quiet(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *a):
                pass

        handler = functools.partial(Quiet, directory=str(FIX / "website"))
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            comps, notes = scan_web(f"http://127.0.0.1:{srv.server_port}/", delay=0)
        finally:
            srv.shutdown()
        got = {(c.name, c.version, c.evidence[0].method) for c in comps if c.ecosystem == "npm"}
        for exp in [("jquery", "3.4.1", "cdn-url"), ("jquery", "3.3.1", "signature"), ("bootstrap", "4.3.1", "signature"),
                    ("axios", "0.21.1", "sourcemap"), ("react-dom", "16.13.1", "sourcemap"),
                    ("@angular/core", "12.0.0", "signature"), ("dompurify", "2.0.8", "signature"),
                    ("minimist", "1.2.0", "exposed-file"), ("dompurify", "2.3.1", "signature"),
                    ("react", "17.0.2", "signature"), ("zone.js", None, "license-manifest"),
                    ("@fullcalendar/core", None, "license-manifest")]:
            self.assertIn(exp, got)
        gen = {(c.name, c.version, c.evidence[0].method) for c in comps if c.ecosystem == "generic"}
        for exp in [("wordpress", "5.8.1", "cms-version"), ("wordpress-plugin:contact-form-7", "5.3.2", "cms-version")]:
            self.assertIn(exp, gen)
        kinds = {n[0] for n in notes}
        self.assertTrue({"missing-sri", "sourcemap-exposed", "exposed-file", "license-manifest"} <= kinds)
        lic = {c.name: c.licenses for c in comps if c.evidence[0].method == "license-manifest"}
        self.assertEqual(lic["pdfmake"], ["MIT"])
        self.assertNotIn("lodash", {n[1] for n in notes if n[0] == "missing-sri" and "lodash" in n[1]})

    def test_apk(self):
        b = io.BytesIO()
        with zipfile.ZipFile(b, "w") as z:
            z.writestr("AndroidManifest.xml", b"\x03\x00")
            z.writestr("classes.dex", make_dex(["Lokhttp3/OkHttpClient;", "okhttp/3.12.1",
                                                "Lretrofit2/Retrofit;", "La/b/c;"]))
            z.writestr("META-INF/androidx.core_core.version", "1.6.0\n")
            z.writestr("META-INF/kotlinx_coroutines_core.version", "1.5.2")
            z.writestr("firebase-messaging.properties", "version=22.0.0\nclient=firebase-messaging\n")
            z.writestr("lib/arm64-v8a/libcrypto.so", b"\x00OpenSSL 1.1.1k  25 Mar 2021\x00")
            z.writestr("assets/index.android.bundle", "var ReactNativeVersion={major:0,minor:63,patch:4};/*! DOMPurify 2.2.0 */")
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".apk") as f:
            f.write(b.getvalue())
            f.flush()
            comps, notes = scan_apk(f.name)
        got = {(c.ecosystem, c.name, c.version) for c in comps}
        for exp in [("Maven", "com.squareup.okhttp3:okhttp", "3.12.1"), ("Maven", "androidx.core:core", "1.6.0"),
                    ("Maven", "org.jetbrains.kotlinx:kotlinx-coroutines-core", "1.5.2"),
                    ("Maven", "com.google.firebase:firebase-messaging", "22.0.0"), ("generic", "openssl", "1.1.1k"),
                    ("npm", "react-native", "0.63.4"), ("npm", "dompurify", "2.2.0"),
                    ("Maven", "com.squareup.retrofit2:retrofit", None)]:
            self.assertIn(exp, got)
        self.assertNotIn(("Maven", "com.squareup.okhttp3:okhttp", None), got)


if __name__ == "__main__":
    unittest.main()


class ModernSignatureTest(unittest.TestCase):
    def test_js_signatures(self):
        from scakit.collectors.blackbox.signatures import scan_js
        cases = {
            'reconcilerVersion:"18.2.0-next-9e3b772b8-20220608"': ("react-dom", "18.2.0"),
            'version:"18.2.0",rendererPackageName:"react-dom"': ("react-dom", "18.2.0"),
            'reconcilerVersion:"19.0.0-rc-66855b96-20241106"': ("react-dom", "19.0.0-rc-66855b96-20241106"),
            "/** @license React v16.13.1\n * react-is.production.min.js": ("react-is", "16.13.1"),
            "/** @license React v17.0.2\n * react.production.min.js": ("react", "17.0.2"),
            "'/* Partytown 0.5.4 - MIT builder.io */\\n!function(t)": ("@builder.io/partytown", "0.5.4"),
            'window.next={version:"13.4.19",appDir:!0}': ("next", "13.4.19"),
            "//! moment-timezone.js\n//! version : 0.5.43": ("moment-timezone", "0.5.43"),
            "//! moment.js\n//! version : 2.29.4": ("moment", "2.29.4"),
            " * Leaflet 1.9.4, a JS library for interactive maps.": ("leaflet", "1.9.4"),
            "/*! tailwindcss v3.4.1 | MIT License | https://tailwindcss.com */": ("tailwindcss", "3.4.1"),
            "reconcilerVersion:`19.1.0`": ("react-dom", "19.1.0"),
            "window.next={version:`15.2.0`,appDir:!0}": ("next", "15.2.0"),
            "mc={version:`2.3.1`,ucs2:{decode:sc}}": ("punycode", "2.3.1"),
        }
        for text, want in cases.items():
            got = [(n, v) for n, v, _ in scan_js(text)]
            self.assertIn(want, got, text)
        self.assertNotIn("react", [n for n, _, _ in scan_js("/** @license React v16.13.1\n * react-is.production.min.js")])
        self.assertNotIn("moment", [n for n, _, _ in scan_js("//! moment-timezone.js\n//! version : 0.5.43")])

    def test_framework_generators(self):
        from scakit.collectors.blackbox.signatures import GENERATOR_RULES
        def det(g):
            return [(n, r.search(g).group(1)) for r, _e, n in GENERATOR_RULES if r.search(g)]
        self.assertEqual(det("Astro v6.3.7"), [("astro", "6.3.7")])
        self.assertEqual(det("Gatsby 5.13.3"), [("gatsby", "5.13.3")])
        self.assertEqual(det("Hugo 0.120.4"), [("hugo", "0.120.4")])


class ExternalAssetAndRateLimitTest(unittest.TestCase):
    def _serve(self, host, handler):
        srv = http.server.ThreadingHTTPServer((host, 0), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        return srv.server_address[1]

    def test_cdn_asset_on_other_host_is_analyzed(self):
        class Cdn(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                body = b"/*! jQuery v1.12.4 | (c) jQuery Foundation | jquery.org/license */"
                self.send_response(200)
                self.send_header("Content-Type", "application/javascript")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        cdn = self._serve("127.0.0.2", Cdn)

        class Site(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                body = f"<html><script src='http://127.0.0.2:{cdn}/sc/app.js'></script></html>".encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        site = self._serve("127.0.0.1", Site)
        url = f"http://127.0.0.1:{site}/"
        comps, _ = scan_web(url, max_pages=1, delay=0.01, probe=False, browser_tls="off")
        self.assertIn(("jquery", "1.12.4"), {(c.name, c.version) for c in comps})
        comps, _ = scan_web(url, max_pages=1, delay=0.01, probe=False, browser_tls="off", external_assets=False)
        self.assertNotIn("jquery", {c.name for c in comps})

    def test_trackers_skipped(self):
        from scakit.collectors.blackbox.web import TRACKERS
        for h in ("www.googletagmanager.com", "connect.facebook.net", "static.hotjar.com"):
            self.assertTrue(TRACKERS.search(h), h)
        for h in ("static.licdn.com", "cdn.example.com"):
            self.assertFalse(TRACKERS.search(h), h)

    def test_429_backoff_retry(self):
        hits = []

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                hits.append(self.path)
                if len(hits) == 1:
                    self.send_response(429)
                    self.send_header("Retry-After", "0")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                body = b"<html><script>/*! jQuery v1.12.4 | (c) jQuery Foundation */</script></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        port = self._serve("127.0.0.1", H)
        waf = []
        comps, _ = scan_web(f"http://127.0.0.1:{port}/", max_pages=1, delay=0.01, probe=False, on_waf=waf.append)
        self.assertEqual(len(hits), 2)
        self.assertEqual(waf, [])


class ChallengePageTest(unittest.TestCase):
    def test_200_challenge_detected_but_normal_pages_not(self):
        from scakit.collectors.blackbox.signatures import packages_from_paths
        from scakit.collectors.blackbox.web import detect_waf
        self.assertEqual(detect_waf(200, {}, b"<html><title>Security Verification | LinkedIn</title>"
                                              b"<script src='/x/RecaptchaChallengePageUi.js'></script>"), "captcha")
        self.assertIsNone(detect_waf(200, {}, b"<html><title>Login</title><script src='https://www.google.com/recaptcha/api.js'>"
                                              b"</script><script src='/cdn-cgi/challenge-platform/scripts/jsd/main.js'></script>"))
        self.assertEqual(set(packages_from_paths(["webpack://x/node_modules/object-inspect|./util.inspect",
                                                  "webpack://x/node_modules/qs/lib/index.js"])), {"qs"})


class AccessDiagnosisTest(unittest.TestCase):
    def test_classifiers(self):
        from scakit.collectors.blackbox.access import classify_error, classify_response, same_site
        self.assertEqual(classify_error(OSError("Failed to resolve: Name or service not known")), "dns")
        self.assertEqual(classify_error(OSError("Read timed out.")), "timeout")
        self.assertEqual(classify_error(OSError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed")), "tls_error")
        self.assertEqual(classify_error(OSError("tlsv13 alert certificate required")), "mtls")
        self.assertEqual(classify_error(OSError("Connection refused")), "refused")
        self.assertEqual(classify_response(401, {"WWW-Authenticate": "NTLM"}, b"", "https://a.com/", "a.com"), ("http_auth", "NTLM"))
        self.assertEqual(classify_response(200, {}, b"<html>", "https://login.microsoftonline.com/x", "a.com")[0], "login_required")
        self.assertEqual(classify_response(200, {}, b"<html>", "https://a.com/account/login?next=/", "a.com")[0], "login_required")
        self.assertEqual(classify_response(403, {}, b"This service is not available in your country", "https://a.com/", "a.com")[0], "geo_block")
        self.assertEqual(classify_response(403, {}, b"Error 1020 Access denied", "https://a.com/", "a.com")[0], "ip_block")
        self.assertEqual(classify_response(451, {}, b"", "https://a.com/", "a.com")[0], "geo_block")
        self.assertIsNone(classify_response(200, {}, b"<html>welcome, login button</html>", "https://a.com/", "a.com"))
        self.assertTrue(same_site("linkedin.com", "www.linkedin.com"))
        self.assertTrue(same_site("www.a.com", "a.com"))
        self.assertFalse(same_site("a.com", "evil-a.com"))

    def test_egress_auto_switch_on_geo_block(self):
        class Target(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if self.headers.get("X-Via-Test-Proxy") != "1":
                    body, st = b"<html>Sorry, this service is not available in your country.</html>", 403
                else:
                    body, st = b"<html><script>/*! jQuery v1.12.4 | (c) jQuery Foundation */</script></html>", 200
                self.send_response(st)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        tsrv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Target)
        threading.Thread(target=tsrv.serve_forever, daemon=True).start()
        self.addCleanup(tsrv.shutdown)

        class Proxy(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                import urllib.request
                req = urllib.request.Request(self.path, headers={"X-Via-Test-Proxy": "1"})
                try:
                    r = urllib.request.urlopen(req, timeout=5)
                    st, body = r.status, r.read()
                except urllib.error.HTTPError as e:
                    st, body = e.code, e.read()
                self.send_response(st)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        psrv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Proxy)
        threading.Thread(target=psrv.serve_forever, daemon=True).start()
        self.addCleanup(psrv.shutdown)
        url = f"http://127.0.0.1:{tsrv.server_address[1]}/"
        proxy = f"http://127.0.0.1:{psrv.server_address[1]}"
        acc = []
        comps, _ = scan_web(url, max_pages=1, delay=0.01, probe=False, browser_tls="off", on_access=acc.append,
                            egress={"mode": "auto", "proxies": [("TR", proxy)]})
        self.assertIn(("jquery", "1.12.4"), {(c.name, c.version) for c in comps})
        self.assertEqual(acc[0]["egress"], "TR")
        acc = []
        comps, _ = scan_web(url, max_pages=1, delay=0.01, probe=False, browser_tls="off", on_access=acc.append,
                            egress={"mode": "direct", "proxies": [("TR", proxy)]})
        self.assertEqual((acc[0]["issue"], acc[0]["severe"]), ("geo_block", True))


class InputFormatTest(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        from pathlib import Path
        self.d = Path(self.tmp.name)

    def test_sbom_xml_and_tag_value(self):
        from scakit.analysis import detect_type
        from scakit.collectors.sbom import scan_sbom
        x = self.d / "bom.xml"
        x.write_text('<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1"><components>'
                     '<component type="library"><name>lodash</name><version>4.17.20</version>'
                     '<purl>pkg:npm/lodash@4.17.20</purl><licenses><license><id>MIT</id></license></licenses></component>'
                     '</components></bom>')
        self.assertEqual(detect_type(str(x)), "sbom")
        comps, _ = scan_sbom(x)
        self.assertEqual([(c.name, c.version, c.licenses) for c in comps], [("lodash", "4.17.20", ["MIT"])])
        t = self.d / "app.spdx"
        t.write_text("SPDXVersion: SPDX-2.3\nDataLicense: CC0-1.0\n\nPackageName: requests\nSPDXID: SPDXRef-1\n"
                     "PackageVersion: 2.19.0\nExternalRef: PACKAGE-MANAGER purl pkg:pypi/requests@2.19.0\n")
        self.assertEqual(detect_type(str(t)), "sbom")
        comps, _ = scan_sbom(t)
        self.assertEqual([(c.ecosystem, c.name, c.version) for c in comps], [("PyPI", "requests", "2.19.0")])
        evil = self.d / "evil.xml"
        evil.write_text('<?xml version="1.0"?><!DOCTYPE bom [<!ENTITY a "aaaa">]>'
                        '<bom xmlns="http://cyclonedx.org/schema/bom/1.5"><components/></bom>')
        with self.assertRaises(ValueError):
            scan_sbom(evil)

    def test_unsupported_and_encrypted_archives(self):
        from scakit.analysis import detect_type
        from scakit.safeio import SafeZipFile, UnsafeInput
        z = self.d / "src.7z"
        z.write_bytes(b"7z\xbc\xaf\x27\x1c")
        with self.assertRaises(ValueError) as cm:
            detect_type(str(z))
        self.assertIn("7z", str(cm.exception))
        enc = self.d / "enc.zip"
        with zipfile.ZipFile(enc, "w") as zf:
            zf.writestr("package-lock.json", "{}")
        raw = bytearray(enc.read_bytes())
        for sig in (b"PK\x03\x04", b"PK\x01\x02"):
            i = raw.find(sig)
            off = i + (6 if sig == b"PK\x03\x04" else 8)
            raw[off] |= 0x1
        enc.write_bytes(bytes(raw))
        with SafeZipFile(enc) as zf, self.assertRaises(UnsafeInput) as cm:
            zf.open("package-lock.json").read()
        self.assertIn("parola", str(cm.exception))

    def test_packer_detected(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"\x03\x00")
            zf.writestr("lib/arm64-v8a/libjiagu_a64.so", b"\x7fELF")
            zf.writestr("classes.dex", make_dex(["Lcom/stub/StubApp;"]))
        p = self.d / "app.apk"
        p.write_bytes(buf.getvalue())
        _comps, notes = scan_apk(str(p))
        self.assertTrue(any(n[0] == "packed" and "Jiagu" in n[2] for n in notes), notes)


class VulnDbCorruptZipTest(unittest.TestCase):
    def test_corrupt_osv_zip_is_skipped(self):
        import json as _json
        import tempfile
        from pathlib import Path
        from scakit.vulndb.db import VulnDB, _zip_ok, update_from_dir
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            adv = {"id": "GHSA-test-0001", "modified": "2026-01-01T00:00:00Z", "aliases": ["CVE-2026-0001"],
                   "affected": [{"package": {"ecosystem": "npm", "name": "left-pad"},
                                 "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.3.0"}]}]}]}
            for name in ("osv_npm.zip", "osv_PyPI.zip"):
                with zipfile.ZipFile(d / name, "w", zipfile.ZIP_STORED) as zf:
                    zf.writestr("GHSA-test-0001.json", _json.dumps({**adv, "id": "GHSA-" + name[4:8]}))
            raw = bytearray((d / "osv_PyPI.zip").read_bytes())
            i = raw.find(b'"modified"')
            raw[i + 2] ^= 0xFF
            (d / "osv_PyPI.zip").write_bytes(bytes(raw))
            self.assertFalse(_zip_ok(d / "osv_PyPI.zip"))
            self.assertTrue(_zip_ok(d / "osv_npm.zip"))
            db = VulnDB(d / "vuln.db")
            logs = []
            update_from_dir(db, d, logs.append)
            self.assertFalse((d / "osv_PyPI.zip").exists())
            self.assertTrue(any("corrupted" in m for m in logs), logs)
            self.assertEqual(db.conn.execute("SELECT COUNT(*) FROM vulns").fetchone()[0], 1)
            db.close()


class VulnDbConcurrencyTest(unittest.TestCase):
    def test_reader_not_blocked_by_running_update(self):
        import tempfile
        from pathlib import Path
        from scakit.vulndb.db import VulnDB
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "v.sqlite"
            VulnDB(path).close()
            writer = VulnDB(path)
            writer.conn.execute("BEGIN IMMEDIATE")
            writer.conn.execute("INSERT INTO meta VALUES ('k', 'v')")
            t0 = __import__("time").monotonic()
            reader = VulnDB(path)
            self.assertEqual(reader.conn.execute("SELECT COUNT(*) FROM meta").fetchone()[0], 0)
            self.assertLess(__import__("time").monotonic() - t0, 2)
            writer.conn.commit()
            self.assertEqual(reader.conn.execute("SELECT COUNT(*) FROM meta").fetchone()[0], 1)
            reader.close()
            writer.close()


class LoginLinkNotBlockerTest(unittest.TestCase):
    def test_signin_link_during_crawl_is_not_an_issue(self):
        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                body = (b"<html><a href='/m/signin'>Sign in</a><script>/*! jQuery v1.12.4 | (c) jQuery Foundation */</script></html>"
                        if self.path == "/" else b"<html><form>login</form></html>")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        acc = []
        scan_web(f"http://127.0.0.1:{srv.server_address[1]}/", max_pages=3, delay=0.01, probe=False, browser_tls="off",
                 on_access=acc.append)
        self.assertEqual(acc, [])
