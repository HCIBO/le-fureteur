import io
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path

try:
    from fastapi.testclient import TestClient
except ImportError:
    TestClient = None

from .helpers import FIX, eco_range, osv, osv_zip

PW = "Guclu-Parola-123"


@unittest.skipIf(TestClient is None, "fastapi kurulu değil")
class _Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["SCAKIT_DATA_DIR"] = self.tmp.name
        os.environ.pop("SCAKIT_DATABASE_URL", None)
        os.environ["SCAKIT_JOB_ISOLATION"] = "0"
        from scakit.server import config, db, security
        config.get_config.cache_clear()
        db.reset_for_tests()
        security._attempts.clear()
        from scakit.server import guard
        self._resolve = guard.resolve
        guard.resolve = lambda host: {"app.acme.com": ["93.184.215.14"], "intranet.acme.com": ["10.0.0.5"]}.get(
            host, ["203.0.113.10"])
        from scakit.server.app import create_app
        from scakit.server.db import SessionLocal
        from scakit.server.models import User
        from scakit.server.security import hash_password
        self.app = create_app()
        s = SessionLocal()
        s.add(User(email="admin@x.io", password_hash=hash_password(PW), role="admin"))
        s.commit()
        s.close()
        from scakit.vulndb.db import VulnDB
        self.dbpath = Path(self.tmp.name) / "vuln.sqlite"
        v = VulnDB(self.dbpath)
        v.import_osv_zip(osv_zip([osv("GHSA-lod", "npm", "lodash", eco_range(("introduced", "0"), ("fixed", "4.17.21")),
                                      severity="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")]), "t")
        v.close()

    def tearDown(self):
        from scakit.server import guard
        guard.resolve = self._resolve
        from scakit.server import db
        db.reset_for_tests()
        self.tmp.cleanup()

    def client(self, email=None, password=PW):
        c = TestClient(self.app)
        c.get("/api/health")
        c.headers["X-CSRF-Token"] = c.cookies.get("scakit_csrf")
        if email:
            r = c.post("/api/auth/login", json={"email": email, "password": password})
            self.assertEqual(r.status_code, 200, r.text)
            c.headers["X-CSRF-Token"] = c.cookies.get("scakit_csrf")
        return c

    def run_worker(self):
        from scakit.server.worker import run_once
        while run_once():
            pass


@unittest.skipIf(TestClient is None, "fastapi kurulu değil")
class ServerTest(_Base):
    def test_auth_csrf_throttle(self):
        c = TestClient(self.app)
        self.assertEqual(c.post("/api/auth/login", json={"email": "admin@x.io", "password": PW}).status_code, 403)
        c = self.client()
        for _ in range(10):
            self.assertEqual(c.post("/api/auth/login", json={"email": "admin@x.io", "password": "yanlis"}).status_code,
                             401)
        self.assertEqual(c.post("/api/auth/login", json={"email": "admin@x.io", "password": PW}).status_code, 429)
        self.assertEqual(TestClient(self.app).get("/api/auth/me").status_code, 401)
        r = self.client().get("/api/health")
        self.assertIn("frame-ancestors 'none'", r.headers["content-security-policy"])

    def test_rbac_and_isolation(self):
        a = self.client("admin@x.io")
        acme = a.post("/api/orgs", json={"name": "Acme", "allowed_domains": ["*.acme.com"]}).json()
        other = a.post("/api/orgs", json={"name": "Other"}).json()
        r = a.post("/api/users", json={"email": "cust@acme.com", "password": PW, "role": "customer",
                                       "organization_id": acme["id"]})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(a.post("/api/users", json={"email": "x@y.z", "password": "kisa", "role": "analyst"}).status_code,
                         400)
        p_other = a.post("/api/projects", json={"organization_id": other["id"], "name": "Gizli"}).json()

        c = self.client("cust@acme.com")
        self.assertEqual(c.get("/api/users").status_code, 403)
        self.assertEqual(c.get("/api/settings").status_code, 403)
        self.assertEqual([o["name"] for o in c.get("/api/orgs").json()], ["Acme"])
        self.assertEqual(c.get(f"/api/projects/{p_other['id']}").status_code, 404)
        p = c.post("/api/projects", json={"organization_id": other["id"], "name": "Portal"}).json()
        self.assertEqual(p["organization_id"], acme["id"])
        self.assertEqual([x["name"] for x in c.get("/api/projects").json()], ["Portal"])
        bad = c.post(f"/api/projects/{p['id']}/targets", json={"name": "x", "kind": "web", "url": "https://evil.com"})
        self.assertEqual(bad.status_code, 400)
        self.assertIn("izinli", bad.json()["detail"])
        internal = c.post(f"/api/projects/{p['id']}/targets",
                          json={"name": "x", "kind": "web", "url": "https://intranet.acme.com"})
        self.assertEqual(internal.status_code, 400)
        self.assertIn("İç ağ", internal.json()["detail"])
        ok = c.post(f"/api/projects/{p['id']}/targets", json={"name": "App", "kind": "web", "url": "https://app.acme.com/"})
        self.assertEqual(ok.status_code, 200, ok.text)
        self.assertEqual(c.post(f"/api/projects/{p['id']}/targets",
                                json={"name": "x", "kind": "web", "url": "file:///etc/passwd"}).status_code, 400)
        a.put("/api/settings", json={"allow_internal_targets": "1"})
        self.assertEqual(a.post(f"/api/projects/{p['id']}/targets",
                                json={"name": "i", "kind": "web", "url": "http://10.0.0.5/"}).status_code, 200)

    def test_settings_secret_not_returned(self):
        a = self.client("admin@x.io")
        a.put("/api/settings", json={"nvd_api_key": "gizli-anahtar-123"})
        view = {s["key"]: s for s in a.get("/api/settings").json()}
        self.assertEqual(view["nvd_api_key"]["value"], "")
        self.assertTrue(view["nvd_api_key"]["is_set"])
        from scakit.server.db import SessionLocal
        from scakit.server.models import Setting
        raw = SessionLocal().get(Setting, "nvd_api_key").value
        self.assertNotIn("gizli-anahtar", raw)
        self.assertEqual(a.put("/api/settings", json={"bilinmeyen": "x"}).status_code, 400)

    def test_scan_lifecycle(self):
        a = self.client("admin@x.io")
        a.put("/api/settings", json={"vulndb_path": str(self.dbpath)})
        org = a.post("/api/orgs", json={"name": "Acme"}).json()
        p = a.post("/api/projects", json={"organization_id": org["id"], "name": "Web",
                                          "license_policy": {"denied": ["AGPL-3.0-only"]}}).json()
        t = a.post(f"/api/projects/{p['id']}/targets", json={"name": "web-ui", "kind": "upload"}).json()
        self.assertEqual(a.post(f"/api/targets/{t['id']}/scans").status_code, 400)

        def upload(lodash_version):
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as z:
                lock = json.loads((FIX / "app" / "web" / "package-lock.json").read_text())
                lock["packages"]["node_modules/lodash"]["version"] = lodash_version
                z.writestr("web/package-lock.json", json.dumps(lock))
                z.writestr("web/package.json", (FIX / "app" / "web" / "package.json").read_text())
            for f in a.get(f"/api/projects/{p['id']}/targets").json()[0]["files"]:
                a.delete(f"/api/targets/{t['id']}/files/{f['stored']}")
            r = a.post(f"/api/targets/{t['id']}/files", files={"file": ("../../kaynak kod.zip", buf.getvalue())})
            self.assertEqual(r.status_code, 200, r.text)
            self.assertEqual(r.json()["files"][0]["name"], "kaynak_kod.zip")

        upload("4.17.20")
        s1 = a.post(f"/api/targets/{t['id']}/scans").json()
        self.assertEqual(a.post(f"/api/targets/{t['id']}/scans").status_code, 409)
        self.run_worker()
        s1 = a.get(f"/api/scans/{s1['id']}").json()
        self.assertEqual(s1["job"]["status"], "done", s1["job"]["log"][-2000:])
        self.assertEqual(s1["summary"]["new"], 1)
        fl = a.get("/api/findings", params={"project_id": p["id"]}).json()
        self.assertEqual([(f["vuln_id"], f["component"], f["status"]) for f in fl["items"]],
                         [("GHSA-lod", "lodash", "open")])
        fid = fl["items"][0]["id"]
        detail = a.get(f"/api/findings/{fid}").json()
        self.assertTrue(any("package-lock.json" in e["location"] for e in detail["evidence"]))
        names = {r["name"] for r in a.get(f"/api/scans/{s1['id']}/reports").json()}
        self.assertTrue({"rapor_tr.html", "sbom.cdx.json", "bulgular_tr.csv"} <= names)
        rep = a.get(f"/api/scans/{s1['id']}/reports/rapor_tr.html")
        self.assertEqual(rep.headers["content-security-policy"], "sandbox")
        self.assertEqual(a.get(f"/api/scans/{s1['id']}/reports/..%2F..%2Fsecret.key").status_code, 404)

        self.assertEqual(a.patch(f"/api/findings/{fid}", json={"status": "accepted_risk"}).status_code, 400)
        self.assertEqual(a.patch(f"/api/findings/{fid}", json={"status": "accepted_risk",
                                                                "reason": "WAF ile azaltıldı"}).status_code, 200)
        s2 = a.post(f"/api/targets/{t['id']}/scans").json()
        self.run_worker()
        f = a.get(f"/api/findings/{fid}").json()
        self.assertEqual((f["status"], f["last_seen_scan"]), ("accepted_risk", s2["id"]))
        html = a.get(f"/api/scans/{s2['id']}/reports/rapor_tr.html").text
        self.assertIn("WAF ile azaltıldı", html)

        a.patch(f"/api/findings/{fid}", json={"status": "open"})
        upload("4.17.21")
        a.post(f"/api/targets/{t['id']}/scans")
        self.run_worker()
        f = a.get(f"/api/findings/{fid}").json()
        self.assertEqual(f["status"], "fixed")
        dash = a.get("/api/dashboard").json()
        self.assertEqual(dash["open_by_severity"]["CRITICAL"], 0)
        self.assertTrue(any(x["action"] == "finding.status" for x in a.get("/api/audit").json()["items"]))

    def test_customer_cannot_touch_other_org_findings(self):
        a = self.client("admin@x.io")
        o1 = a.post("/api/orgs", json={"name": "A"}).json()
        o2 = a.post("/api/orgs", json={"name": "B"}).json()
        a.post("/api/users", json={"email": "c@a.com", "password": PW, "role": "customer", "organization_id": o1["id"]})
        p2 = a.post("/api/projects", json={"organization_id": o2["id"], "name": "B-proj"}).json()
        from scakit.server.db import SessionLocal
        from scakit.server.models import Finding, Target
        s = SessionLocal()
        t = Target(project_id=p2["id"], name="t", kind="upload", files=[])
        s.add(t)
        s.flush()
        f = Finding(target_id=t.id, project_id=p2["id"], component_key="npm|x|1", vuln_id="GHSA-1")
        s.add(f)
        s.commit()
        fid = f.id
        s.close()
        c = self.client("c@a.com")
        self.assertEqual(c.get(f"/api/findings/{fid}").status_code, 404)
        self.assertEqual(c.patch(f"/api/findings/{fid}", json={"status": "open"}).status_code, 404)
        self.assertEqual(c.get("/api/findings").json()["total"], 0)


if __name__ == "__main__":
    unittest.main()


@unittest.skipIf(TestClient is None, "fastapi kurulu değil")
class Phase2Test(_Base):

    def _scan_setup(self, a, lodash="4.17.20"):
        a.put("/api/settings", json={"vulndb_path": str(self.dbpath), "public_url": "https://scakit.test"})
        org = a.post("/api/orgs", json={"name": "Acme"}).json()
        p = a.post("/api/projects", json={"organization_id": org["id"], "name": "Web"}).json()
        t = a.post(f"/api/projects/{p['id']}/targets", json={"name": "web-ui", "kind": "upload"}).json()
        self._upload(a, t["id"], lodash)
        return org, p, t

    def _upload(self, a, tid, lodash):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            lock = json.loads((FIX / "app" / "web" / "package-lock.json").read_text())
            lock["packages"]["node_modules/lodash"]["version"] = lodash
            z.writestr("web/package-lock.json", json.dumps(lock))
            z.writestr("web/package.json", (FIX / "app" / "web" / "package.json").read_text())
        for f in a.get(f"/api/targets/{tid}").json()["files"]:
            a.delete(f"/api/targets/{tid}/files/{f['stored']}")
        self.assertEqual(a.post(f"/api/targets/{tid}/files", files={"file": ("src.zip", buf.getvalue())}).status_code, 200)

    def test_schedules(self):
        a = self.client("admin@x.io")
        _org, _p, t = self._scan_setup(a)
        self.assertEqual(a.post("/api/schedules", json={"target_id": t["id"], "cron": "*/5 * * * *"}).status_code, 400)
        self.assertEqual(a.post("/api/schedules", json={"target_id": t["id"], "cron": "bozuk"}).status_code, 400)
        prev = a.get("/api/schedules/preview", params={"cron": "0 2 * * *"}).json()
        self.assertEqual(len(prev["next"]), 5)
        self.assertIn("T02:00:00", prev["next"][0])
        s = a.post("/api/schedules", json={"target_id": t["id"], "cron": "0 2 * * *"}).json()
        self.assertTrue(s["next_run_at"])
        from datetime import datetime, timedelta, timezone
        from scakit.server.db import SessionLocal
        from scakit.server.models import Schedule
        db = SessionLocal()
        db.get(Schedule, s["id"]).next_run_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        db.commit()
        db.close()
        self.run_worker()
        scans = a.get("/api/scans", params={"target_id": t["id"]}).json()
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0]["job"]["status"], "done")
        s2 = a.get("/api/schedules", params={"target_id": t["id"]}).json()[0]
        self.assertTrue(s2["last_run_at"] and s2["next_run_at"] > s2["last_run_at"])
        self.run_worker()
        self.assertEqual(len(a.get("/api/scans", params={"target_id": t["id"]}).json()), 1)
        a.post("/api/users", json={"email": "an@x.io", "password": PW, "role": "analyst"})
        an = self.client("an@x.io")
        self.assertEqual(an.post("/api/schedules", json={"kind": "db_update", "cron": "0 3 * * *"}).status_code, 403)
        self.assertEqual(a.post("/api/schedules", json={"kind": "db_update", "cron": "0 3 * * *"}).status_code, 200)

    def test_notifications_and_jira(self):
        from scakit.server import jira, notify
        sent, jira_calls = [], []
        orig_post, orig_req = notify._http_post, jira._request
        notify._http_post = lambda url, body, headers: sent.append((url, json.loads(body), headers))

        class R:
            def __init__(self, code, data):
                self.status_code, self._d = code, data
                self.content = json.dumps(data).encode()
                self.text = self.content.decode()

            def json(self):
                return self._d

        def fake_jira(method, url, cfg, json_body=None):
            jira_calls.append((method, url, json_body, cfg["auth"]))
            if url.endswith("/myself"):
                return R(200, {"displayName": "Test"})
            if url.endswith("/issue"):
                return R(201, {"key": f"SEC-{len(jira_calls)}"})
            return R(201, {})
        jira._request = fake_jira
        try:
            a = self.client("admin@x.io")
            org, p, t = self._scan_setup(a)
            self.assertEqual(a.post("/api/notifications", json={"name": "x", "kind": "slack",
                                                                "config": {"url": "javascript:x"}}).status_code, 400)
            ch = a.post("/api/notifications", json={"name": "Slack", "kind": "slack",
                                                    "config": {"url": "https://hooks.slack.com/services/T/B/gizli"}}).json()
            self.assertEqual(ch["config"]["url"], "https://hooks.slack.com/…")
            a.post("/api/notifications", json={"name": "Hook", "kind": "webhook", "events": ["kev", "new_findings"],
                                               "min_severity": "CRITICAL",
                                               "config": {"url": "https://hook.test/x", "secret": "s3"}})
            other = a.post("/api/orgs", json={"name": "Baska"}).json()
            a.post("/api/notifications", json={"name": "Teams-baska", "kind": "teams", "organization_id": other["id"],
                                               "config": {"url": "https://teams.test/x"}})
            self.assertEqual(a.post(f"/api/notifications/{ch['id']}/test").status_code, 200)
            self.assertEqual(sent[-1][1]["text"], "Le Fureteur test notification")
            sent.clear()
            a.put("/api/settings", json={"jira_url": "https://jira.test", "jira_user": "u@x.io", "jira_token": "tok",
                                         "jira_project_key": "SEC", "jira_auto_min_severity": "CRITICAL"})
            self.assertEqual(a.post("/api/jira/test").json()["user"], "Test")
            a.post(f"/api/targets/{t['id']}/scans")
            self.run_worker()
            urls = [u for u, _b, _h in sent]
            self.assertIn("https://hooks.slack.com/services/T/B/gizli", urls)
            self.assertNotIn("https://teams.test/x", urls)
            hook = [(b, h) for u, b, h in sent if u == "https://hook.test/x"]
            self.assertEqual(hook[0][0]["event"], "new_findings")
            self.assertTrue(hook[0][1]["X-Scakit-Signature"].startswith("sha256="))
            slack = next(b for u, b, _h in sent if "slack" in u)
            self.assertIn("https://scakit.test/scans/", json.dumps(slack))
            f = a.get("/api/findings").json()["items"][0]
            self.assertTrue(f["jira_key"].startswith("SEC-"))
            issue = next(b for m, u, b, _a in jira_calls if u.endswith("/issue"))
            self.assertIn("lodash", issue["fields"]["summary"])
            self.assertIn("severity-critical", issue["fields"]["labels"])
            n = len(jira_calls)
            r = a.post(f"/api/findings/{f['id']}/jira").json()
            self.assertEqual((r["created"], len(jira_calls)), (False, n))
            self._upload(a, t["id"], "4.17.21")
            s2 = a.post(f"/api/targets/{t['id']}/scans").json()
            self.run_worker()
            ch2 = a.get(f"/api/scans/{s2['id']}/changes").json()
            self.assertEqual([x["vuln_id"] for x in ch2["fixed"]], ["GHSA-lod"])
            self.assertTrue(any(u.endswith(f"/issue/{f['jira_key']}/comment") for _m, u, _b, _a in jira_calls))
            a.post("/api/users", json={"email": "c@acme.com", "password": PW, "role": "customer",
                                       "organization_id": org["id"]})
            c = self.client("c@acme.com")
            for path in ("/api/notifications", "/api/system", "/api/system/selfscan"):
                self.assertEqual(c.get(path).status_code, 403, path)
            self.assertEqual(c.post("/api/jira/test").status_code, 403)
        finally:
            notify._http_post, jira._request = orig_post, orig_req

    def test_system_page(self):
        a = self.client("admin@x.io")
        a.put("/api/settings", json={"vulndb_path": str(self.dbpath)})
        info = a.get("/api/system").json()
        self.assertTrue(any(p["name"].lower() == "fastapi" and p["direct"] for p in info["python_packages"]))
        titles = [c["title"] for c in info["checks"]]
        self.assertIn("Çalışan worker yok", titles)
        self.assertIn("Oturum çerezi Secure değil", titles)
        self.assertEqual(self.client().get("/deps.json").status_code, 404)
        job = a.post("/api/system/selfscan").json()
        self.run_worker()
        res = a.get("/api/system/selfscan").json()
        self.assertGreater(res["components"]["python"], 5)
        info = a.get("/api/system").json()
        self.assertTrue(info["workers"] and info["workers"][0]["alive"])
        self.assertNotIn("Çalışan worker yok", [c["title"] for c in info["checks"]])
        self.assertEqual(info["selfscan_job"]["id"], job["id"])


@unittest.skipIf(TestClient is None, "fastapi kurulu değil")
class I18nApiTest(_Base):
    def test_openapi_requires_login_and_user_lang(self):
        self.assertEqual(self.client().get("/api/openapi.json").status_code, 401)
        a = self.client("admin@x.io")
        spec = a.get("/api/openapi.json").json()
        self.assertIn("/api/findings", spec["paths"])
        self.assertEqual(a.patch("/api/auth/me", json={"lang": "xx"}).status_code, 400)
        self.assertEqual(a.patch("/api/auth/me", json={"lang": "de"}).json()["lang"], "de")
        self.assertEqual(a.get("/api/auth/me").json()["lang"], "de")

    def test_project_report_lang_four(self):
        a = self.client("admin@x.io")
        org = a.post("/api/orgs", json={"name": "O"}).json()
        p = a.post("/api/projects", json={"organization_id": org["id"], "name": "P", "report_lang": "fr"}).json()
        self.assertEqual(p["report_lang"], "fr")


@unittest.skipIf(TestClient is None, "fastapi kurulu değil")
class TokenTest(_Base):
    def _setup(self):
        a = self.client("admin@x.io")
        acme = a.post("/api/orgs", json={"name": "Acme", "allowed_domains": ["*.acme.com"]}).json()
        other = a.post("/api/orgs", json={"name": "Other"}).json()
        p1 = a.post("/api/projects", json={"organization_id": acme["id"], "name": "P1"}).json()
        p2 = a.post("/api/projects", json={"organization_id": acme["id"], "name": "P2"}).json()
        p3 = a.post("/api/projects", json={"organization_id": other["id"], "name": "P3"}).json()
        a.post("/api/users", json={"email": "c@acme.com", "password": PW, "role": "customer",
                                   "organization_id": acme["id"]})
        return a, acme, p1, p2, p3

    def bearer(self, token):
        from fastapi.testclient import TestClient as TC
        c = TC(self.app)
        c.headers["Authorization"] = f"Bearer {token}"
        return c

    def test_token_scope_and_project_limits(self):
        a, acme, p1, p2, p3 = self._setup()
        c = self.client("c@acme.com")
        self.assertEqual(c.post("/api/tokens", json={"name": "x"}).status_code, 400)
        self.assertEqual(c.post("/api/tokens", json={"name": "x", "project_id": p3["id"]}).status_code, 404)
        r = c.post("/api/tokens", json={"name": "ci", "project_id": p1["id"], "scopes": ["read", "scan"]}).json()
        tok = r["token"]
        self.assertTrue(tok.startswith("lf_") and r["prefix"] == tok[:10])
        self.assertNotIn("token", c.get("/api/tokens").json()[0])
        b = self.bearer(tok)
        self.assertEqual([p["name"] for p in b.get("/api/projects").json()], ["P1"])
        self.assertEqual(b.get(f"/api/projects/{p2['id']}").status_code, 404)
        t = b.post(f"/api/projects/{p1['id']}/targets", json={"name": "src", "kind": "upload"})
        self.assertEqual(t.status_code, 200, t.text)
        self.assertEqual(b.post(f"/api/projects/{p2['id']}/targets", json={"name": "x", "kind": "upload"}).status_code, 404)
        for m, path in [("get", "/api/tokens"), ("get", "/api/orgs"), ("get", "/api/dashboard"),
                        ("post", "/api/tokens"), ("patch", f"/api/projects/{p1['id']}"), ("get", "/api/settings")]:
            self.assertEqual(getattr(b, m)(path, **({"json": {}} if m != "get" else {})).status_code, 403, path)
        ro = c.post("/api/tokens", json={"name": "ro", "project_id": p1["id"], "scopes": ["read"]}).json()["token"]
        self.assertEqual(self.bearer(ro).post(f"/api/targets/{t.json()['id']}/scans").status_code, 403)
        tid = c.get("/api/tokens").json()[-1]["id"]
        c.delete(f"/api/tokens/{tid}")
        self.assertEqual(b.get("/api/projects").status_code, 401)
        self.assertEqual(self.bearer("lf_sahte").get("/api/projects").status_code, 401)
        self.assertEqual(len(a.get("/api/tokens").json()), 2)
        at = a.post("/api/tokens", json={"name": "adm"}).json()
        self.assertEqual(c.delete(f"/api/tokens/{at['id']}").status_code, 404)
        cid = [u for u in a.get("/api/users").json() if u["email"] == "c@acme.com"][0]["id"]
        a.patch(f"/api/users/{cid}", json={"active": False})
        self.assertEqual(self.bearer(ro).get("/api/projects").status_code, 401)


@unittest.skipIf(TestClient is None, "fastapi kurulu değil")
class CiTest(_Base):
    def _zip(self, lodash="4.17.20", license=None):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            lock = json.loads((FIX / "app" / "web" / "package-lock.json").read_text())
            lock["packages"]["node_modules/lodash"]["version"] = lodash
            if license:
                lock["packages"]["node_modules/lodash"]["license"] = license
            z.writestr("web/package-lock.json", json.dumps(lock))
            z.writestr("web/package.json", (FIX / "app" / "web" / "package.json").read_text())
        return buf.getvalue()

    def test_ci_flow_gate_sarif(self):
        a = self.client("admin@x.io")
        a.put("/api/settings", json={"vulndb_path": str(self.dbpath), "public_url": "https://lf.test"})
        org = a.post("/api/orgs", json={"name": "Acme"}).json()
        p = a.post("/api/projects", json={"organization_id": org["id"], "name": "Web"}).json()
        self.assertEqual(p["ci_policy"]["fail_on"], "HIGH")
        tok = a.post("/api/tokens", json={"name": "gh", "project_id": p["id"], "scopes": ["scan"]}).json()["token"]
        from fastapi.testclient import TestClient as TC
        b = TC(self.app)
        b.headers["Authorization"] = f"Bearer {tok}"
        self.assertIn("def main", b.get("/api/ci/client.py").text)
        self.assertEqual(b.post("/api/ci/scan", data={"project_id": p["id"], "fail_on": "YANLIS"},
                                files={"file": ("r.zip", self._zip())}).status_code, 400)
        r = b.post("/api/ci/scan", data={"project_id": p["id"], "target": "repo", "ref": "main@abc"},
                   files={"file": ("r.zip", self._zip())})
        self.assertEqual(r.status_code, 200, r.text)
        sid = r.json()["scan_id"]
        self.assertEqual(r.json()["ui_url"], f"https://lf.test/scans/{sid}")
        self.assertEqual(b.get(f"/api/ci/scans/{sid}").json()["status"], "queued")
        self.run_worker()
        st = b.get(f"/api/ci/scans/{sid}").json()
        self.assertEqual(st["status"], "done")
        self.assertFalse(st["gate"]["passed"])
        self.assertEqual(st["gate"]["reasons"][0]["rule"], "severity")
        sar = json.loads(b.get(f"/api/scans/{sid}/sarif").text)
        self.assertEqual(sar["version"], "2.1.0")
        res = sar["runs"][0]["results"][0]
        self.assertEqual((res["ruleId"], res["level"]), ("GHSA-lod", "error"))
        self.assertTrue(res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].endswith("package-lock.json"))
        self.assertEqual(sar["runs"][0]["tool"]["driver"]["name"], "Le Fureteur")
        a.patch(f"/api/projects/{p['id']}", json={"ci_policy": {"fail_on": "NONE"}})
        self.assertTrue(b.get(f"/api/ci/scans/{sid}").json()["gate"]["passed"])
        a.patch(f"/api/projects/{p['id']}", json={"ci_policy": {"fail_on": "CRITICAL"}})
        r2 = b.post("/api/ci/scan", data={"project_id": p["id"], "target": "repo", "new_only": "true"},
                    files={"file": ("r2.zip", self._zip())}).json()
        self.run_worker()
        st2 = b.get(f"/api/ci/scans/{r2['scan_id']}").json()
        self.assertTrue(st2["gate"]["passed"], st2["gate"])
        tg = a.get(f"/api/targets/{r2['target_id']}").json()
        self.assertEqual(len(tg["files"]), 1)
        a.patch(f"/api/projects/{p['id']}", json={"license_policy": {"denied": ["AGPL-3.0-only"]},
                                                  "ci_policy": {"fail_on": "NONE", "fail_on_license": True}})
        r3 = b.post("/api/ci/scan", data={"project_id": p["id"], "target": "repo"},
                    files={"file": ("r3.zip", self._zip("4.17.21", "AGPL-3.0-only"))}).json()
        self.run_worker()
        g3 = b.get(f"/api/ci/scans/{r3['scan_id']}").json()["gate"]
        self.assertEqual([x["rule"] for x in g3["reasons"]], ["license"])
        self.assertEqual(g3["reasons"][0]["items"][0]["component"], "lodash")
        self.assertEqual(b.get("/api/findings").status_code, 403)
        p2 = a.post("/api/projects", json={"organization_id": org["id"], "name": "Diger"}).json()
        self.assertEqual(b.post("/api/ci/scan", data={"project_id": p2["id"]},
                                files={"file": ("r.zip", self._zip())}).status_code, 404)


@unittest.skipIf(TestClient is None, "fastapi kurulu değil")
class WebAuthTest(_Base):
    def _site(self):
        import http.server
        import threading
        hits = {"logout": 0, "app_ok": 0}

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body=b"", headers=()):
                self.send_response(code)
                for k, v in headers:
                    self.send_header(k, v)
                self.send_header("Content-Type", "text/html" if not self.path.endswith(".js") else "application/javascript")
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                logged = "sid=ok" in (self.headers.get("Cookie") or "")
                if self.path == "/login":
                    self._send(200, b'<form method=post><input type="hidden" name="csrf" value="tok123">'
                                    b'<input name=user><input name=pass type=password></form>')
                elif self.path == "/app":
                    if not logged:
                        return self._send(302, headers=[("Location", "/login")])
                    hits["app_ok"] += 1
                    self._send(200, b'<html><script src="/static/jquery-3.4.1.min.js"></script>'
                                    b'<a href="/logout">Logout</a><a href="/other">x</a></html>')
                elif self.path == "/logout":
                    hits["logout"] += 1
                    self._send(200, b"bye")
                elif self.path.startswith("/static/jquery"):
                    self._send(200, b"/*! jQuery v3.4.1 | (c) JS Foundation and other contributors */ var x=1;")
                elif self.path == "/basic":
                    import base64
                    if self.headers.get("Authorization") == "Basic " + base64.b64encode(b"bob:pw").decode():
                        return self._send(200, b'<script src="/static/jquery-3.4.1.min.js"></script>')
                    self._send(401)
                else:
                    self._send(200, b"<html>other</html>")

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n).decode()
                if self.path == "/login" and "user=alice" in body and "pass=s3cret" in body and "csrf=tok123" in body:
                    return self._send(302, headers=[("Set-Cookie", "sid=ok; Path=/"), ("Location", "/app")])
                self._send(200, b"Hatali giris")
        srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return f"http://127.0.0.1:{srv.server_port}", hits

    def test_form_login_and_validation(self):
        base, hits = self._site()
        a = self.client("admin@x.io")
        a.put("/api/settings", json={"allow_internal_targets": "1", "vulndb_path": str(self.dbpath)})
        org = a.post("/api/orgs", json={"name": "Acme"}).json()
        p = a.post("/api/projects", json={"organization_id": org["id"], "name": "W"}).json()
        t = a.post(f"/api/projects/{p['id']}/targets", json={"name": "app", "kind": "web", "url": base + "/app",
                                                              "options": {"delay": 0.2, "probe": False}}).json()
        bad = [{"type": "header", "name": "X-Key", "value": "a\r\nInjected: 1"},
               {"type": "header", "name": "Host", "value": "x"},
               {"type": "form", "login_url": "http://other.example/login", "username_field": "user",
                "password_field": "pass", "username": "u", "password": "p"},
               {"type": "form", "login_url": base + "/login", "username_field": "us er", "password_field": "pass",
                "username": "u", "password": "p"},
               {"type": "kerberos"}]
        for b in bad:
            self.assertEqual(a.patch(f"/api/targets/{t['id']}", json={"auth": b}).status_code, 400, b)
        form = {"type": "form", "login_url": base + "/login", "username_field": "user", "password_field": "pass",
                "csrf_field": "csrf", "username": "alice", "password": "s3cret", "failure_text": "Hatali"}
        r = a.patch(f"/api/targets/{t['id']}", json={"auth": form}).json()
        self.assertEqual(r["auth"]["password"], True)
        self.assertNotIn("s3cret", json.dumps(r))
        a.patch(f"/api/targets/{t['id']}", json={"auth": {**form, "password": ""}})
        s = a.post(f"/api/targets/{t['id']}/scans").json()
        self.run_worker()
        sc = a.get(f"/api/scans/{s['id']}").json()
        self.assertEqual(sc["job"]["status"], "done", sc["job"]["log"][-1500:])
        self.assertNotIn("s3cret", sc["job"]["log"])
        comps = a.get(f"/api/scans/{s['id']}/components").json()
        self.assertIn(("jquery", "3.4.1"), {(c["name"].lower(), c["version"]) for c in comps})
        self.assertGreaterEqual(hits["app_ok"], 1)
        self.assertEqual(hits["logout"], 0)
        a.patch(f"/api/targets/{t['id']}", json={"auth": {**form, "password": "yanlis"}})
        s2 = a.post(f"/api/targets/{t['id']}/scans").json()
        self.run_worker()
        j2 = a.get(f"/api/scans/{s2['id']}").json()["job"]
        self.assertEqual(j2["status"], "failed")
        self.assertIn("giriş başarısız", j2["error"])
        t2 = a.post(f"/api/projects/{p['id']}/targets", json={"name": "b", "kind": "web", "url": base + "/basic",
                                                               "options": {"delay": 0.2, "probe": False},
                                                               "auth": {"type": "basic", "username": "bob",
                                                                        "password": "pw"}}).json()
        self.assertEqual(t2["auth"], {"type": "basic", "username": "bob", "password": True})
        s3 = a.post(f"/api/targets/{t2['id']}/scans").json()
        self.run_worker()
        comps = a.get(f"/api/scans/{s3['id']}/components").json()
        self.assertIn("jquery", {c["name"].lower() for c in comps})


@unittest.skipIf(TestClient is None, "fastapi kurulu değil")
class TagTest(_Base):
    def test_tags(self):
        a = self.client("admin@x.io")
        o1 = a.post("/api/orgs", json={"name": "A"}).json()
        o2 = a.post("/api/orgs", json={"name": "B"}).json()
        for email, org in (("c1@a.com", o1), ("c2@b.com", o2)):
            a.post("/api/users", json={"email": email, "password": PW, "role": "customer", "organization_id": org["id"]})
        tags = a.get("/api/tags").json()["items"]
        builtin = {t["name"]: t["id"] for t in tags if t["builtin"]}
        self.assertEqual(set(builtin), {"Web", "Mobil", "API", "Kaynak kod"})
        c1, c2 = self.client("c1@a.com"), self.client("c2@b.com")
        t1 = c1.post("/api/tags", json={"name": "  Ödeme   ", "color": "red", "organization_id": o2["id"]}).json()
        self.assertEqual((t1["name"], t1["organization_id"]), ("Ödeme", o1["id"]))
        self.assertEqual(c1.post("/api/tags", json={"name": "ödeme"}).status_code, 409)
        self.assertEqual(c1.post("/api/tags", json={"name": "web"}).status_code, 409)
        self.assertEqual(c1.post("/api/tags", json={"name": "x", "color": "javascript"}).status_code, 400)
        self.assertNotIn(t1["id"], [t["id"] for t in c2.get("/api/tags").json()["items"]])
        self.assertEqual(c1.patch(f"/api/tags/{builtin['Web']}", json={"color": "red"}).status_code, 403)
        self.assertEqual(a.delete(f"/api/tags/{builtin['Web']}").status_code, 400)
        self.assertEqual(a.patch(f"/api/tags/{builtin['Web']}", json={"name": "X"}).status_code, 400)
        self.assertEqual(c2.delete(f"/api/tags/{t1['id']}").status_code, 404)
        p = c1.post("/api/projects", json={"name": "Portal", "tag_ids": [builtin["Web"], t1["id"]]}).json()
        self.assertEqual([t["name"] for t in p["tags"]], ["Web", "Ödeme"])
        self.assertEqual(c2.post("/api/projects", json={"name": "Z", "tag_ids": [t1["id"]]}).status_code, 400)
        a.post("/api/projects", json={"organization_id": o1["id"], "name": "Mobil app", "tag_ids": [builtin["Mobil"]]})
        self.assertEqual([x["name"] for x in c1.get("/api/projects", params={"tag": t1["id"]}).json()], ["Portal"])
        c1.delete(f"/api/tags/{t1['id']}")
        self.assertEqual([t["name"] for t in c1.get(f"/api/projects/{p['id']}").json()["tags"]], ["Web"])


@unittest.skipIf(TestClient is None, "fastapi kurulu değil")
class CollabTest(_Base):
    def test_teams_approval_assign_share_inbox(self):
        a = self.client("admin@x.io")
        oa = a.post("/api/orgs", json={"name": "A"}).json()
        ob = a.post("/api/orgs", json={"name": "B"}).json()
        ids = {}
        for email, org in (("alice@a.com", oa), ("bob@a.com", oa), ("carol@a.com", oa), ("dave@b.com", ob)):
            ids[email] = a.post("/api/users", json={"email": email, "password": PW, "role": "customer",
                                                    "organization_id": org["id"]}).json()["id"]
        alice, bob, carol, dave = (self.client(e) for e in ("alice@a.com", "bob@a.com", "carol@a.com", "dave@b.com"))
        self.assertEqual(carol.post("/api/teams", json={"name": "x", "organization_id": oa["id"]}).status_code, 403)
        team = a.post("/api/teams", json={"name": "Uygulama Güvenliği", "organization_id": oa["id"]}).json()
        bad = [[{"user_id": ids["dave@b.com"]}],
               [{"user_id": ids["alice@a.com"], "reports_to": ids["bob@a.com"]}, {"user_id": ids["bob@a.com"]}]]
        for b in bad:
            self.assertEqual(a.put(f"/api/teams/{team['id']}/members", json=b).status_code, 400, b)
        r = a.put(f"/api/teams/{team['id']}/members", json=[
            {"user_id": ids["carol@a.com"], "role": "manager"},
            {"user_id": ids["bob@a.com"], "role": "lead", "reports_to": ids["carol@a.com"]},
            {"user_id": ids["alice@a.com"], "role": "member", "reports_to": ids["bob@a.com"]}])
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual([x["name"] for x in dave.get("/api/teams").json()], [])
        p = a.post("/api/projects", json={"organization_id": oa["id"], "name": "P"}).json()
        from scakit.server.db import SessionLocal
        from scakit.server.models import Finding, Target
        s = SessionLocal()
        t = Target(project_id=p["id"], name="t", kind="upload", files=[])
        s.add(t)
        s.flush()
        f1 = Finding(target_id=t.id, project_id=p["id"], component_key="npm|x|1", vuln_id="GHSA-1", component="x",
                     version="1", severity="HIGH", aliases=["CVE-2024-1"])
        f2 = Finding(target_id=t.id, project_id=p["id"], component_key="npm|y|1", vuln_id="GHSA-2", component="y",
                     version="1", severity="LOW")
        s.add_all([f1, f2])
        s.commit()
        fid, fid2 = f1.id, f2.id
        s.close()
        r = alice.patch(f"/api/findings/{fid}", json={"status": "accepted_risk", "reason": "WAF var"}).json()
        self.assertEqual((r["status"], r["approval"]["state"]), ("open", "pending"))
        self.assertEqual({x["email"] for x in r["approval"]["approvers"]}, {"bob@a.com", "carol@a.com"})
        self.assertEqual(alice.patch(f"/api/findings/{fid}", json={"status": "false_positive", "reason": "x"}).status_code, 409)
        self.assertEqual(bob.get("/api/approvals/count").json()["pending"], 1)
        self.assertEqual(alice.get("/api/approvals/count").json()["pending"], 0)
        self.assertEqual(dave.get("/api/approvals").json(), [])
        inbox = bob.get("/api/inbox").json()
        self.assertEqual((inbox[0]["kind"], inbox[0]["params"]["vuln"]), ("approval_requested", "CVE-2024-1"))
        req_id = r["approval"]["id"]
        self.assertEqual(alice.post(f"/api/approvals/{req_id}/decide", json={"approve": True}).status_code, 403)
        self.assertEqual(dave.post(f"/api/approvals/{req_id}/decide", json={"approve": True}).status_code, 404)
        self.assertEqual(bob.post(f"/api/approvals/{req_id}/decide", json={"approve": False}).status_code, 400)
        d = bob.post(f"/api/approvals/{req_id}/decide", json={"approve": True, "note": "uygun"}).json()
        self.assertEqual(d["state"], "approved")
        self.assertEqual(alice.get(f"/api/findings/{fid}").json()["status"], "accepted_risk")
        self.assertEqual(alice.get("/api/inbox").json()[0]["params"]["approved"], True)
        self.assertEqual(bob.post(f"/api/approvals/{req_id}/decide", json={"approve": True}).status_code, 409)
        self.assertEqual(carol.patch(f"/api/findings/{fid2}", json={"status": "false_positive", "reason": "test kodu"})
                         .json()["status"], "false_positive")
        self.assertEqual(a.patch(f"/api/findings/{fid}/assign", json={"assignee_id": ids["dave@b.com"]}).status_code, 400)
        r = carol.post("/api/findings/assign", json={"ids": [fid, fid2], "assignee_id": ids["alice@a.com"],
                                                     "due_date": "2026-12-01T00:00:00Z"}).json()
        self.assertEqual(r["assigned"], 2)
        mine = alice.get("/api/findings", params={"assignee": "me", "status": ""}).json()
        self.assertEqual(mine["total"], 2)
        self.assertEqual(mine["items"][0]["assignee"]["email"], "alice@a.com")
        self.assertEqual(alice.get("/api/inbox").json()[0]["kind"], "assigned_bulk")
        self.assertEqual(alice.post(f"/api/findings/{fid}/share", json={"user_ids": [ids["dave@b.com"]]}).status_code, 400)
        self.assertEqual(alice.post(f"/api/findings/{fid}/share", json={"user_ids": [ids["bob@a.com"]],
                                                                      "message": "bakar mısın"}).json()["shared"], 1)
        alice.post(f"/api/findings/{fid}/comments", json={"text": "@carol@a.com ve @dave@b.com bakın"})
        self.assertEqual(carol.get("/api/inbox").json()[0]["kind"], "mentioned")
        self.assertEqual(dave.get("/api/inbox/count").json()["unread"], 0)
        self.assertEqual(dave.get("/api/directory").json()[0]["email"], "dave@b.com")
        self.assertGreater(bob.get("/api/inbox/count").json()["unread"], 0)
        bob.post("/api/inbox/read", json={"all": True})
        self.assertEqual(bob.get("/api/inbox/count").json()["unread"], 0)
        a.put("/api/settings", json={"approval_required": "0"})
        self.assertEqual(alice.patch(f"/api/findings/{fid}", json={"status": "not_affected", "reason": "x"}).json()["status"],
                         "not_affected")


@unittest.skipIf(TestClient is None or not hasattr(os, "fork"), "fork yok")
class IsolationTest(_Base):

    def _job(self, kind="scan"):
        from scakit.server.db import SessionLocal
        from scakit.server.models import Job
        s = SessionLocal()
        j = Job(kind=kind, status="running", worker="test")
        s.add(j)
        s.commit()
        jid = j.id
        s.close()
        return jid

    def _run(self, handler, after_start=None):
        import time
        from scakit.server import pipeline, worker
        from scakit.server.db import SessionLocal
        from scakit.server.models import Job
        jid = self._job("selfscan")
        orig = pipeline.HANDLERS["selfscan"]
        pipeline.HANDLERS["selfscan"] = handler
        worker.HANDLERS["selfscan"] = handler
        os.environ["SCAKIT_JOB_ISOLATION"] = "1"
        try:
            db = SessionLocal()
            job = db.get(Job, jid)
            proc, deadline = worker.start_isolated(db, job)
            if after_start:
                after_start(jid)
            t0 = time.time()
            while not worker.supervise(db, job, proc, deadline):
                time.sleep(0.2)
            elapsed = time.time() - t0
            db.refresh(job)
            out = (job.status, job.error or "", elapsed, proc.is_alive())
            db.close()
            return out
        finally:
            pipeline.HANDLERS["selfscan"] = orig
            worker.HANDLERS["selfscan"] = orig
            os.environ["SCAKIT_JOB_ISOLATION"] = "0"
            os.environ.pop("SCAKIT_JOB_TIMEOUT_SECONDS", None)

    def test_timeout_kills(self):
        import time
        os.environ["SCAKIT_JOB_TIMEOUT_SECONDS"] = "2"
        status, err, elapsed, alive = self._run(lambda db, job, ctx: time.sleep(60))
        self.assertEqual(status, "failed")
        self.assertIn("Zaman aşımı", err)
        self.assertLess(elapsed, 10)
        self.assertFalse(alive)

    def test_cancel_kills_immediately(self):
        import time

        def cancel(jid):
            from scakit.server.db import SessionLocal
            from scakit.server.models import Job
            time.sleep(1)
            s = SessionLocal()
            s.get(Job, jid).status = "canceled"
            s.commit()
            s.close()
        import threading
        status, _err, elapsed, alive = self._run(lambda db, job, ctx: time.sleep(60),
                                                 after_start=lambda jid: threading.Thread(target=cancel, args=(jid,)).start())
        self.assertEqual(status, "canceled")
        self.assertLess(elapsed, 10)
        self.assertFalse(alive)

    def test_crash_marked_failed(self):
        status, err, _e, _a = self._run(lambda db, job, ctx: os._exit(9))
        self.assertEqual(status, "failed")
        self.assertIn("beklenmedik", err)

    def test_success(self):
        def ok(db, job, ctx):
            ctx.log("merhaba")
        status, _err, _e, _a = self._run(ok)
        self.assertEqual(status, "done")


@unittest.skipIf(TestClient is None, "fastapi kurulu değil")
class MaintenanceTest(_Base):
    def test_retention(self):
        from datetime import datetime, timedelta, timezone
        from scakit.server.config import get_config
        from scakit.server.db import SessionLocal
        from scakit.server.models import AuditLog, Finding, Job, Project, Organization, Scan, Target
        a = self.client("admin@x.io")
        a.put("/api/settings", json={"retention_scans_per_target": "2", "audit_retention_days": "30"})
        s = SessionLocal()
        org = Organization(name="O")
        s.add(org)
        s.flush()
        p = Project(organization_id=org.id, name="P")
        s.add(p)
        s.flush()
        t = Target(project_id=p.id, name="t", kind="upload", files=[])
        s.add(t)
        s.flush()
        dirs = []
        for i in range(5):
            j = Job(kind="scan", status="done" if i < 4 else "running")
            s.add(j)
            s.flush()
            d = get_config().scans_dir / f"s{i}"
            d.mkdir(parents=True)
            (d / "x").write_text("x")
            dirs.append(d)
            s.add(Scan(target_id=t.id, job_id=j.id, workdir=str(d)))
        s.add(Finding(target_id=t.id, project_id=p.id, component_key="npm|a|1", vuln_id="X", first_seen_scan=1))
        s.add(AuditLog(action="eski", at=datetime.now(timezone.utc) - timedelta(days=40)))
        outside = Path(self.tmp.name).parent / "lf-outside-test"
        outside.mkdir(exist_ok=True)
        jo = Job(kind="scan", status="done")
        s.add(jo)
        s.flush()
        s.add(Scan(target_id=t.id, job_id=jo.id, workdir=str(outside)))
        s.commit()
        s.close()
        r = a.post("/api/system/maintenance").json()
        self.assertGreaterEqual(r["stats"]["scans"], 2)
        s = SessionLocal()
        left = sorted(sc.workdir for sc in s.query(Scan).filter(Scan.workdir.like("%/s%")))
        self.assertIn(str(dirs[4]), left)
        self.assertIn(str(dirs[3]), left)
        self.assertFalse(dirs[0].exists())
        self.assertEqual(s.query(Finding).count(), 1)
        self.assertEqual(s.query(AuditLog).filter_by(action="eski").count(), 0)
        self.assertTrue(outside.exists())
        s.close()
        from scakit.server.maintenance import _rm_tree
        root = get_config().scans_dir
        self.assertFalse(_rm_tree(outside, root))
        self.assertFalse(_rm_tree(root, root))
        link = root / "baglanti"
        os.symlink(outside, link)
        self.assertFalse(_rm_tree(link, root))
        self.assertTrue(outside.exists())
        link.unlink()
        outside.rmdir()
        self.assertTrue(a.get("/api/system").json()["maintenance"]["at"])


@unittest.skipIf(TestClient is None, "fastapi kurulu değil")
class OidcTest(_Base):
    def setUp(self):
        super().setUp()
        import base64
        import time
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
        from scakit.server import oidc
        self.oidc = oidc
        oidc._CACHE.clear()
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub = self.key.public_key().public_numbers()
        b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
        self.b64u = b64u
        jwk = {"kty": "RSA", "kid": "k1", "n": b64u(pub.n.to_bytes(256, "big")), "e": b64u(pub.e.to_bytes(3, "big"))}
        self.iss = "https://idp.test/realm"
        self.claims = {}

        def get(url):
            if url.endswith("/.well-known/openid-configuration"):
                return {"issuer": self.iss, "authorization_endpoint": self.iss + "/auth",
                        "token_endpoint": self.iss + "/token", "jwks_uri": self.iss + "/jwks"}
            return {"keys": [jwk]}

        def sign(claims, key=None, alg="RS256", kid="k1"):
            h = b64u(json.dumps({"alg": alg, "kid": kid}).encode())
            p = b64u(json.dumps(claims).encode())
            if alg == "none":
                return f"{h}.{p}."
            sig = (key or self.key).sign(f"{h}.{p}".encode(), padding.PKCS1v15(), hashes.SHA256())
            return f"{h}.{p}.{b64u(sig)}"
        self.sign = sign
        self.token_fn = lambda nonce: sign({**self._base(nonce), **self.claims})
        self.orig = (oidc._http_get, oidc._http_post)
        oidc._http_get = get
        oidc._http_post = lambda url, data: {"id_token": self.token_fn(self.nonce)}
        a = self.client("admin@x.io")
        a.put("/api/settings", json={"oidc_enabled": "1", "oidc_issuer": self.iss, "oidc_client_id": "le-fureteur",
                                     "oidc_client_secret": "s3cret"})
        self.now = time.time()

    def tearDown(self):
        self.oidc._http_get, self.oidc._http_post = self.orig
        super().tearDown()

    def _base(self, nonce):
        return {"iss": self.iss, "aud": "le-fureteur", "exp": self.now + 300, "iat": self.now, "nonce": nonce,
                "email": "admin@x.io", "email_verified": True}

    def _flow(self, tamper_state=False):
        from urllib.parse import parse_qs, urlparse
        c = TestClient(self.app)
        r = c.get("/api/auth/oidc/start", follow_redirects=False)
        self.assertEqual(r.status_code, 302)
        q = parse_qs(urlparse(r.headers["location"]).query)
        self.assertEqual(q["code_challenge_method"], ["S256"])
        self.nonce = q["nonce"][0]
        state = "kotu" if tamper_state else q["state"][0]
        r = c.get(f"/api/auth/oidc/callback?code=abc&state={state}", follow_redirects=False)
        return c, r

    def test_success_and_attacks(self):
        self.assertTrue(TestClient(self.app).get("/api/auth/oidc/config").json()["enabled"])
        c, r = self._flow()
        self.assertEqual(r.status_code, 200)
        self.assertIn("refresh", r.text)
        self.assertEqual(c.get("/api/auth/me").json()["email"], "admin@x.io")
        attacks = {
            "none": lambda n: self.sign(self._base(n), alg="none"),
            "baska_anahtar": lambda n: self.sign(self._base(n), key=self.other),
            "aud": lambda n: self.sign({**self._base(n), "aud": "baska-uygulama"}),
            "sure": lambda n: self.sign({**self._base(n), "exp": self.now - 3600}),
            "nonce": lambda n: self.sign({**self._base(n), "nonce": "x"}),
            "iss": lambda n: self.sign({**self._base(n), "iss": "https://kotu.test"}),
            "dogrulanmamis": lambda n: self.sign({**self._base(n), "email_verified": False}),
            "hs256": lambda n: self.sign(self._base(n), alg="HS256"),
        }
        for name, fn in attacks.items():
            self.token_fn = fn
            c, r = self._flow()
            self.assertIn("sso_error=failed", r.headers.get("location", ""), name)
            self.assertEqual(c.get("/api/auth/me").status_code, 401, name)
        self.token_fn = lambda n: self.sign({**self._base(n), "email": "yok@x.io"})
        c, r = self._flow()
        self.assertIn("sso_error=no_account", r.headers["location"])
        self.token_fn = lambda n: self.sign(self._base(n))
        c, r = self._flow(tamper_state=True)
        self.assertIn("sso_error=failed", r.headers["location"])
        r = TestClient(self.app).get("/api/auth/oidc/callback?code=x&state=y", follow_redirects=False)
        self.assertIn("sso_error=failed", r.headers["location"])


@unittest.skipIf(TestClient is None, "fastapi kurulu değil")
class EventsTest(_Base):
    def test_structured_scan_events(self):
        import requests
        from scakit.server import notify
        orig = notify._http_post

        def boom(url, body, headers):
            raise requests.ConnectionError("HTTPSConnectionPool(host='hooks.slack.invalid', port=443): "
                                           "NameResolutionError: Failed to resolve 'hooks.slack.invalid'")
        notify._http_post = boom
        try:
            a = self.client("admin@x.io")
            a.put("/api/settings", json={"vulndb_path": str(self.dbpath)})
            a.post("/api/notifications", json={"name": "Ekip", "kind": "slack", "config": {"url": "https://hooks.slack.invalid/x"}})
            org = a.post("/api/orgs", json={"name": "O"}).json()
            p = a.post("/api/projects", json={"organization_id": org["id"], "name": "P"}).json()
            t = a.post(f"/api/projects/{p['id']}/targets", json={"name": "src", "kind": "upload"}).json()
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as z:
                z.writestr("web/package-lock.json", (FIX / "app" / "web" / "package-lock.json").read_text())
            a.post(f"/api/targets/{t['id']}/files", files={"file": ("kaynak-kodu.zip", buf.getvalue())})
            s = a.post(f"/api/targets/{t['id']}/scans").json()
            self.run_worker()
            ev = a.get(f"/api/scans/{s['id']}").json()["job"]["events"]
            codes = [e["code"] for e in ev]
            for c in ("scan_started", "input_started", "input_done", "matched", "synced", "reports", "notify_failed",
                      "scan_finished"):
                self.assertIn(c, codes)
            started = next(e for e in ev if e["code"] == "input_started")
            self.assertEqual(started["params"]["name"], "kaynak-kodu.zip")
            nf = next(e for e in ev if e["code"] == "notify_failed")
            self.assertEqual((nf["params"]["kind"], nf["params"]["channel"]), ("dns", "Ekip"))
        finally:
            notify._http_post = orig


@unittest.skipIf(TestClient is None, "fastapi kurulu değil")
class ReportSuppressedTest(_Base):
    def test_docx_pdf_with_accepted_risk_all_langs(self):
        try:
            import docx
            import reportlab
        except ImportError:
            self.skipTest("rapor kütüphaneleri yok")
        a = self.client("admin@x.io")
        a.put("/api/settings", json={"vulndb_path": str(self.dbpath)})
        org = a.post("/api/orgs", json={"name": "O"}).json()
        p = a.post("/api/projects", json={"organization_id": org["id"], "name": "P"}).json()
        t = a.post(f"/api/projects/{p['id']}/targets", json={"name": "src", "kind": "upload"}).json()
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("web/package-lock.json", (FIX / "app" / "web" / "package-lock.json").read_text())
        a.post(f"/api/targets/{t['id']}/files", files={"file": ("k.zip", buf.getvalue())})
        a.post(f"/api/targets/{t['id']}/scans")
        self.run_worker()
        fid = a.get("/api/findings").json()["items"][0]["id"]
        a.patch(f"/api/findings/{fid}", json={"status": "accepted_risk", "reason": "WAF"})
        for lang in ("tr", "en", "fr", "de"):
            a.patch(f"/api/projects/{p['id']}", json={"report_lang": lang})
            s = a.post(f"/api/targets/{t['id']}/scans").json()
            self.run_worker()
            job = a.get(f"/api/scans/{s['id']}").json()["job"]
            self.assertEqual(job["status"], "done", (lang, job["error"]))
            names = {r["name"] for r in a.get(f"/api/scans/{s['id']}/reports").json()}
            self.assertTrue(any(n.endswith(".docx") for n in names) and any(n.endswith(".pdf") for n in names), (lang, names))


@unittest.skipIf(TestClient is None, "fastapi kurulu değil")
class DisputeTest(_Base):
    def test_dispute_flow(self):
        a = self.client("admin@x.io")
        oa = a.post("/api/orgs", json={"name": "A"}).json()
        ob = a.post("/api/orgs", json={"name": "B"}).json()
        ids = {}
        for email, org, role in (("alice@a.com", oa, "customer"), ("bob@a.com", oa, "customer"), ("carol@a.com", oa, "customer"),
                                 ("dave@b.com", ob, "customer"), ("ana@x.io", None, "analyst")):
            ids[email] = a.post("/api/users", json={"email": email, "password": PW, "role": role,
                                                    "organization_id": org["id"] if org else None}).json()["id"]
        team = a.post("/api/teams", json={"name": "T", "organization_id": oa["id"]}).json()
        a.put(f"/api/teams/{team['id']}/members", json=[{"user_id": ids["carol@a.com"], "role": "manager"},
                                                        {"user_id": ids["bob@a.com"], "role": "lead", "reports_to": ids["carol@a.com"]},
                                                        {"user_id": ids["alice@a.com"], "role": "member", "reports_to": ids["bob@a.com"]}])
        p = a.post("/api/projects", json={"organization_id": oa["id"], "name": "P"}).json()
        from scakit.server.db import SessionLocal
        from scakit.server.models import Finding, Target
        s = SessionLocal()
        t = Target(project_id=p["id"], name="t", kind="upload", files=[])
        s.add(t)
        s.flush()
        f = Finding(target_id=t.id, project_id=p["id"], component_key="npm|x|1", vuln_id="GHSA-9", component="x",
                    version="1", severity="HIGH")
        s.add(f)
        s.commit()
        fid = f.id
        s.close()
        alice, bob, carol, dave, ana = (self.client(e) for e in ("alice@a.com", "bob@a.com", "carol@a.com", "dave@b.com", "ana@x.io"))
        self.assertEqual(alice.post(f"/api/findings/{fid}/disputes", json={"title": "Gerçekten etkileniyor muyuz?", "message": "x",
                                                                         "participants": [ids["dave@b.com"]]}).status_code, 400)
        d = alice.post(f"/api/findings/{fid}/disputes", json={"title": "Gerçekten etkileniyor muyuz?",
                                                              "message": "Bu fonksiyonu kullanmıyoruz", "participants": [ids["bob@a.com"]]}).json()
        did = d["id"]
        self.assertEqual(dave.get(f"/api/disputes/{did}").status_code, 404)
        self.assertEqual(bob.get("/api/inbox").json()[0]["kind"], "dispute_opened")
        bob.post(f"/api/disputes/{did}/messages", json={"text": "Bence kullanıyoruz, servis X'te çağrılıyor"})
        e = alice.post(f"/api/disputes/{did}/escalate", json={"note": "Uzlaşamadık"}).json()
        self.assertEqual(e["status"], "escalated")
        self.assertEqual([j["email"] for j in e["judges"]], ["carol@a.com"])
        self.assertEqual(carol.get("/api/disputes", params={"box": "judge"}).json()[0]["id"], did)
        for c in (alice, bob):
            self.assertEqual(c.post(f"/api/disputes/{did}/resolve", json={"resolution": "x"}).status_code, 403)
        self.assertEqual(carol.post(f"/api/disputes/{did}/delegate", json={"user_id": ids["dave@b.com"]}).status_code, 400)
        self.assertEqual(carol.post(f"/api/disputes/{did}/delegate", json={"user_id": ids["ana@x.io"], "note": "Sen bakar mısın"}).status_code, 200)
        self.assertEqual(ana.get("/api/inbox").json()[0]["kind"], "dispute_delegated")
        r = ana.post(f"/api/disputes/{did}/resolve", json={"resolution": "Kod incelendi; etkilenen fonksiyon çağrılmıyor",
                                                          "status": "false_positive"}).json()
        self.assertEqual((r["status"], r["resolved_status"]), ("resolved", "false_positive"))
        fd = alice.get(f"/api/findings/{fid}").json()
        self.assertEqual(fd["status"], "false_positive")
        self.assertIn("dispute", [c["kind"] for c in fd["comments"]])
        self.assertEqual(alice.get("/api/inbox").json()[0]["kind"], "dispute_resolved")
        self.assertEqual(bob.post(f"/api/disputes/{did}/messages", json={"text": "?"}).status_code, 409)
        d2 = bob.post(f"/api/findings/{fid}/disputes", json={"title": "Sürüm notu", "message": "x"}).json()
        self.assertEqual(bob.post(f"/api/disputes/{d2['id']}/resolve", json={"resolution": "ok", "status": "open"}).status_code, 403)
        self.assertEqual(bob.post(f"/api/disputes/{d2['id']}/resolve", json={"resolution": "Anlaştık"}).json()["status"], "resolved")


@unittest.skipIf(TestClient is None, "fastapi kurulu değil")
class MessagingTest(_Base):
    def test_messages_receipts_team_reminders(self):
        a = self.client("admin@x.io")
        oa = a.post("/api/orgs", json={"name": "A"}).json()
        ob = a.post("/api/orgs", json={"name": "B"}).json()
        ids = {}
        for email, org, role in (("alice@a.com", oa, "customer"), ("bob@a.com", oa, "customer"), ("carol@a.com", oa, "customer"),
                                 ("dave@b.com", ob, "customer"), ("ana@x.io", None, "analyst")):
            ids[email] = a.post("/api/users", json={"email": email, "password": PW, "role": role,
                                                    "organization_id": org["id"] if org else None}).json()["id"]
        team = a.post("/api/teams", json={"name": "T", "organization_id": oa["id"]}).json()
        a.put(f"/api/teams/{team['id']}/members", json=[{"user_id": ids["carol@a.com"], "role": "manager"},
                                                        {"user_id": ids["bob@a.com"], "role": "member"},
                                                        {"user_id": ids["alice@a.com"], "role": "member"}])
        alice, bob, carol, dave, ana = (self.client(e) for e in ("alice@a.com", "bob@a.com", "carol@a.com", "dave@b.com", "ana@x.io"))
        self.assertEqual(alice.post("/api/messages/threads", json={"subject": "x", "body": "y", "to": [ids["dave@b.com"]]}).status_code, 400)
        self.assertNotIn("dave@b.com", [u["email"] for u in alice.get("/api/messages/recipients").json()["users"]])
        self.assertIn("ana@x.io", [u["email"] for u in alice.get("/api/messages/recipients").json()["users"]])
        self.assertEqual(dave.post("/api/messages/threads", json={"subject": "x", "body": "y", "team_id": team["id"]}).status_code, 403)
        t = alice.post("/api/messages/threads", json={"subject": "Sprint", "body": "Log4j bu hafta", "team_id": team["id"]}).json()
        self.assertEqual(sorted(p["email"] for p in t["participants"]), ["alice@a.com", "bob@a.com", "carol@a.com"])
        self.assertEqual(t["messages"][0]["state"], "sent")
        self.assertEqual(dave.get(f"/api/messages/threads/{t['id']}").status_code, 404)
        self.assertEqual(bob.get("/api/messages/count").json()["unread"], 1)
        th = alice.get(f"/api/messages/threads/{t['id']}").json()
        self.assertEqual(th["messages"][0]["state"], "sent")
        carol.get("/api/messages/count")
        self.assertEqual(alice.get(f"/api/messages/threads/{t['id']}").json()["messages"][0]["state"], "delivered")
        bob.get(f"/api/messages/threads/{t['id']}")
        self.assertEqual(bob.get("/api/messages/count").json()["unread"], 0)
        n = alice.post(f"/api/messages/threads/{t['id']}/nudge").json()
        self.assertEqual(n["nudged"], 1)
        self.assertEqual(carol.get("/api/inbox").json()[0]["kind"], "message_nudge")
        self.assertEqual(alice.post(f"/api/messages/threads/{t['id']}/nudge").status_code, 429)
        carol.get(f"/api/messages/threads/{t['id']}")
        self.assertEqual(alice.get(f"/api/messages/threads/{t['id']}").json()["messages"][0]["state"], "read")
        self.assertEqual(bob.get(f"/api/messages/threads/{t['id']}").json()["messages"][0]["receipts"], [])
        bob.post(f"/api/messages/threads/{t['id']}/reply", json={"body": "Tamam"})
        self.assertEqual([x["id"] for x in alice.get("/api/messages/threads", params={"box": "unread"}).json()], [t["id"]])
        self.assertEqual(len(alice.get("/api/messages/threads", params={"box": "inbox"}).json()), 1)
        self.assertEqual(carol.get("/api/messages/threads", params={"box": "sent"}).json(), [])
        self.assertEqual(len(carol.get("/api/messages/threads", params={"box": "inbox"}).json()), 1)
        self.assertEqual(alice.post("/api/reminders", json={"text": "x", "due_at": "2020-01-01T00:00:00Z", "link": "https://evil.example"}).status_code, 400)
        r = alice.post("/api/reminders", json={"text": "Log4j kontrol", "due_at": "2020-01-01T00:00:00Z", "link": "/findings?open=1"}).json()
        future = alice.post("/api/reminders", json={"text": "Gelecek", "due_at": "2099-01-01T00:00:00Z"}).json()
        alice.get("/api/messages/count")
        kinds = [i["kind"] for i in alice.get("/api/inbox").json()]
        self.assertEqual(kinds.count("reminder"), 1)
        self.assertEqual(bob.patch(f"/api/reminders/{r['id']}", json={"done": True}).status_code, 404)
        self.assertIsNotNone(alice.patch(f"/api/reminders/{r['id']}", json={"done": True}).json()["done_at"])
        self.assertEqual(bob.delete(f"/api/reminders/{future['id']}").status_code, 404)
        self.assertEqual(alice.delete(f"/api/reminders/{future['id']}").status_code, 200)


@unittest.skipIf(TestClient is None, "fastapi kurulu değil")
class TeamOverviewTest(_Base):
    def test_team_and_org_overview(self):
        a = self.client("admin@x.io")
        oa = a.post("/api/orgs", json={"name": "A", "tags": ["Bankacılık", " KVKK ", ""], "industry": "Finans",
                                       "contact_email": "ciso@a.com"}).json()
        self.assertEqual(oa["tags"], ["Bankacılık", "KVKK"])
        self.assertEqual(a.patch(f"/api/orgs/{oa['id']}", json={"contact_email": "bozuk"}).status_code, 400)
        self.assertEqual(a.patch(f"/api/orgs/{oa['id']}", json={"contract_end": "2027-06-30T00:00:00Z"}).json()["contract_end"][:10], "2027-06-30")
        ob = a.post("/api/orgs", json={"name": "B"}).json()
        ids = {}
        for email, org in (("alice@a.com", oa), ("carol@a.com", oa), ("dave@b.com", ob)):
            ids[email] = a.post("/api/users", json={"email": email, "password": PW, "role": "customer",
                                                    "organization_id": org["id"]}).json()["id"]
        team = a.post("/api/teams", json={"name": "T", "organization_id": oa["id"]}).json()
        a.put(f"/api/teams/{team['id']}/members", json=[{"user_id": ids["carol@a.com"], "role": "manager"},
                                                        {"user_id": ids["alice@a.com"], "role": "member", "reports_to": ids["carol@a.com"]}])
        p = a.post("/api/projects", json={"organization_id": oa["id"], "name": "P", "status": "active",
                                          "due_date": "2030-01-01T00:00:00Z", "owner_id": ids["carol@a.com"]}).json()
        self.assertEqual((p["status"], p["owner"]["email"]), ("active", "carol@a.com"))
        self.assertEqual(a.patch(f"/api/projects/{p['id']}", json={"owner_id": ids["dave@b.com"]}).status_code, 400)
        self.assertEqual(a.patch(f"/api/projects/{p['id']}", json={"status": "bozuk"}).status_code, 400)
        from scakit.server.db import SessionLocal
        from scakit.server.models import Finding, Target
        from datetime import datetime, timedelta, timezone
        s = SessionLocal()
        t = Target(project_id=p["id"], name="t", kind="upload", files=[])
        s.add(t)
        s.flush()
        past = datetime.now(timezone.utc) - timedelta(days=2)
        for i, (sev, st, due) in enumerate((("CRITICAL", "open", past), ("HIGH", "open", None), ("LOW", "open", None))):
            s.add(Finding(target_id=t.id, project_id=p["id"], component_key=f"npm|x{i}|1", vuln_id=f"GHSA-{i}", component=f"x{i}",
                          version="1", severity=sev, status=st, assignee_id=ids["alice@a.com"], due_date=due))
        s.commit()
        last = s.query(Finding).filter_by(vuln_id="GHSA-2").one()
        last.status = "accepted_risk"
        s.commit()
        s.close()
        carol, dave = self.client("carol@a.com"), self.client("dave@b.com")
        ov = carol.get(f"/api/teams/{team['id']}/overview").json()
        self.assertEqual(ov["totals"]["open"], 2)
        self.assertEqual(ov["totals"]["overdue"], 1)
        self.assertEqual(ov["totals"]["delivered_30d"], 1)
        alice_row = next(x for x in ov["people"] if x["user"]["email"] == "alice@a.com")
        self.assertEqual((alice_row["open"], alice_row["overdue"], alice_row["delivered_30d"]), (2, 1, 1))
        self.assertEqual(ov["queue"][0]["vuln_id"], "GHSA-0")
        self.assertEqual(dave.get(f"/api/teams/{team['id']}/overview").status_code, 404)
        self.assertEqual(carol.get(f"/api/projects/{p['id']}").json()["overdue"], 1)
        o = carol.get(f"/api/orgs/{oa['id']}/overview").json()
        self.assertEqual((len(o["projects"]), len(o["teams"]), len(o["users"])), (1, 1, 2))
        self.assertEqual(dave.get(f"/api/orgs/{oa['id']}/overview").status_code, 404)


@unittest.skipIf(TestClient is None, "fastapi kurulu değil")
class ToolsetTest(_Base):
    def setUp(self):
        super().setUp()
        from scakit.server import ratelimit
        ratelimit.reset()

    def _local_server(self):
        import http.server
        import threading

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if self.path == "/redir":
                    self.send_response(302)
                    self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
                    self.end_headers()
                    return
                body = (f"cookie={self.headers.get('Cookie')}|x={self.headers.get('X-Test')}|<script>x</script>").encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        return srv.server_address[1]

    def test_ssrf_blocked_and_limits(self):
        a = self.client("admin@x.io")
        port = self._local_server()
        for url in (f"http://127.0.0.1:{port}/", "http://169.254.169.254/latest/meta-data/", "http://localhost/",
                    "file:///etc/passwd", "gopher://127.0.0.1:6379/", "http://user:pw@example.com/", "http://[::1]/"):
            r = a.post("/api/tools/http", json={"url": url})
            self.assertEqual(r.status_code, 400, url)
        self.assertEqual(a.post("/api/tools/ping", json={"host": "127.0.0.1", "port": port}).status_code, 400)
        self.assertEqual(a.post("/api/tools/http", json={"url": "https://example.com/", "headers": [["X", "a\r\nInjected: 1"]]}).status_code, 400)
        self.assertEqual(a.post("/api/tools/http", json={"url": "https://example.com/", "method": "TRACE"}).status_code, 400)
        self.assertEqual(a.post("/api/tools/http", json={"url": "https://example.com/", "headers": [["Content-Length", "5"]]}).status_code, 400)
        org = a.post("/api/orgs", json={"name": "A", "allowed_domains": ["acme.test"]}).json()
        a.post("/api/users", json={"email": "c@a.com", "password": PW, "role": "customer", "organization_id": org["id"]})
        c = self.client("c@a.com")
        self.assertEqual(c.post("/api/tools/http", json={"url": "https://example.com/"}).status_code, 403)
        self.assertFalse(c.get("/api/tools/status").json()["network"])
        a.put("/api/settings", json={"toolset_customers": "1"})
        r = c.post("/api/tools/http", json={"url": "https://example.com/"})
        self.assertEqual(r.status_code, 400)
        self.assertIn("izinli", r.json()["detail"])
        a.put("/api/settings", json={"toolset_enabled": "0"})
        self.assertEqual(a.post("/api/tools/http", json={"url": "https://example.com/"}).status_code, 403)

    def test_success_path_with_local_fixture(self):
        from unittest import mock
        from scakit.server import guard, toolset
        port = self._local_server()
        real = guard._bad_ip
        relaxed = lambda ip: False if ip == "127.0.0.1" else real(ip)
        a = self.client("admin@x.io")
        with mock.patch.object(guard, "_bad_ip", relaxed), mock.patch.object(toolset, "_bad_ip", relaxed):
            r = a.post("/api/tools/http", json={"url": f"http://127.0.0.1:{port}/", "headers": [["X-Test", "42"]]}).json()
            self.assertEqual(r["status"], 200)
            self.assertIn("x=42", r["body"])
            self.assertIn("cookie=None", r["body"])
            self.assertIn("<script>", r["body"])
            r = a.post("/api/tools/http", json={"url": f"http://127.0.0.1:{port}/redir", "follow_redirects": True})
            self.assertEqual(r.status_code, 400)
            p = a.post("/api/tools/ping", json={"host": "127.0.0.1", "port": port, "count": 2}).json()
            self.assertEqual(p["received"], 2)
        a.put("/api/settings", json={"toolset_rate_per_minute": "2"})
        from scakit.server import ratelimit
        ratelimit.reset()
        codes = [a.post("/api/tools/http", json={"url": "https://example.invalid/"}).status_code for _ in range(3)]
        self.assertEqual(codes[-1], 429)

    def test_notes_private(self):
        a = self.client("admin@x.io")
        a.post("/api/users", json={"email": "b@x.io", "password": PW, "role": "analyst"})
        b = self.client("b@x.io")
        n = a.post("/api/tools/notes", json={"title": "Payloadlar", "body": "<img src=x onerror=alert(1)>"}).json()
        self.assertEqual(b.get("/api/tools/notes").json(), [])
        self.assertEqual(b.put(f"/api/tools/notes/{n['id']}", json={"title": "x"}).status_code, 404)
        self.assertEqual(b.delete(f"/api/tools/notes/{n['id']}").status_code, 404)
        self.assertEqual(a.put(f"/api/tools/notes/{n['id']}", json={"title": "P", "body": "y", "pinned": True}).json()["pinned"], True)
        self.assertEqual(a.delete(f"/api/tools/notes/{n['id']}").status_code, 200)


@unittest.skipIf(TestClient is None, "fastapi kurulu değil")
class AdminSecurityTest(_Base):
    def setUp(self):
        super().setUp()
        from scakit.server import ratelimit
        from scakit.server.security import _attempts
        ratelimit.reset()
        _attempts.clear()

    def test_maintenance_mode(self):
        a = self.client("admin@x.io")
        a.post("/api/users", json={"email": "an@x.io", "password": PW, "role": "analyst"})
        an = self.client("an@x.io")
        tok = an.post("/api/tokens", json={"name": "ci", "scopes": ["read"]}).json()["token"]
        self.assertFalse(a.get("/api/public/status").json()["maintenance"])
        a.put("/api/settings", json={"maintenance_mode": "1", "maintenance_message": "Sürüm yükseltmesi 22:00'ye kadar"})
        r = an.get("/api/projects")
        self.assertEqual(r.status_code, 503)
        self.assertEqual(r.json()["detail"]["code"], "maintenance")
        from fastapi.testclient import TestClient as TC
        from scakit.server.app import create_app
        raw = TC(create_app())
        self.assertEqual(raw.get("/api/projects", headers={"Authorization": f"Bearer {tok}"}).status_code, 503)
        pub = raw.get("/api/public/status").json()
        self.assertEqual((pub["maintenance"], pub["message"]), (True, "Sürüm yükseltmesi 22:00'ye kadar"))
        csrf = raw.get("/api/health").cookies.get("scakit_csrf") or raw.cookies.get("scakit_csrf")
        r = raw.post("/api/auth/login", json={"email": "an@x.io", "password": PW}, headers={"X-CSRF-Token": csrf})
        self.assertEqual(r.status_code, 503)
        self.assertEqual(a.get("/api/projects").status_code, 200)
        a.put("/api/settings", json={"maintenance_mode": "0"})
        self.assertEqual(an.get("/api/projects").status_code, 200)

    def test_login_limit_configurable_and_history(self):
        a = self.client("admin@x.io")
        u = a.post("/api/users", json={"email": "u@x.io", "password": PW, "role": "analyst"}).json()
        a.put("/api/settings", json={"login_max_failures": "2", "login_window_minutes": "1"})
        from fastapi.testclient import TestClient as TC
        from scakit.server.app import create_app
        c = TC(create_app())
        csrf = c.get("/api/health").cookies.get("scakit_csrf") or c.cookies.get("scakit_csrf")
        h = {"X-CSRF-Token": csrf, "User-Agent": "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0 Safari/537.36"}
        codes = [c.post("/api/auth/login", json={"email": "u@x.io", "password": "yanlis-parola-1"}, headers=h).status_code for _ in range(3)]
        self.assertEqual(codes, [401, 401, 429])
        from scakit.server.security import _attempts
        _attempts.clear()
        self.assertEqual(c.post("/api/auth/login", json={"email": "u@x.io", "password": PW}, headers=h).status_code, 200)
        d = a.get(f"/api/users/{u['id']}/detail").json()
        self.assertEqual(d["last_device"], "Chrome · Windows")
        self.assertEqual([e["reason"] for e in d["logins"][:4]], ["", "throttled", "bad_password", "bad_password"])
        self.assertEqual(d["stats"]["sessions"], 1)
        self.assertEqual(len(c.get("/api/auth/sessions").json()), 1)
        self.assertTrue(c.get("/api/auth/sessions").json()[0]["current"])
        self.assertEqual(a.delete(f"/api/users/{u['id']}/sessions").json()["revoked"], 1)
        self.assertEqual(c.get("/api/auth/me").status_code, 401)
        an = self.client("u@x.io")
        self.assertEqual(an.get(f"/api/users/{u['id']}/detail").status_code, 403)
        sid = an.get("/api/auth/sessions").json()[0]["id"]
        other = self.client("admin@x.io")
        self.assertEqual(other.delete(f"/api/auth/sessions/{sid}").status_code, 404)

    def test_api_rate_limit(self):
        a = self.client("admin@x.io")
        a.put("/api/settings", json={"api_rate_per_minute": "5"})
        from scakit.server import ratelimit
        ratelimit.reset()
        codes = [a.get("/api/auth/me").status_code for _ in range(7)]
        self.assertEqual(codes[:5], [200] * 5)
        self.assertEqual(codes[-1], 429)
        ratelimit.reset()
        a.put("/api/settings", json={"api_rate_per_minute": "0"})

    def test_audit_filters_and_csv(self):
        a = self.client("admin@x.io")
        a.post("/api/orgs", json={"name": "=HYPERLINK(\"http://x\")"})
        a.post("/api/users", json={"email": "f@x.io", "password": PW, "role": "analyst"})
        r = a.get("/api/audit", params={"action": "org"}).json()
        self.assertTrue(r["items"]) and self.assertTrue(all(i["action"].startswith("org.") for i in r["items"]))
        self.assertEqual(a.get("/api/audit", params={"action": "org.create", "q": "HYPERLINK"}).json()["total"], 1)
        self.assertEqual(a.get("/api/audit", params={"q": "%"}).json()["total"], 0)
        self.assertIn("org.create", a.get("/api/audit/facets").json()["actions"])
        csv_text = a.get("/api/audit.csv", params={"action": "org.create"}).text
        self.assertIn("'=HYPERLINK", csv_text)
        self.assertEqual(a.get("/api/audit", params={"date_from": "2099-01-01T00:00:00Z"}).json()["total"], 0)


@unittest.skipIf(TestClient is None, "fastapi kurulu değil")
class TargetsB6Test(_Base):
    _scan_setup = Phase2Test._scan_setup
    _upload = Phase2Test._upload

    def test_bulk_web_targets_and_options(self):
        from scakit.server import guard
        prev = guard.resolve
        guard.resolve = lambda h: ["93.184.215.14"] if h.endswith("acme.test") else prev(h)
        self.addCleanup(setattr, guard, "resolve", prev)
        a = self.client("admin@x.io")
        org = a.post("/api/orgs", json={"name": "A", "allowed_domains": ["*.acme.test"]}).json()
        a.post("/api/users", json={"email": "c@a.com", "password": PW, "role": "customer", "organization_id": org["id"]})
        c = self.client("c@a.com")
        p = c.post("/api/projects", json={"name": "P"}).json()
        r = c.post(f"/api/projects/{p['id']}/targets/bulk", json={"urls": ["portal.acme.test", "https://api.acme.test/",
                                                                          "evil.example.com", "portal.acme.test", "http://127.0.0.1/"],
                                                                 "options": {"delay": 2, "user_agent": "LeFureteur-Scan (izinli)"}}).json()
        self.assertEqual(sorted(t["name"] for t in r["created"]), ["api.acme.test", "portal.acme.test"])
        self.assertEqual(len(r["errors"]), 2)
        self.assertEqual(r["created"][0]["options"]["user_agent"], "LeFureteur-Scan (izinli)")
        again = c.post(f"/api/projects/{p['id']}/targets/bulk", json={"urls": ["portal.acme.test"]}).json()
        self.assertEqual((again["created"], again["errors"][0]["error"]), ([], "Bu adres projede zaten hedef olarak var"))
        self.assertEqual(c.post(f"/api/projects/{p['id']}/targets/bulk", json={"urls": ["x.acme.test"], "options": {"user_agent": "a\r\nX: y"}}).status_code, 400)
        self.assertEqual(c.post(f"/api/projects/{p['id']}/targets/bulk", json={"urls": ["x.acme.test"], "options": {"browser_tls": "netscape"}}).status_code, 400)
        if c.get("/api/meta").json()["browser_tls"]:
            r = c.post(f"/api/projects/{p['id']}/targets/bulk", json={"urls": ["tls.acme.test"], "options": {"browser_tls": "chrome"}}).json()
            self.assertEqual(r["created"][0]["options"]["browser_tls"], "chrome")
        for mode in ("auto", "off"):
            r = c.post(f"/api/projects/{p['id']}/targets/bulk", json={"urls": [f"{mode}.acme.test"], "options": {"browser_tls": mode}})
            self.assertEqual(r.status_code, 200)
        self.assertEqual(c.post(f"/api/projects/{p['id']}/targets", json={"name": "m", "kind": "upload", "options": {"type": "mobile"}}).status_code, 200)
        self.assertEqual(c.post(f"/api/projects/{p['id']}/targets", json={"name": "m", "kind": "upload", "options": {"type": "bozuk"}}).status_code, 400)
        self.assertEqual(c.post(f"/api/projects/{p['id']}/targets", json={"name": "m", "kind": "upload", "options": {"os": "Debian;rm"}}).status_code, 400)

    def test_multi_language_reports(self):
        a = self.client("admin@x.io")
        _org, p, t = self._scan_setup(a)
        r = a.patch(f"/api/projects/{p['id']}", json={"report_langs": ["en", "fr", "tr", "xx"]}).json()
        self.assertEqual(r["report_langs"], ["tr", "en", "fr"])
        a.post(f"/api/targets/{t['id']}/scans")
        self.run_worker()
        sid = a.get("/api/scans", params={"target_id": t["id"]}).json()[0]["id"]
        names = {x["name"] for x in a.get(f"/api/scans/{sid}/reports").json()}
        for n in ("rapor_tr.html", "report_en.html", "rapport_fr.html", "constats_fr.csv", "sbom.cdx.json"):
            self.assertIn(n, names)
        a.patch(f"/api/projects/{p['id']}", json={"report_lang": "de", "report_langs": []})
        self.assertEqual(a.post(f"/api/scans/{sid}/reports/regenerate").status_code, 200)
        self.run_worker()
        self.assertIn("bericht_de.html", {x["name"] for x in a.get(f"/api/scans/{sid}/reports").json()})


class WafDetectTest(unittest.TestCase):
    def test_waf_detected_locally(self):
        import http.server
        import threading
        from scakit.collectors.blackbox.web import scan_web

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                body = b"<html><title>Just a moment...</title><script src='/cdn-cgi/challenge-platform/x.js'></script></html>"
                self.send_response(403)
                self.send_header("Server", "cloudflare")
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        seen = []
        comps, notes = scan_web(f"http://127.0.0.1:{srv.server_address[1]}/", max_pages=3, delay=0.01, probe=False,
                                on_waf=seen.append)
        self.assertEqual(seen[0]["vendor"], "cloudflare")
        self.assertTrue(seen[0]["severe"])
        self.assertTrue(any("WAF" in n for n in notes))


@unittest.skipUnless(__import__("importlib").util.find_spec("curl_cffi"), "curl_cffi kurulu değil")
class BrowserTLSScanTest(unittest.TestCase):
    def test_scan_with_browser_tls(self):
        import http.server
        import threading
        from scakit.collectors.blackbox.web import scan_web
        uas = []

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                uas.append(self.headers.get("User-Agent", ""))
                if self.path.startswith("/js/"):
                    body, ct = b"/*! jQuery v1.12.4 | (c) jQuery Foundation | jquery.org/license */", "application/javascript"
                else:
                    body, ct = b"<html><script src='/js/jquery.min.js'></script></html>", "text/html"
                self.send_response(200)
                self.send_header("Content-Type", ct)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        comps, _notes = scan_web(f"http://127.0.0.1:{srv.server_address[1]}/", max_pages=2, delay=0.01, probe=False,
                                 browser_tls="chrome")
        self.assertIn(("jquery", "1.12.4"), {(c.name, c.version) for c in comps})
        self.assertTrue(uas and all("Chrome" in u for u in uas))

    def test_auto_switch_on_waf(self):
        import http.server
        import threading
        from scakit.collectors.blackbox.web import scan_web

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if "Chrome" not in self.headers.get("User-Agent", ""):
                    body, ct, st = b"<html><title>Just a moment...</title></html>", "text/html", 403
                elif self.path.startswith("/js/"):
                    body, ct, st = b"/*! jQuery v1.12.4 | (c) jQuery Foundation */", "application/javascript", 200
                else:
                    body, ct, st = b"<html><script src='/js/jquery.min.js'></script></html>", "text/html", 200
                self.send_response(st)
                if st == 403:
                    self.send_header("Server", "cloudflare")
                self.send_header("Content-Type", ct)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        url = f"http://127.0.0.1:{srv.server_address[1]}/"
        waf = []
        comps, _ = scan_web(url, max_pages=2, delay=0.01, probe=False, on_waf=waf.append)
        self.assertIn(("jquery", "1.12.4"), {(c.name, c.version) for c in comps})
        self.assertEqual(waf, [])
        waf = []
        comps, _ = scan_web(url, max_pages=2, delay=0.01, probe=False, on_waf=waf.append, browser_tls="off")
        self.assertTrue(waf and waf[0]["severe"] and waf[0]["browser_tls"] is None)


@unittest.skipIf(TestClient is None, "fastapi kurulu değil")
class SearchQueueTrendTest(_Base):
    _scan_setup = Phase2Test._scan_setup
    _upload = Phase2Test._upload

    def test_findings_search_filters_csv(self):
        a = self.client("admin@x.io")
        _org, p, t = self._scan_setup(a)
        a.post(f"/api/targets/{t['id']}/scans")
        self.run_worker()
        total = a.get("/api/findings").json()["total"]
        self.assertGreater(total, 0)
        for q in ("web-ui", "Acme", "Web lodash", "LODASH"):
            self.assertEqual(a.get("/api/findings", params={"q": q}).json()["total"], total, q)
        self.assertEqual(a.get("/api/findings", params={"q": "neova"}).json()["total"], 0)
        m = a.get("/api/findings", params={"q": "web-ui", "severity": "UNKNOWN"}).json()
        self.assertEqual([(x["name"], x["open"] > 0) for x in m["matched_targets"]], [("web-ui", True)])
        self.assertEqual(a.get("/api/findings", params={"q": "%"}).json()["total"], 0)
        item = a.get("/api/findings").json()["items"][0]
        self.assertEqual((item["target"], item["project"]), ("web-ui", "Web"))
        full = a.get(f"/api/findings/{item['id']}").json()
        alias = next((x for x in full["aliases"] if x != full["vuln_id"]), None)
        for term in filter(None, (full["vuln_id"], alias)):
            self.assertGreaterEqual(a.get("/api/findings", params={"q": term}).json()["total"], 1, term)
        self.assertEqual(a.get("/api/findings", params={"ecosystem": "npm", "has_fix": "true", "since_days": 1,
                                                         "target_kind": "upload"}).json()["total"], total)
        self.assertEqual(a.get("/api/findings", params={"target_kind": "web"}).json()["total"], 0)
        self.assertEqual(a.get("/api/findings/facets").json()["ecosystems"], ["npm"])
        r = a.get("/api/findings.csv", params={"q": "lodash"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.text.count("\n"), total + 1)
        self.assertIn("web-ui", r.text)

    def test_queue_priority_and_rules(self):
        from scakit.server import worker
        from scakit.server.db import SessionLocal
        from scakit.server.models import Job
        a = self.client("admin@x.io")
        org, p, t = self._scan_setup(a)
        ids = []
        for n in ("b", "c"):
            tt = a.post(f"/api/projects/{p['id']}/targets", json={"name": n, "kind": "upload"}).json()
            self._upload(a, tt["id"], "4.17.20")
            ids.append(tt["id"])
        jobs = [a.post(f"/api/targets/{x}/scans").json()["job"]["id"] for x in [t["id"]] + ids]
        q = a.get("/api/queue").json()
        self.assertEqual([x["job_id"] for x in q["queued"]], jobs)
        self.assertTrue(q["can_reorder"])
        self.assertEqual(a.post(f"/api/queue/{jobs[2]}/move", json={"to": "top"}).json()["position"], 1)
        self.assertEqual(a.post(f"/api/queue/{jobs[0]}/move", json={"to": "bottom"}).json()["position"], 3)
        self.assertEqual([x["job_id"] for x in a.get("/api/queue").json()["queued"]], [jobs[2], jobs[1], jobs[0]])
        self.assertEqual(a.post(f"/api/queue/{jobs[1]}/move", json={"to": "sideways"}).status_code, 422)
        db = SessionLocal()
        try:
            self.assertEqual(worker.claim(db).id, jobs[2])
        finally:
            db.close()
        a.post("/api/users", json={"email": "cu@a.com", "password": PW, "role": "customer", "organization_id": org["id"]})
        c = self.client("cu@a.com")
        self.assertEqual(c.post(f"/api/queue/{jobs[1]}/move", json={"to": "top"}).status_code, 403)
        self.assertFalse(c.get("/api/queue").json()["can_reorder"])
        self.assertEqual(a.put("/api/settings", json={"queue_concurrency": "99"}).status_code, 400)
        self.assertEqual(a.put("/api/settings", json={"queue_concurrency": "3", "queue_gap_seconds": "30"}).status_code, 200)
        self.assertEqual(a.get("/api/queue").json()["gap_seconds"], 30)

    def test_project_queue_rules(self):
        from datetime import datetime, timedelta, timezone
        from scakit.server import worker
        from scakit.server.db import SessionLocal
        from scakit.server.models import Job
        a = self.client("admin@x.io")
        org, p, t = self._scan_setup(a)
        ids = [t["id"]]
        for n in ("b", "c"):
            tt = a.post(f"/api/projects/{p['id']}/targets", json={"name": n, "kind": "upload"}).json()
            self._upload(a, tt["id"], "4.17.20")
            ids.append(tt["id"])
        p2 = a.post("/api/projects", json={"organization_id": org["id"], "name": "Diğer"}).json()
        o = a.post(f"/api/projects/{p2['id']}/targets", json={"name": "o", "kind": "upload"}).json()
        self._upload(a, o["id"], "4.17.20")
        r = a.post("/api/scans/batch", json={"target_ids": ids, "queue": {"priority": "normal", "parallel": 1, "gap": 60}}).json()
        self.assertEqual((len(r["started"]), r["errors"]), (3, []))
        other = a.post(f"/api/targets/{o['id']}/scans").json()["job"]["id"]
        db = SessionLocal()
        try:
            j1 = worker.claim(db)
            self.assertEqual(j1.queue_parallel, 1)
            j2 = worker.claim(db)
            self.assertEqual(j2.id, other)
            self.assertIsNone(worker.claim(db))
            j1.status, j1.finished_at = "done", datetime.now(timezone.utc)
            db.commit()
            self.assertIsNone(worker.claim(db))
            j1.finished_at = datetime.now(timezone.utc) - timedelta(seconds=61)
            db.commit()
            self.assertIsNotNone(worker.claim(db))
        finally:
            db.close()
        self.assertEqual(a.patch(f"/api/projects/{p2['id']}", json={"queue_policy": {"parallel": 99}}).status_code, 400)
        self.assertEqual(a.patch(f"/api/projects/{p2['id']}", json={"queue_policy": {"priority": "low", "parallel": 2, "gap": 5}}).status_code, 200)
        self.assertEqual(a.get(f"/api/projects/{p2['id']}").json()["queue_policy"], {"priority": "low", "parallel": 2, "gap": 5})
        a.post("/api/users", json={"email": "cq@a.com", "password": PW, "role": "customer", "organization_id": org["id"]})
        c = self.client("cq@a.com")
        self.assertEqual(c.patch(f"/api/projects/{p2['id']}", json={"queue_policy": {"priority": "high"}}).status_code, 403)
        self.assertEqual(c.post("/api/scans/batch", json={"target_ids": [o["id"]], "queue": {"priority": "high"}}).status_code, 403)
        r = c.post("/api/scans/batch", json={"target_ids": [o["id"]], "queue": {"priority": "normal", "parallel": 3, "gap": 0},
                                             "save_default": True}).json()
        self.assertEqual(r["errors"][0]["error"], "Bu hedef için zaten bekleyen / çalışan bir tarama var")
        self.assertEqual(a.get(f"/api/projects/{p2['id']}").json()["queue_policy"]["parallel"], 3)

    def test_bulk_schedule_and_trends(self):
        a = self.client("admin@x.io")
        _org, p, t = self._scan_setup(a)
        a.post(f"/api/projects/{p['id']}/targets", json={"name": "b", "kind": "upload"})
        r = a.post(f"/api/projects/{p['id']}/schedules", json={"cron": "0 9-18/3 * * 1-5", "target_kind": "all"}).json()
        self.assertEqual((r["created"], r["skipped"]), (2, 0))
        r = a.post(f"/api/projects/{p['id']}/schedules", json={"cron": "0 9-18/3 * * 1-5", "target_kind": "all"}).json()
        self.assertEqual((r["created"], r["skipped"]), (0, 2))
        r = a.post(f"/api/projects/{p['id']}/schedules", json={"cron": "0 2 * * 1,4", "target_kind": "upload", "replace": True}).json()
        self.assertEqual((r["created"], r["replaced"]), (2, 2))
        self.assertEqual(len(a.get("/api/schedules", params={"project_id": p["id"]}).json()), 2)
        self.assertEqual(a.post(f"/api/projects/{p['id']}/schedules", json={"cron": "*/5 * * * *"}).status_code, 400)
        self.assertEqual(a.delete(f"/api/projects/{p['id']}/schedules").json()["deleted"], 2)
        a.post(f"/api/targets/{t['id']}/scans")
        self.run_worker()
        for bucket in ("hour", "day", "week"):
            tr = a.get("/api/trends", params={"project_id": p["id"], "bucket": bucket, "periods": 4}).json()
            self.assertEqual(len(tr["items"]), 4)
            last = tr["items"][-1]
            self.assertEqual(last["scans"], 1)
            self.assertGreater(last["open"], 0)
            self.assertEqual(last["delta_open"], last["open"])
            self.assertEqual(last["new"], last["open"])
        self.assertEqual(a.get("/api/trends", params={"bucket": "year"}).status_code, 422)


@unittest.skipIf(TestClient is None, "fastapi kurulu değil")
class AccessDiagnosticsServerTest(_Base):
    _scan_setup = Phase2Test._scan_setup
    _upload = Phase2Test._upload

    def test_egress_settings_and_options(self):
        a = self.client("admin@x.io")
        self.assertEqual(a.put("/api/settings", json={"egress_proxies": "TR=ftp://x"}).status_code, 400)
        self.assertEqual(a.put("/api/settings", json={"egress_proxies": "auto=http://1.2.3.4:3128"}).status_code, 400)
        self.assertEqual(a.put("/api/settings", json={"egress_proxies": "TR=socks5://u:gizli@1.2.3.4:1080; DE=http://5.6.7.8:3128"}).status_code, 200)
        m = a.get("/api/meta").json()
        self.assertEqual(m["egress"], ["TR", "DE"])
        self.assertNotIn("gizli", json.dumps(a.get("/api/settings").json()))
        org = a.post("/api/orgs", json={"name": "O"}).json()
        p = a.post("/api/projects", json={"organization_id": org["id"], "name": "P"}).json()
        r = a.post(f"/api/projects/{p['id']}/targets", json={"name": "u", "kind": "upload"})
        self.assertEqual(r.status_code, 200)
        from scakit.server import guard
        prev = guard.resolve
        guard.resolve = lambda h: ["93.184.215.14"]
        self.addCleanup(setattr, guard, "resolve", prev)
        r = a.post(f"/api/projects/{p['id']}/targets", json={"name": "w", "kind": "web", "url": "https://x.example.com",
                                                             "options": {"egress": "TR"}})
        self.assertEqual(r.json()["options"]["egress"], "TR")
        bad = a.post(f"/api/projects/{p['id']}/targets", json={"name": "w2", "kind": "web", "url": "https://y.example.com",
                                                               "options": {"egress": "../x"}})
        self.assertEqual(bad.status_code, 400)

    def test_empty_upload_diagnosed(self):
        a = self.client("admin@x.io")
        _org, p, t = self._scan_setup(a)
        tt = a.post(f"/api/projects/{p['id']}/targets", json={"name": "bos", "kind": "upload", "options": {"type": "source"}}).json()
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("README.md", "merhaba")
        a.post(f"/api/targets/{tt['id']}/files", files={"file": ("src.zip", buf.getvalue())})
        sid = a.post(f"/api/targets/{tt['id']}/scans").json()["id"]
        self.run_worker()
        sm = a.get(f"/api/scans/{sid}").json()["summary"]
        self.assertEqual((sm["access"]["issue"], sm["access"]["type"]), ("empty_input", "source"))


@unittest.skipIf(TestClient is None, "fastapi kurulu değil")
class MultiJiraTest(_Base):
    _scan_setup = Phase2Test._scan_setup
    _upload = Phase2Test._upload

    def test_instances_permissions_and_choice(self):
        from scakit.server import jira
        calls = []

        class R:
            def __init__(self, code, body):
                self.status_code, self._b, self.text, self.content = code, body, json.dumps(body), b"x"

            def json(self):
                return self._b

        def fake(method, url, cfg, json_body=None):
            calls.append((url, cfg["token"]))
            if url.endswith("/myself"):
                return R(200, {"displayName": "Bot"})
            if "/project/" in url:
                return R(200, {"key": url.rsplit("/", 1)[1], "name": "Proje"})
            return R(201, {"key": f"{json_body['fields']['project']['key']}-{len(calls)}"})
        orig = jira._request
        jira._request = fake
        self.addCleanup(setattr, jira, "_request", orig)
        a = self.client("admin@x.io")
        org, p, t = self._scan_setup(a)
        other = a.post("/api/orgs", json={"name": "Başka"}).json()
        a.post("/api/users", json={"email": "cu@a.com", "password": PW, "role": "customer", "organization_id": org["id"]})
        a.post("/api/users", json={"email": "an@a.com", "password": PW, "role": "analyst"})
        tids = [t["id"]]
        for n in ("b", "c"):
            tt = a.post(f"/api/projects/{p['id']}/targets", json={"name": n, "kind": "upload"}).json()
            self._upload(a, tt["id"], "4.17.20")
            tids.append(tt["id"])
        for x in tids:
            a.post(f"/api/targets/{x}/scans")
        self.run_worker()
        base = {"url": "https://acme.atlassian.net", "user": "bot@acme.test", "token": "gizli-1", "project_key": "ACME"}
        j1 = a.post("/api/jira/instances", json={**base, "name": "Acme Jira", "roles": ["admin", "analyst", "customer"],
                                                 "org_ids": [org["id"]]}).json()
        j2 = a.post("/api/jira/instances", json={**base, "name": "İç Jira", "url": "https://jira.ic.test", "token": "gizli-2",
                                                 "project_key": "SEC", "roles": ["admin", "analyst"]}).json()
        j3 = a.post("/api/jira/instances", json={**base, "name": "Başka müşteri", "token": "gizli-3", "project_key": "OTH",
                                                 "roles": ["admin", "analyst", "customer"], "org_ids": [other["id"]]}).json()
        self.assertEqual(a.post("/api/jira/instances", json={**base, "name": "Acme Jira"}).status_code, 400)
        self.assertEqual(a.post("/api/jira/instances", json={**base, "name": "x", "url": "file:///etc"}).status_code, 400)
        self.assertEqual(a.post("/api/jira/instances", json={**base, "name": "y", "roles": ["root"]}).status_code, 400)
        everything = json.dumps(a.get("/api/jira/instances").json())
        self.assertNotIn("gizli", everything)
        self.assertEqual(a.post("/api/jira/test", json={"instance_id": j2["id"]}).json()["user"], "Bot")
        c, an = self.client("cu@a.com"), self.client("an@a.com")
        self.assertEqual([i["name"] for i in c.get("/api/jira/instances").json()], ["Acme Jira"])
        self.assertNotIn("url", c.get("/api/jira/instances").json()[0])
        self.assertEqual(c.post("/api/jira/instances", json={**base, "name": "z"}).status_code, 403)
        self.assertEqual(c.post(f"/api/jira/test", json={"instance_id": j1["id"]}).status_code, 403)
        fids = [a.get("/api/findings", params={"target_id": x}).json()["items"][0]["id"] for x in tids]
        fid = fids[0]
        r = c.post(f"/api/findings/{fid}/jira", json={"instance_id": j2["id"]})
        self.assertEqual(r.status_code, 400)
        r = c.post(f"/api/findings/{fid}/jira", json={"instance_id": j3["id"]})
        self.assertEqual(r.status_code, 400)
        r = an.post(f"/api/findings/{fid}/jira")
        self.assertEqual(r.status_code, 400)
        self.assertIn("seçin", r.json()["detail"])
        r = an.post(f"/api/findings/{fid}/jira", json={"instance_id": j2["id"]}).json()
        self.assertTrue(r["key"].startswith("SEC-"))
        self.assertEqual(calls[-1][1], "gizli-2")
        fid2 = fids[1]
        r = c.post(f"/api/findings/{fid2}/jira").json()
        self.assertTrue(r["key"].startswith("ACME-"))
        a.put(f"/api/jira/instances/{j2['id']}", json={**base, "name": "İç Jira", "url": "https://jira.ic.test", "token": None,
                                                       "project_key": "SEC", "roles": ["admin", "analyst"], "user_ids": [1]})
        self.assertNotIn("İç Jira", [i["name"] for i in an.get("/api/jira/instances").json()])
        self.assertEqual(c.patch(f"/api/projects/{p['id']}", json={"jira_instance_id": j2["id"]}).status_code, 400)
        a.patch(f"/api/projects/{p['id']}", json={"jira_instance_id": j1["id"]})
        fid3 = fids[2]
        self.assertTrue(an.post(f"/api/findings/{fid3}/jira").json()["key"].startswith("ACME-"))
        self.assertEqual(a.delete(f"/api/jira/instances/{j1['id']}").status_code, 200)
        self.assertIsNone(a.get(f"/api/projects/{p['id']}").json()["jira_instance_id"])


@unittest.skipIf(TestClient is None, "fastapi kurulu değil")
class CliPackageTest(_Base):
    def test_download_package(self):
        import tarfile
        a = self.client("admin@x.io")
        r = a.get("/api/cli/scakit.tar.gz")
        self.assertEqual(r.status_code, 200)
        names = tarfile.open(fileobj=io.BytesIO(r.content), mode="r:gz").getnames()
        base = names[0].split("/")[0]
        self.assertIn(f"{base}/pyproject.toml", names)
        self.assertIn(f"{base}/scakit/cli.py", names)
        self.assertFalse(any("__pycache__" in n or n.endswith(".pyc") for n in names))
        self.assertTrue(all(n.startswith(base + "/") and ".." not in n for n in names))
        org = a.post("/api/orgs", json={"name": "O"}).json()
        a.post("/api/users", json={"email": "cu@a.com", "password": PW, "role": "customer", "organization_id": org["id"]})
        self.assertEqual(self.client("cu@a.com").get("/api/cli/scakit.tar.gz").status_code, 403)


@unittest.skipIf(TestClient is None, "fastapi kurulu değil")
class CrossTenantNewEndpointsTest(_Base):
    _scan_setup = Phase2Test._scan_setup
    _upload = Phase2Test._upload

    def test_isolation(self):
        a = self.client("admin@x.io")
        org_b, p_b, t_b = self._scan_setup(a)
        a.post(f"/api/targets/{t_b['id']}/scans")
        self.run_worker()
        a.post(f"/api/targets/{t_b['id']}/scans")
        org_a = a.post("/api/orgs", json={"name": "Acme-A"}).json()
        a.post("/api/users", json={"email": "ca@a.com", "password": PW, "role": "customer", "organization_id": org_a["id"]})
        c = self.client("ca@a.com")
        p_a = c.post("/api/projects", json={"name": "PA"}).json()
        self.assertEqual(c.get("/api/findings", params={"q": "web-ui"}).json()["total"], 0)
        self.assertEqual(c.get("/api/findings", params={"q": "web-ui"}).json().get("matched_targets", []), [])
        self.assertNotIn("web-ui", c.get("/api/findings.csv").text)
        self.assertEqual(c.get("/api/findings/facets").json()["ecosystems"], [])
        self.assertEqual(c.get("/api/queue").json()["queued"], [])
        self.assertIn(c.get("/api/trends", params={"project_id": p_b["id"]}).status_code, (403, 404))
        self.assertIn(c.get("/api/trends", params={"target_id": t_b["id"]}).status_code, (403, 404))
        self.assertEqual(sum(x["open"] for x in c.get("/api/trends").json()["items"]), 0)
        self.assertIn(c.post("/api/scans/batch", json={"target_ids": [t_b["id"]]}).status_code, (403, 404))
        self.assertIn(c.post(f"/api/projects/{p_b['id']}/schedules", json={"cron": "0 2 * * 1"}).status_code, (403, 404))
        self.assertIn(c.delete(f"/api/projects/{p_b['id']}/schedules").status_code, (403, 404))
        self.assertIn(c.get("/api/schedules", params={"project_id": p_b["id"]}).status_code, (403, 404))
        self.assertIn(c.patch(f"/api/projects/{p_b['id']}", json={"queue_policy": {"parallel": 1}}).status_code, (403, 404))
        self.assertIn(c.post(f"/api/targets/{t_b['id']}/capture-ticket").status_code, (403, 404))
        self.assertIn(c.get(f"/api/targets/{t_b['id']}/capture-status").status_code, (403, 404))
        job_b = a.get("/api/queue").json()["queued"][0]["job_id"]
        self.assertEqual(c.post(f"/api/queue/{job_b}/move", json={"to": "bottom"}).status_code, 403)
        self.assertEqual(c.get("/api/cli/scakit.tar.gz").status_code, 403)
        self.assertEqual(c.post("/api/jira/instances", json={"name": "x", "url": "https://j.test"}).status_code, 403)
        self.assertEqual(c.put("/api/settings", json={"egress_proxies": "X=http://1.2.3.4:1"}).status_code, 403)
        self.assertNotIn("egress_proxies", json.dumps(c.get("/api/meta").json()))
        self.assertEqual(c.get("/api/findings", params={"project_id": p_a["id"]}).json()["total"], 0)


@unittest.skipIf(TestClient is None, "fastapi kurulu değil")
class BulkDeleteTest(_Base):
    _scan_setup = Phase2Test._scan_setup
    _upload = Phase2Test._upload

    def test_permissions_preview_and_delete(self):
        from scakit.server.config import get_config
        a = self.client("admin@x.io")
        org, p, t = self._scan_setup(a)
        sid = a.post(f"/api/targets/{t['id']}/scans").json()["id"]
        self.run_worker()
        queued = a.post(f"/api/targets/{t['id']}/scans").json()["id"]
        self.assertTrue((get_config().scans_dir / str(sid)).exists())
        a.post("/api/users", json={"email": "an@a.com", "password": PW, "role": "analyst"})
        an_id = next(u["id"] for u in a.get("/api/users").json() if u["email"] == "an@a.com")
        an = self.client("an@a.com")
        body = {"kind": "scans", "ids": [sid, queued]}
        self.assertEqual(an.post("/api/bulk/preview", json=body).status_code, 403)
        self.assertEqual(an.post("/api/bulk/delete", json=body).status_code, 403)
        self.assertEqual(a.patch(f"/api/users/{an_id}", json={"permissions": ["root"]}).status_code, 400)
        self.assertEqual(a.patch(f"/api/users/{an_id}", json={"permissions": ["bulk_delete"]}).json()["permissions"], ["bulk_delete"])
        self.assertEqual(an.post("/api/bulk/preview", json=body).json()["counts"], {"scans": 2, "active": 1})
        r = an.post("/api/bulk/delete", json=body).json()
        self.assertEqual(r["deleted"], [sid])
        self.assertEqual(r["errors"][0]["id"], queued)
        self.assertFalse((get_config().scans_dir / str(sid)).exists())
        self.assertEqual(an.delete(f"/api/scans/{queued}").status_code, 409)
        other = a.post("/api/orgs", json={"name": "B"}).json()
        a.post("/api/users", json={"email": "cb@b.com", "password": PW, "role": "customer", "organization_id": other["id"]})
        cb_id = next(u["id"] for u in a.get("/api/users").json() if u["email"] == "cb@b.com")
        a.patch(f"/api/users/{cb_id}", json={"permissions": ["bulk_delete"]})
        cb = self.client("cb@b.com")
        own = cb.post("/api/projects", json={"name": "Kendi"}).json()
        r = cb.post("/api/bulk/delete", json={"kind": "projects", "ids": [p["id"], own["id"]]}).json()
        self.assertEqual((r["deleted"], r["errors"][0]["id"]), ([own["id"]], p["id"]))
        self.assertEqual(a.get(f"/api/projects/{p['id']}").status_code, 200)
        pv = a.post("/api/bulk/preview", json={"kind": "projects", "ids": [p["id"]]}).json()["counts"]
        self.assertEqual((pv["projects"], pv["targets"], pv["scans"]), (1, 1, 1))
        self.assertGreater(pv["findings"], 0)
        a.post("/api/bulk/delete", json={"kind": "projects", "ids": [p["id"]]})
        self.assertEqual(a.get(f"/api/projects/{p['id']}").status_code, 404)
        self.assertEqual(a.post("/api/bulk/delete", json={"kind": "users", "ids": [1]}).status_code, 422)


@unittest.skipIf(TestClient is None, "fastapi kurulu değil")
class ScanDuplicateTest(_Base):
    _scan_setup = Phase2Test._scan_setup
    _upload = Phase2Test._upload

    def test_duplicates_and_locations(self):
        a = self.client("admin@x.io")
        _org, p, t = self._scan_setup(a)
        for _ in range(2):
            a.post(f"/api/targets/{t['id']}/scans")
            self.run_worker()
        self._upload(a, t["id"], "4.17.21")
        a.post(f"/api/targets/{t['id']}/scans")
        self.run_worker()
        scans = sorted(a.get("/api/scans", params={"target_id": t["id"]}).json(), key=lambda x: x["id"])
        self.assertNotIn("duplicate_of", scans[0])
        self.assertEqual((scans[1]["duplicate_of"], scans[1]["same_input"]), (scans[0]["id"], True))
        self.assertNotIn("duplicate_of", scans[2])
        self.assertEqual(a.get(f"/api/scans/{scans[1]['id']}").json()["duplicate_of"], scans[0]["id"])
        items = a.get("/api/findings", params={"target_id": t["id"], "evidence": "true", "status": "open,fixed"}).json()["items"]
        loc = items[0]["locations"][0]
        self.assertEqual(loc["location"], "web/package-lock.json")
        self.assertTrue(loc["line"])


@unittest.skipIf(TestClient is None, "fastapi kurulu değil")
class PurgeTest(_Base):
    _scan_setup = Phase2Test._scan_setup
    _upload = Phase2Test._upload

    def test_deleted_project_leaves_no_files(self):
        from scakit.server.config import get_config
        a = self.client("admin@x.io")
        _org, p, t = self._scan_setup(a)
        a.post(f"/api/targets/{t['id']}/scans")
        self.run_worker()
        sid = a.get("/api/scans", params={"target_id": t["id"]}).json()[0]["id"]
        cfg = get_config()
        self.assertTrue((cfg.scans_dir / str(sid)).exists() and (cfg.uploads_dir / str(t["id"])).exists())
        a.delete(f"/api/projects/{p['id']}")
        self.assertFalse((cfg.scans_dir / str(sid)).exists())
        self.assertFalse((cfg.uploads_dir / str(t["id"])).exists())


@unittest.skipIf(TestClient is None, "fastapi kurulu değil")
class SettingsValidationTest(_Base):
    def test_validation_and_tests(self):
        a = self.client("admin@x.io")
        bad = {"smtp_from": "a@b.com\r\nBcc: x@evil.com", "timezone": "Mars/Base", "web_default_max_pages": "9999",
               "public_url": "javascript:alert(1)", "smtp_security": "plain", "oidc_issuer": "http://idp.example.com",
               "web_default_delay": "abc", "jira_project_key": "bad key"}
        r = a.put("/api/settings", json=bad)
        self.assertEqual(r.status_code, 400)
        self.assertEqual(set(r.json()["detail"]["fields"]), set(bad))
        r = a.put("/api/settings", json={"timezone": "Europe/Paris", "web_default_delay": "1,5", "public_url": "https://lf.acme.test/",
                                         "approval_required": "true", "jira_project_key": "sec"}).json()
        vals = {x["key"]: x["value"] for x in r}
        self.assertEqual((vals["web_default_delay"], vals["public_url"], vals["approval_required"], vals["jira_project_key"]),
                         ("1.5", "https://lf.acme.test", "1", "SEC"))
        a.put("/api/settings", json={"smtp_password": "s3cret"})
        a.put("/api/settings", json={"smtp_password": ""})
        db0 = __import__("scakit.server.db", fromlist=["x"]).SessionLocal()
        self.assertEqual(__import__("scakit.server.settings_store", fromlist=["x"]).get(db0, "smtp_password"), "s3cret"); db0.close()
        a.put("/api/settings", json={"smtp_password": "", "_clear": ["smtp_password"]})
        a.put("/api/settings", json={"smtp_password": "s3cret"})
        from scakit.server import settings_store
        from scakit.server.db import SessionLocal
        db = SessionLocal()
        self.assertEqual(settings_store.get(db, "smtp_password"), "s3cret")
        db.close()
        self.assertIn("SMTP", a.post("/api/settings/smtp/test").json()["detail"])
        a.put("/api/settings", json={"smtp_host": "mail.acme.test", "smtp_port": "2525", "smtp_security": "none", "smtp_from": "lf@acme.test"})
        sent = []
        from unittest import mock

        class FakeSMTP:
            def __init__(self, *a, **k): pass
            def login(self, *a): pass
            def send_message(self, m): sent.append(m)
            def quit(self): pass
        with mock.patch("smtplib.SMTP", FakeSMTP):
            r = a.post("/api/settings/smtp/test").json()
        self.assertEqual(r["to"], "admin@x.io")
        self.assertEqual(sent[0]["To"], "admin@x.io")
        self.assertEqual(a.post("/api/settings/oidc/test").status_code, 400)


@unittest.skipIf(TestClient is None, "fastapi kurulu değil")
class NotifySecretLeakTest(_Base):
    def test_channel_error_hides_webhook_token(self):
        a = self.client("admin@x.io")
        c = a.post("/api/notifications", json={"name": "S", "kind": "slack", "config": {"url": "https://hooks.slack.invalid/services/T0/B0/SUPERSECRETTOKEN"},
                                               "events": ["scan_done"]}).json()
        r = a.post(f"/api/notifications/{c['id']}/test")
        self.assertEqual(r.status_code, 400)
        self.assertNotIn("SUPERSECRET", r.text)
        self.assertNotIn("SUPERSECRET", json.dumps(a.get("/api/notifications").json()))


def _har(entries):
    return json.dumps({"log": {"version": "1.2", "creator": {"name": "test"}, "entries": [
        {"request": {"method": "GET", "url": u, "headers": [{"name": "Cookie", "value": "session=SECRETCOOKIE"},
                                                          {"name": "Authorization", "value": "Bearer SECRETTOKEN"}],
                     "cookies": [{"name": "session", "value": "SECRETCOOKIE"}], "postData": {"text": "password=SECRETPW"}},
         "response": {"status": st, "headers": [{"name": "Content-Type", "value": ct}, {"name": "Set-Cookie", "value": "x=SECRETSET"}],
                      "content": {"mimeType": ct, "text": body}}} for u, st, ct, body in entries]}})


TRAFFIC = [("https://shop.acme.test/", 200, "text/html; charset=utf-8",
            '<html><head><script src="/static/jquery.min.js"></script><script src="https://cdn.jsdelivr.net/npm/lodash@4.17.15/lodash.min.js"></script></head><body><a href="/about">x</a></body></html>'),
           ("https://shop.acme.test/static/jquery.min.js", 200, "application/javascript",
            "/*! jQuery v1.12.4 | (c) jQuery Foundation | jquery.org/license */\n!function(a,b){}(window);"),
           ("https://shop.acme.test/about", 301, "text/html", "")]


class TrafficImportTest(unittest.TestCase):
    def test_offline_har_and_burp(self):
        import base64
        import tempfile
        from unittest import mock
        from scakit.collectors.blackbox import traffic
        d = Path(tempfile.mkdtemp())
        har = d / "site.har"
        har.write_text(_har(TRAFFIC))
        with mock.patch("requests.Session.get", side_effect=AssertionError("ağa çıkılmamalı")), \
                mock.patch("requests.Session.request", side_effect=AssertionError("ağa çıkılmamalı")):
            comps, _notes = traffic.scan_traffic(str(har), target="shop")
        names = {(c.name.lower(), c.version) for c in comps}
        self.assertIn(("jquery", "1.12.4"), names)
        self.assertIn(("lodash", "4.17.15"), names)
        self.assertTrue(traffic.sanitize_upload(har))
        txt = har.read_text()
        for s in ("SECRETCOOKIE", "SECRETTOKEN", "SECRETPW", "SECRETSET"):
            self.assertNotIn(s, txt)
        raw = (b"HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\nSet-Cookie: s=SECRETSET\r\n\r\n"
               b"/*! jQuery v1.12.4 | (c) jQuery Foundation | jquery.org/license */")
        burp = d / "burp.xml"
        burp.write_text('<?xml version="1.0"?>\n<!DOCTYPE items [\n<!ELEMENT items (item*)>\n<!ATTLIST items burpVersion CDATA "">\n]>\n'
                        f'<items burpVersion="2024.1"><item><url><![CDATA[https://shop.acme.test/j.js]]></url>'
                        f'<request base64="true">{base64.b64encode(b"GET /j.js HTTP/1.1").decode()}</request>'
                        f'<response base64="true">{base64.b64encode(raw).decode()}</response></item></items>')
        self.assertEqual(traffic.sniff(burp), "burp")
        self.assertTrue(traffic.sanitize_upload(burp))
        self.assertEqual(traffic.sniff(burp), "har")
        self.assertNotIn("SECRETSET", burp.read_text())
        evil = d / "evil.xml"
        evil.write_text('<?xml version="1.0"?><!DOCTYPE items [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;">]><items burpVersion="1">&b;</items>')
        from scakit.safeio import UnsafeInput
        with self.assertRaises(UnsafeInput):
            traffic.load(evil)


@unittest.skipIf(TestClient is None, "fastapi kurulu değil")
class TrafficServerTest(_Base):
    def test_upload_sanitized_and_scanned(self):
        a = self.client("admin@x.io")
        a.put("/api/settings", json={"vulndb_path": str(self.dbpath)})
        org = a.post("/api/orgs", json={"name": "A"}).json()
        p = a.post("/api/projects", json={"organization_id": org["id"], "name": "P"}).json()
        t = a.post(f"/api/projects/{p['id']}/targets", json={"name": "shop (HAR)", "kind": "upload", "options": {"type": "traffic"}}).json()
        r = a.post(f"/api/targets/{t['id']}/files", files={"file": ("site.har", _har(TRAFFIC).encode())})
        self.assertEqual(r.status_code, 200)
        from scakit.server.config import get_config
        sf = a.get(f"/api/targets/{t['id']}").json()["files"][0]["stored"]
        stored = (get_config().uploads_dir / str(t["id"]) / sf).read_text()
        self.assertNotIn("SECRETCOOKIE", stored)
        a.post(f"/api/targets/{t['id']}/scans")
        self.run_worker()
        s = a.get("/api/scans", params={"target_id": t["id"]}).json()[0]
        self.assertEqual(s["job"]["status"], "done")
        self.assertGreaterEqual(s["summary"]["components"], 2)
        bad = a.post(f"/api/targets/{t['id']}/files", files={"file": ("x.xml", b'<!DOCTYPE items [<!ENTITY a "x">]><items burpVersion="1"/>')})
        self.assertEqual(bad.status_code, 400)


@unittest.skipIf(TestClient is None, "fastapi kurulu değil")
class CaptureTicketTest(_Base):
    def test_ticket_flow_and_limits(self):
        from datetime import datetime, timedelta, timezone
        from fastapi.testclient import TestClient as TC
        from scakit.server import guard
        prev = guard.resolve
        guard.resolve = lambda h: ["93.184.215.14"] if h.endswith("acme.test") else prev(h)
        self.addCleanup(setattr, guard, "resolve", prev)
        from scakit.server.app import create_app
        a = self.client("admin@x.io")
        a.put("/api/settings", json={"vulndb_path": str(self.dbpath)})
        org = a.post("/api/orgs", json={"name": "A", "allowed_domains": ["*.acme.test"]}).json()
        ob = a.post("/api/orgs", json={"name": "B"}).json()
        a.post("/api/users", json={"email": "c@a.com", "password": PW, "role": "customer", "organization_id": org["id"]})
        a.post("/api/users", json={"email": "d@b.com", "password": PW, "role": "customer", "organization_id": ob["id"]})
        c, d = self.client("c@a.com"), self.client("d@b.com")
        p = c.post("/api/projects", json={"name": "P"}).json()
        web = c.post(f"/api/projects/{p['id']}/targets", json={"name": "shop", "kind": "web", "url": "https://shop.acme.test/",
                                                               "options": {"waf_assist": True}}).json()
        self.assertTrue(web["options"]["waf_assist"])
        self.assertEqual(d.post(f"/api/targets/{web['id']}/capture-ticket").status_code, 404)
        tk = c.post(f"/api/targets/{web['id']}/capture-ticket").json()["ticket"]
        raw = TC(create_app())
        self.assertEqual(raw.get("/api/capture/info").status_code, 401)
        self.assertEqual(raw.get("/api/capture/info", headers={"Authorization": "Bearer lfc_yanlis"}).status_code, 401)
        info = raw.get("/api/capture/info", headers={"Authorization": f"Bearer {tk}"}).json()
        self.assertEqual(info["url"], "https://shop.acme.test/")
        self.assertGreaterEqual(info["delay"], 1.0)
        h = {"Authorization": f"Bearer {tk}"}
        self.assertEqual(raw.post("/api/capture/upload", headers=h, files={"file": ("x.har", b"not json")}).status_code, 400)
        r = raw.post("/api/capture/upload", headers=h, files={"file": ("capture.har", _har(TRAFFIC).encode())})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(raw.post("/api/capture/upload", headers=h, files={"file": ("capture.har", _har(TRAFFIC).encode())}).status_code, 409)
        self.run_worker()
        s = c.get(f"/api/scans/{r.json()['scan_id']}").json()
        self.assertEqual(s["job"]["status"], "done")
        self.assertIn("tarayıcı kaydı", s["target"])
        st = c.get(f"/api/targets/{web['id']}/capture-status").json()["ticket"]
        self.assertEqual(st["result_scan_id"], r.json()["scan_id"])
        tk2 = c.post(f"/api/targets/{web['id']}/capture-ticket").json()["ticket"]
        from scakit.server.db import SessionLocal
        from scakit.server.models import CaptureTicket
        db = SessionLocal()
        row = db.query(CaptureTicket).order_by(CaptureTicket.id.desc()).first()
        row.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        db.commit(); db.close()
        self.assertEqual(raw.get("/api/capture/info", headers={"Authorization": f"Bearer {tk2}"}).status_code, 401)
        tk3 = c.post(f"/api/targets/{web['id']}/capture-ticket").json()["ticket"]
        uid = next(u["id"] for u in a.get("/api/users").json() if u["email"] == "c@a.com")
        a.patch(f"/api/users/{uid}", json={"active": False})
        self.assertEqual(raw.get("/api/capture/info", headers={"Authorization": f"Bearer {tk3}"}).status_code, 401)
        self.assertIn("lfc_", "lfc_") and self.assertIn("playwright", raw.get("/api/capture/helper.py").text.lower())
