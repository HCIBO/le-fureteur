import hashlib, hmac, json, sys, time, urllib.request
from playwright.sync_api import sync_playwright
S = sys.argv[1]; B = "http://localhost:8812"; LOG = f"{S}/b8/mock.log"; R = {}
def mock():
    try: return [json.loads(l) for l in open(LOG)]
    except FileNotFoundError: return []
def mailpit():
    return json.loads(urllib.request.urlopen("http://127.0.0.1:8025/api/v1/messages").read())["messages"]
def check(name, cond, info=""):
    R[name] = bool(cond); print(("OK  " if cond else "FAIL"), name, info if not cond else "")
with sync_playwright() as p:
    b = p.chromium.launch()
    ctx = b.new_context(viewport={"width": 1400, "height": 950}); ctx.add_init_script("try { localStorage.setItem('lf_lang', 'tr') } catch (e) {}")
    pg = ctx.new_page(); pg.goto(B + "/login"); pg.fill("input[autocomplete=username]", "admin@test.local"); pg.fill("input[type=password]", "Deneme-Parola-2026")
    pg.click("button[type=submit]"); pg.wait_for_url(B + "/")
    tok = next(c["value"] for c in ctx.cookies() if "csrf" in c["name"])
    H = {"X-CSRF-Token": tok}
    def call(m, path, data=None):
        r = ctx.request.fetch(B + "/api" + path, method=m, data=data, headers=H); 
        try: return r.status, r.json()
        except Exception: return r.status, r.text()
    st, _ = call("PUT", "/settings", {"public_url": "http://localhost:8812", "smtp_host": "127.0.0.1", "smtp_port": "1025", "smtp_security": "none", "smtp_user": "", "smtp_from": "lefureteur@acme.test",
        "oidc_enabled": "1", "oidc_issuer": "http://localhost:8180/realms/lefureteur", "oidc_client_id": "le-fureteur", "oidc_client_secret": "kc-test-secret-only", "oidc_button_label": "Acme kurumsal hesabı",
        "jira_url": "http://127.0.0.1:8899", "jira_auth": "cloud", "jira_user": "bot@acme.test", "jira_token": "jira-test-token", "jira_project_key": "SEC", "jira_auto_min_severity": "", "jira_comment_on_fix": "1"})
    check("settings saved", st == 200)
    st, r = call("POST", "/settings/smtp/test"); time.sleep(1)
    msgs = mailpit()
    check("smtp test (Mailpit)", st == 200 and any("SMTP deneme" in m["Subject"] and m["To"][0]["Address"] == "admin@test.local" for m in msgs), (st, r))
    st, r = call("POST", "/settings/oidc/test")
    check("oidc test (Keycloak)", st == 200 and r.get("keys", 0) >= 1, (st, r))
    st, r = call("POST", "/jira/test")
    check("jira test", st == 200 and r.get("user") == "Jira Bot" and "SEC" in r.get("project", ""), (st, r))
    fid = call("GET", "/findings?target_id=10&size=1")[1]["items"][0]["id"]
    st, r = call("POST", f"/findings/{fid}/jira")
    js = [x for x in mock() if x["path"] == "/rest/api/2/issue"]
    body = json.loads(js[-1]["body"]) if js else {}
    check("jira issue created", st == 200 and r.get("key", "").startswith("SEC-") and body.get("fields", {}).get("project", {}).get("key") == "SEC"
          and js[-1]["headers"].get("Authorization", "").startswith("Basic "), (st, r))
    for c in call("GET", "/notifications")[1]:
        call("DELETE", f"/notifications/{c['id']}")
    ev = ["scan_done", "new_findings", "kev", "scan_failed"]
    ids = {}
    for kind, cfg in (("slack", {"url": "http://127.0.0.1:8899/slack/T0/B0/xyz"}), ("teams", {"url": "http://127.0.0.1:8899/teams/abc"}),
                      ("webhook", {"url": "http://127.0.0.1:8899/hook", "secret": "hook-secret"}), ("email", {"to": ["carol@acme.test", "bob@acme.test"]})):
        st, c = call("POST", "/notifications", {"name": f"E2E {kind}", "kind": kind, "config": cfg, "events": ev, "min_severity": "LOW"})
        ids[kind] = c.get("id"); st2, r2 = call("POST", f"/notifications/{c['id']}/test")
        check(f"channel test {kind}", st == 200 and st2 == 200, (st, c, st2, r2))
    log = mock()
    sl = [x for x in log if x["path"].startswith("/slack/")]; tm = [x for x in log if x["path"].startswith("/teams/")]; hk = [x for x in log if x["path"] == "/hook"]
    check("slack payload", sl and ("blocks" in json.loads(sl[-1]["body"]) or "text" in json.loads(sl[-1]["body"])))
    tb = json.loads(tm[-1]["body"]) if tm else {}
    check("teams payload (adaptive card)", tb.get("type") == "message" or "attachments" in tb, str(tb)[:200])
    if hk:
        sig = hk[-1]["headers"].get("X-Scakit-Signature", "")
        good = "sha256=" + hmac.new(b"hook-secret", hk[-1]["body"].encode(), hashlib.sha256).hexdigest()
        check("webhook HMAC signature", sig == good, sig)
    else:
        check("webhook HMAC signature", False, "no request")
    time.sleep(1)
    check("email channel test (Mailpit)", any(len(m["To"]) == 2 for m in mailpit()))
    before_mail, before_mock = len(mailpit()), len(mock())
    st, s = call("POST", "/targets/10/scans")
    for _ in range(60):
        time.sleep(2)
        if call("GET", f"/scans/{s['id']}")[1]["job"]["status"] in ("done", "failed"): break
    sc = call("GET", f"/scans/{s['id']}")[1]
    time.sleep(2)
    codes = [e["code"] for e in sc["job"]["events"]]
    check("scan done + notify events", sc["job"]["status"] == "done" and codes.count("notify_sent") >= 4, codes)
    newmock = mock()[before_mock:]
    check("scan notified slack/teams/webhook", {x["path"].split("/")[1] for x in newmock} >= {"slack", "teams", "hook"}, [x["path"] for x in newmock])
    check("scan notified email", len(mailpit()) > before_mail)
    def sso(user):
        c2 = b.new_context(viewport={"width": 1300, "height": 900}); c2.add_init_script("try { localStorage.setItem('lf_lang', 'tr') } catch (e) {}")
        q = c2.new_page(); q.goto(B + "/login"); q.wait_for_timeout(1200)
        q.get_by_role("link", name="Acme kurumsal hesabı").click()
        q.wait_for_url("**/realms/lefureteur/**", timeout=20000)
        q.fill("#username", user); q.fill("#password", "Kc-Deneme-2026"); q.click("#kc-login")
        q.wait_for_timeout(4000)
        return c2, q
    c2, q = sso("carol")
    me = c2.request.get(B + "/api/auth/me")
    check("SSO login carol", me.status == 200 and me.json()["email"] == "carol@acme.test", (me.status, q.url))
    q.screenshot(path=f"{S}/srv2/b8-sso-carol.png")
    c3, q3 = sso("ghost")
    check("SSO unknown user rejected", "sso_error=no_account" in q3.url and c3.request.get(B + "/api/auth/me").status == 401, q3.url)
    q3.screenshot(path=f"{S}/srv2/b8-sso-ghost.png")
    st, d = call("GET", "/users")
    carol = next(u for u in d if u["email"] == "carol@acme.test")
    det = call("GET", f"/users/{carol['id']}/detail")[1]
    check("SSO login recorded", det["logins"][0]["method"] == "sso" and det["logins"][0]["success"])
    b.close()
print("SUMMARY", sum(R.values()), "/", len(R))
