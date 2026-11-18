import json, os, subprocess, sys, time
from playwright.sync_api import sync_playwright
S = sys.argv[1]; B = "http://localhost:8812"
with sync_playwright() as p:
    b = p.chromium.launch(); ctx = b.new_context(viewport={"width": 1400, "height": 1000}); ctx.add_init_script("try { localStorage.setItem('lf_lang', 'tr') } catch (e) {}")
    pg = ctx.new_page(); pg.goto(B + "/login"); pg.fill("input[autocomplete=username]", "admin@test.local"); pg.fill("input[type=password]", "Deneme-Parola-2026")
    pg.click("button[type=submit]"); pg.wait_for_url(B + "/")
    H = {"X-CSRF-Token": next(c["value"] for c in ctx.cookies() if "csrf" in c["name"])}
    call = lambda m, path, data=None: ctx.request.fetch(B + "/api" + path, method=m, data=data, headers=H).json()
    call("PUT", "/settings", {"allow_internal_targets": "1"})
    try:
        pid = call("GET", "/projects")[0]["id"]
        t = call("POST", f"/projects/{pid}/targets", {"name": "waf-demo (yerel)", "kind": "web", "url": "http://127.0.0.1:8777/",
                                                      "options": {"waf_assist": True, "delay": 0.5, "max_pages": 10, "probe": False}})
        s = call("POST", f"/targets/{t['id']}/scans")
        for _ in range(40):
            time.sleep(2)
            if call("GET", f"/scans/{s['id']}")["job"]["status"] in ("done", "failed"): break
        sc = call("GET", f"/scans/{s['id']}")
        print("web scan:", sc["job"]["status"], sc["summary"].get("components"), "waf=", sc["summary"].get("waf", {}).get("vendor"), [e["code"] for e in sc["job"]["events"]])
        pg.goto(f"{B}/scans/{s['id']}"); pg.wait_for_timeout(1500); pg.screenshot(path=f"{S}/srv2/assist-card.png")
        tk = call("POST", f"/targets/{t['id']}/capture-ticket")["ticket"]
        env = dict(os.environ, LF_CAPTURE_HEADLESS="1")
        out = subprocess.run([sys.executable, "/home/hamit/scakit/scakit/capture_client.py", "--server", B, "--ticket", tk],
                             capture_output=True, text=True, env=env, timeout=300)
        print(out.stdout[-1500:], out.stderr[-800:])
        st = call("GET", f"/targets/{t['id']}/capture-status")["ticket"]
        for _ in range(40):
            time.sleep(2)
            r = call("GET", f"/scans/{st['result_scan_id']}")
            if r["job"]["status"] in ("done", "failed"): break
        print("capture scan:", r["job"]["status"], r["summary"])
        comps = call("GET", f"/scans/{st['result_scan_id']}/components")
        print([(c["name"], c["version"]) for c in comps])
        pg.goto(f"{B}/scans/{s['id']}"); pg.wait_for_timeout(1500); pg.screenshot(path=f"{S}/srv2/assist-done.png")
        tid = st["result_target_id"]
        stored = call("GET", f"/targets/{tid}")["files"][0]["stored"]
        print("stored", stored)
        inbox = [i["kind"] for i in call("GET", "/inbox")][:3]
        print("inbox", inbox)
    finally:
        call("PUT", "/settings", {"allow_internal_targets": "0"})
    b.close()
