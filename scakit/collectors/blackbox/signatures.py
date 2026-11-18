from __future__ import annotations

import re

V = r"(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)"
RV = r"(\d+\.\d+\.\d+(?:-(?!next-)[0-9A-Za-z.-]+?)?)"

JS_SIGNATURES: list[tuple[str, re.Pattern]] = [(n, re.compile(p, f)) for n, p, f in [
    ("jquery", r"/\*!?\s*jQuery (?:JavaScript Library )?v" + V, 0),
    ("jquery", r"[\"'`]" + V + r"[\"'`],\w+=function\(e,t\)\{return new \w+\.fn\.init\(e,t\)\}", 0),
    ("jquery-ui", r"jQuery UI - v" + V, 0),
    ("jquery-migrate", r"jQuery Migrate - v" + V, 0),
    ("jquery-validation", r"jQuery Validation Plugin - v" + V, 0),
    ("bootstrap", r"Bootstrap v" + V + r" \(https?://getbootstrap\.com", 0),
    ("bootstrap", r"Bootstrap v" + V, 0),
    ("angular", r"AngularJS v" + V, 0),
    ("@angular/core", r"@license Angular v" + V, 0),
    ("vue", r"Vue\.js v" + V, 0),
    ("@vue/runtime-core", r"@vue/runtime-core v" + V, 0),
    ("@vue/shared", r"@vue/shared v" + V, 0),
    ("react-dom", r"reconcilerVersion:[\"'`]" + RV + r"(?:-next-[0-9a-f]+-\d{8})?[\"'`]", 0),
    ("react-dom", r"version:[\"'`]" + RV + r"(?:-next-[0-9a-f]+-\d{8})?[\"'`],rendererPackageName:[\"'`]react-dom[\"'`]", 0),
    ("react", r"React v" + V, 0),
    ("punycode", r"version:[\"'`]" + V + r"[\"'`],ucs2:", 0),
    ("@builder.io/partytown", r"Partytown " + V + r" - MIT builder\.io", 0),
    ("lodash", r"var VERSION\s*=\s*'" + V + r"';\s*(?:/\*\*[^*]*\*/\s*)?var LARGE_ARRAY_SIZE", 0),
    ("lodash", r"[\"'`]" + V + r"[\"'`][^\"'`]{0,40}=200,\w+=[\"'`]Unsupported core-js use", 0),
    ("underscore", r"Underscore\.js " + V, 0),
    ("backbone", r"Backbone\.js " + V, 0),
    ("knockout", r"Knockout JavaScript library v" + V, 0),
    ("moment", r"//! moment\.js\s*(?:\\n)?\s*//! version : " + V, 0),
    ("moment-timezone", r"//! moment-timezone\.js\s*(?:\\n)?\s*//! version : " + V, 0),
    ("next", r"window\.next\s*=\s*\{\s*version:\s*[\"'`]" + V, 0),
    ("leaflet", r"Leaflet " + V + r", a JS library", 0),
    ("gsap", r"\bGSAP " + V, 0),
    ("mapbox-gl", r"mapbox-gl-js/blob/v" + V + r"/LICENSE", 0),
    ("clipboard", r"clipboard\.js v" + V, 0),
    ("js-cookie", r"JavaScript Cookie v" + V, 0),
    ("modernizr", r"modernizr " + V + r" \(Custom Build\)", 0),
    ("isotope-layout", r"Isotope PACKAGED v" + V, 0),
    ("masonry-layout", r"Masonry PACKAGED v" + V, 0),
    ("flickity", r"Flickity PACKAGED v" + V, 0),
    ("owl.carousel", r"Owl Carousel v" + V, 0),
    ("@fancyapps/fancybox", r"fancyBox v" + V, 0),
    ("bootstrap-datepicker", r"Datepicker for Bootstrap v" + V, 0),
    ("@fortawesome/fontawesome-free", r"Font Awesome Free " + V, 0),
    ("tailwindcss", r"tailwindcss v" + V + r" \| MIT License", 0),
    ("dompurify", r"DOMPurify " + V, 0),
    ("handlebars", r"handlebars v" + V, re.I),
    ("mustache", r"mustache\.js[^\n]{0,80}?" + V, 0),
    ("axios", r"Axios v" + V, re.I),
    ("tinymce", r"TinyMCE version " + V, 0),
    ("select2", r"Select2 " + V, 0),
    ("datatables.net", r"DataTables " + V + r"\s*(?:\\n|\n)?\s*\*?\s*(?:©|\(c\)|Copyright)", re.I),
    ("datatables.net", r"DataTable\.version\s*=\s*[\"'`]" + V, 0),
    ("chart.js", r"Chart\.js v" + V, 0),
    ("swiper", r"Swiper " + V, 0),
    ("@popperjs/core", r"@popperjs/core v" + V, 0),
    ("popper.js", r"Popper\.js v" + V, 0),
    ("highcharts", r"Highcharts JS v" + V, 0),
    ("pdfjs-dist", r"pdfjsVersion\s*=\s*[\"'`]" + V, 0),
    ("socket.io-client", r"Socket\.IO v" + V, 0),
    ("core-js", r"version:[\"'`]" + V + r"[\"'`],mode:[\"'`](?:global|pure)[\"'`]", 0),
    ("ckeditor4", r"CKEDITOR[^\n]{0,200}?version:[\"'`](4\.\d+\.\d+)", 0),
    ("sweetalert2", r"sweetalert2 v" + V, 0),
    ("video.js", r"Video\.js " + V, 0),
    ("hammerjs", r"Hammer\.JS - v" + V, 0),
    ("jszip", r"JSZip v" + V, 0),
    ("crypto-js", r"crypto-js[^\n]{0,40}v" + V, re.I),
    ("marked", r"marked v" + V, 0),
    ("prismjs", r"Prism\.js[^\n]{0,40}?" + V, 0),
    ("quill", r"Quill Editor v" + V, 0),
    ("summernote", r"Summernote v" + V, 0),
    ("froala-editor", r"froala_editor v" + V, 0),
    ("ua-parser-js", r"UAParser\.js v" + V, 0),
    ("hls.js", r"hls\.js[^\n]{0,40}?" + V, 0),
]]

_CDNJS_MAP = {"jquery": "jquery", "angular.js": "angular", "twitter-bootstrap": "bootstrap", "lodash.js": "lodash",
              "vue": "vue", "moment.js": "moment", "dompurify": "dompurify", "handlebars.js": "handlebars",
              "underscore.js": "underscore", "jqueryui": "jquery-ui", "axios": "axios", "Chart.js": "chart.js",
              "popper.js": "popper.js", "select2": "select2", "datatables": "datatables.net", "react": "react",
              "react-dom": "react-dom", "socket.io": "socket.io-client", "tinymce": "tinymce", "pdf.js": "pdfjs-dist",
              "jquery-validate": "jquery-validation", "backbone.js": "backbone", "knockout": "knockout",
              "highcharts": "highcharts", "sweetalert2": "sweetalert2", "crypto-js": "crypto-js"}
CDN_PATTERNS = [
    (re.compile(r"cdn\.jsdelivr\.net/npm/((?:@[^/@]+/)?[^/@]+)@([^/]+)/"), None),
    (re.compile(r"unpkg\.com/((?:@[^/@]+/)?[^/@]+)@([^/]+)/"), None),
    (re.compile(r"cdnjs\.cloudflare\.com/ajax/libs/([^/]+)/([^/]+)/"), _CDNJS_MAP),
    (re.compile(r"ajax\.googleapis\.com/ajax/libs/([^/]+)/([^/]+)/"), {"jquery": "jquery", "angularjs": "angular",
                                                                       "jqueryui": "jquery-ui"}),
    (re.compile(r"code\.jquery\.com/(jquery|ui/)(?:-)?(\d+\.\d+\.\d+)"), {"jquery": "jquery", "ui/": "jquery-ui"}),
    (re.compile(r"code\.jquery\.com/ui/(\d+\.\d+\.\d+)/"), "jquery-ui"),
    (re.compile(r"(?:stackpath|maxcdn|netdna)\.bootstrapcdn\.com/(?:twitter-)?(bootstrap)/(\d+\.\d+\.\d+)/"),
     {"bootstrap": "bootstrap"}),
    (re.compile(r"cdn\.datatables\.net/(\d+\.\d+\.\d+)/"), "datatables.net"),
]
FILENAME_VERSION = re.compile(
    r"/(jquery|jquery-ui|jquery-migrate|bootstrap|angular|vue|lodash|moment|dompurify|handlebars|underscore|"
    r"knockout|backbone|select2|axios|chart|popper|tinymce|socket\.io)[.-](\d+\.\d+\.\d+)(?:\.min|\.slim|\.bundle)*\.(?:js|css)",
    re.I)
WP_VER = re.compile(r"/wp-(?:includes|content)/[^?\"']+\?ver=(\d+\.\d+(?:\.\d+)?)")


def cdn_match(url: str):
    for rx, mapping in CDN_PATTERNS:
        m = rx.search(url)
        if not m:
            continue
        if isinstance(mapping, str):
            return mapping, m.group(1)
        name, ver = m.group(1), m.group(2)
        if mapping is not None:
            name = mapping.get(name)
            if not name:
                continue
        ver = ver.lstrip("v")
        if re.match(r"^\d+\.\d+", ver):
            return name, ver
    m = FILENAME_VERSION.search(url)
    if m:
        name = m.group(1).lower()
        return {"chart": "chart.js", "popper": "popper.js", "socket.io": "socket.io-client"}.get(name, name), m.group(2)
    return None


_REQ_BEFORE = re.compile(r"(?:requires?|required|needs?|minimum|at least|compatible with)\W*\w*\W*$", re.I)
_REQ_AFTER = re.compile(r"^[\s'\"]*(?:or (?:newer|greater|later|higher|above)|and (?:newer|above|later)|\+|or\s*>)",
                        re.I)


def _is_requirement(text: str, m) -> bool:
    return bool(_REQ_BEFORE.search(text[max(0, m.start() - 40): m.start()]) or
                _REQ_AFTER.match(text[m.end(1): m.end(1) + 25]))


_REACT_FILE = re.compile(r"\s*(?:\*\s*)?([a-z][a-z0-9-]*)\.(?:production|development|profiling)(?:\.min)?\.js")


def _react_banner(text: str, m) -> str:
    f = _REACT_FILE.match(text, m.end(), m.end() + 80)
    return f.group(1) if f else "react"


def scan_js(text: str) -> list[tuple[str, str, str]]:
    out, seen = [], set()
    for name, rx in JS_SIGNATURES:
        for m in rx.finditer(text):
            if _is_requirement(text, m):
                continue
            ver = m.group(1)
            if name == "react":
                name = _react_banner(text, m)
            if (name, ver) in seen:
                continue
            seen.add((name, ver))
            snippet = text[max(0, m.start() - 20): m.end() + 20].replace("\n", " ")
            out.append((name, ver, snippet[:160]))
    return out


NM_PATH = re.compile(r"node_modules/((?:@[^/]+/)?[^/]+)/")
PNPM_PATH = re.compile(r"\.pnpm/((?:@[^+/]+\+)?[^@/]+)@(\d[^/_(]*)")
YARN_PATH = re.compile(r"\.yarn/(?:cache|unplugged|__virtual__)/(?:[^/]+/)*?((?:@[a-z0-9-]+-)?[a-z0-9._-]+?)-npm-(\d+\.\d+\.\d+[^-/]*)-")


def packages_from_paths(sources: list[str]) -> dict[str, set]:
    pkgs: dict[str, set] = {}
    for s in sources:
        for m in PNPM_PATH.finditer(s):
            if _NPM_NAME.match(m.group(1).replace("+", "/")):
                pkgs.setdefault(m.group(1).replace("+", "/"), set()).add(m.group(2))
        for m in YARN_PATH.finditer(s):
            if _NPM_NAME.match(m.group(1)):
                pkgs.setdefault(m.group(1), set()).add(m.group(2))
        for m in NM_PATH.finditer(s):
            name = m.group(1)
            if name.startswith(".") or name in (".pnpm", ".yarn") or not _NPM_NAME.match(name):
                continue
            pkgs.setdefault(name, set())
    return pkgs


def _family(name: str) -> str:
    return re.split(r"[-/.]", name.lstrip("@"), maxsplit=1)[0]


def analyze_sourcemap(sm: dict) -> dict[str, set]:
    import json as _json
    sources = [s for s in sm.get("sources") or [] if isinstance(s, str)]
    pkgs = packages_from_paths(sources)
    for src, content in zip(sources, sm.get("sourcesContent") or []):
        if not content or not isinstance(content, str):
            continue
        pm = NM_PATH.search(src) or PNPM_PATH.search(src)
        path_pkg = pm.group(1).replace("+", "/") if pm else None
        for name, ver, _ in scan_js(content[:400000]):
            if path_pkg and path_pkg != name and _family(path_pkg) == _family(name):
                name = path_pkg
            pkgs.setdefault(name, set()).add(ver)
        if pm and src.endswith("/package.json"):
            try:
                pj = _json.loads(content)
                if pj.get("name") and pj.get("version"):
                    pkgs.setdefault(pj["name"], set()).add(pj["version"])
            except ValueError:
                pass
    return pkgs


LICENSE_MANIFESTS = ["3rdpartylicenses.txt", "third-party-licenses.txt", "THIRD-PARTY-NOTICES.txt",
                     "ThirdPartyNotices.txt", "licenses.txt"]
LICENSE_REF = re.compile(r"For license information please see ([\w.\-/]+\.LICENSE\.txt)")
_NPM_NAME = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$")
_LIC_ID = re.compile(r"^\(?[A-Za-z0-9.+-]+(?: (?:OR|AND|WITH|or|and) [A-Za-z0-9.+-]+)*\)?$")


def parse_license_manifest(text: str) -> list[tuple[str, str, str | None]]:
    out, seen = [], set()
    lines = text.splitlines()
    cur: dict = {}
    for line in lines + [""]:
        m = re.match(r"^\s*(Package|Name|Version|License|Licenses)\s*:\s*(.*)$", line)
        if m:
            key = m.group(1).lower().rstrip("s")
            key = "package" if key == "name" else key
            if key == "package" and cur.get("package"):
                out.append(cur)
                cur = {}
            cur[key] = m.group(2).strip().strip('"')
        elif not line.strip() and cur.get("package") and ("license" in cur or "version" in cur):
            out.append(cur)
            cur = {}
    if cur.get("package"):
        out.append(cur)
    result = []
    for d in out:
        if _NPM_NAME.match(d["package"]) and d["package"] not in seen:
            seen.add(d["package"])
            ver = d.get("version")
            result.append((d["package"], d.get("license", ""), ver if ver and re.match(r"^\d", ver) else None))
    if result:
        return result
    for i, line in enumerate(lines[:-1]):
        name, lic = line.strip(), lines[i + 1].strip()
        if (i == 0 or not lines[i - 1].strip()) and _NPM_NAME.match(name) and lic and len(lic) <= 60 \
                and _LIC_ID.match(lic) and name not in seen:
            seen.add(name)
            result.append((name, lic, None))
    return result


HEADER_RULES = {
    "server": [
        (re.compile(r"\bnginx/(\d[\d.]*)", re.I), "generic", "nginx"),
        (re.compile(r"\bopenresty/(\d[\d.]*)", re.I), "generic", "openresty"),
        (re.compile(r"\bApache/(\d[\d.]*)", re.I), "generic", "apache-httpd"),
        (re.compile(r"Microsoft-IIS/(\d[\d.]*)", re.I), "generic", "microsoft-iis"),
        (re.compile(r"\bLiteSpeed/?(\d[\d.]*)?", re.I), "generic", "litespeed"),
        (re.compile(r"\bJetty\((\d[\w.\-]*)\)", re.I), "Maven", "org.eclipse.jetty:jetty-server"),
        (re.compile(r"\bWerkzeug/(\d[\d.]*)", re.I), "PyPI", "werkzeug"),
        (re.compile(r"\bgunicorn/(\d[\d.]*)", re.I), "PyPI", "gunicorn"),
        (re.compile(r"\buvicorn\b", re.I), "PyPI", "uvicorn"),
        (re.compile(r"\bTornadoServer/(\d[\d.]*)", re.I), "PyPI", "tornado"),
        (re.compile(r"\bCaddy\b", re.I), "generic", "caddy"),
        (re.compile(r"\bKestrel\b", re.I), "generic", "kestrel"),
        (re.compile(r"\bApache-Coyote/(\d[\d.]*)", re.I), "generic", "apache-tomcat-coyote"),
        (re.compile(r"\bWebSphere Application Server/(\d[\d.]*)", re.I), "generic", "ibm-websphere"),
        (re.compile(r"\bWildFly/(\d[\d.]*)", re.I), "generic", "wildfly"),
    ],
    "x-powered-by": [
        (re.compile(r"\bPHP/(\d[\d.]*)", re.I), "generic", "php"),
        (re.compile(r"\bExpress\b"), "npm", "express"),
        (re.compile(r"\bNext\.js(?:\s+(\d[\d.]*))?"), "npm", "next"),
        (re.compile(r"\bNuxt\b"), "npm", "nuxt"),
        (re.compile(r"\bASP\.NET\b"), "generic", "asp.net"),
        (re.compile(r"Servlet/(\d[\d.]*)"), "generic", "java-servlet"),
        (re.compile(r"Apache Tomcat/(\d+\.\d+\.\d+)"), "generic", "apache-tomcat"),
        (re.compile(r"\bPHP/(\d[\d.]*)"), "generic", "php"),
        (re.compile(r"\bPleskLin\b"), "generic", "plesk"),
    ],
    "x-aspnet-version": [(re.compile(r"(\d[\d.]*)"), "generic", ".net-framework")],
    "x-aspnetmvc-version": [(re.compile(r"(\d[\d.]*)"), "NuGet", "Microsoft.AspNet.Mvc")],
    "x-generator": [(re.compile(r"Drupal (\d+)"), "generic", "drupal")],
    "microsoftsharepointteamservices": [(re.compile(r"(\d+\.\d+\.\d+\.\d+)"), "generic", "microsoft-sharepoint")],
    "x-jenkins": [(re.compile(r"(\d+\.\d+(?:\.\d+)?)"), "generic", "jenkins")],
    "liferay-portal": [(re.compile(r"(\d+\.\d+\.\d+(?:\.\d+)?)"), "generic", "liferay-portal")],
    "x-confluence-request-time": [(re.compile(r"^(?!x)x"), "generic", "confluence")],
    "x-arequestid": [(re.compile(r"^(?!x)x"), "generic", "atlassian")],
    "x-owa-version": [(re.compile(r"(\d+\.\d+\.\d+\.\d+)"), "generic", "microsoft-exchange-owa")],
    "x-powered-cms": [(re.compile(r"([A-Za-z][\w .-]+)"), "generic", "cms")],
}
META_GENERATOR = re.compile(r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)[\"']", re.I)
GENERATOR_RULES = [
    (re.compile(r"WordPress (\d[\d.]*)"), "generic", "wordpress"),
    (re.compile(r"Drupal (\d+(?:\.\d+)*)"), "generic", "drupal"),
    (re.compile(r"Joomla!? (\d[\d.]*)"), "generic", "joomla"),
    (re.compile(r"TYPO3 CMS (\d[\d.]*)?"), "generic", "typo3"),
    (re.compile(r"Umbraco"), "generic", "umbraco"),
    (re.compile(r"Sitecore"), "generic", "sitecore"),
    (re.compile(r"^Astro v?(\d[\d.]*)"), "npm", "astro"),
    (re.compile(r"^Gatsby (\d[\d.]*)"), "npm", "gatsby"),
    (re.compile(r"^Next\.js (\d[\d.]*)?"), "npm", "next"),
    (re.compile(r"^Nuxt(?:\.js)? ?v?(\d[\d.]*)?"), "npm", "nuxt"),
    (re.compile(r"^Docusaurus v?(\d[\d.]*)"), "npm", "@docusaurus/core"),
    (re.compile(r"^VuePress (\d[\d.]*)"), "npm", "vuepress"),
    (re.compile(r"^VitePress v?(\d[\d.]*)"), "npm", "vitepress"),
    (re.compile(r"^Eleventy v?(\d[\d.]*)"), "npm", "@11ty/eleventy"),
    (re.compile(r"^Hexo (\d[\d.]*)"), "npm", "hexo"),
    (re.compile(r"^Hugo (\d[\d.]*)"), "generic", "hugo"),
    (re.compile(r"^Jekyll v(\d[\d.]*)"), "generic", "jekyll"),
    (re.compile(r"^Ghost (\d[\d.]*)"), "generic", "ghost"),
]
