from __future__ import annotations

import re

V = r"(\d+\.\d+(?:\.\d+){0,2})"

BODY_PATTERNS = [
    (re.compile(r'ng-version="(\d+\.\d+\.\d+[\w.-]*)"'), "npm", "@angular/core"),
    (re.compile(r"Apache Tomcat/(\d+\.\d+\.\d+)"), "generic", "apache-tomcat"),
    (re.compile(r"<center>nginx/(\d+\.\d+\.\d+)</center>"), "generic", "nginx"),
    (re.compile(r"<address>Apache/(\d+\.\d+\.\d+)[^<]*Server at"), "generic", "apache-httpd"),
    (re.compile(r"Powered by Jetty:// ?(\d+\.\d+\.\d+[\w.-]*)"), "Maven", "org.eclipse.jetty:jetty-server"),
    (re.compile(r"Django Version:\s*</th>\s*<td>\s*" + V), "PyPI", "django"),
    (re.compile(r"ASP\.NET Version:\s*" + V), "generic", "asp.net"),
    (re.compile(r"Microsoft \.NET Framework Version:\s*" + V), "generic", ".net-framework"),
    (re.compile(r"IIS (\d+\.\d+) Detailed Error"), "generic", "microsoft-iis"),
    (re.compile(r"<b>Werkzeug</b> powered traceback interpreter"), "PyPI", "werkzeug"),
    (re.compile(r'<generator>https?://wordpress\.org/\?v=' + V + r"</generator>"), "generic", "wordpress"),
    (re.compile(r'generator="WordPress/' + V + '"'), "generic", "wordpress"),
    (re.compile(r'name="ajs-version-number" content="' + V + '"'), "generic", "@atlassian"),
    (re.compile(r'name="ajs-build-number" content="(\d+)"'), None, None),
    (re.compile(r"^Drupal " + V + r",", re.M), "generic", "drupal"),
    (re.compile(r"<version>" + V + r"</version>[\s\S]{0,400}?<(?:creationDate|author)>"), "generic", "joomla"),
    (re.compile(r"Magento/(\d+\.\d+) \("), "generic", "magento"),
    (re.compile(r'"siteClientTag"\s*:\s*"\d+\$\$(\d+\.\d+\.\d+\.\d+)"'), "generic", "microsoft-sharepoint"),
    (re.compile(r"vti_buildversion:SR\|(\d+\.\d+\.\d+\.\d+)"), "generic", "microsoft-sharepoint"),
]

DETECT = {
    "wordpress": [r"/wp-content/", r"/wp-includes/", r'content="WordPress'],
    "drupal": [r"Drupal\.settings", r"/sites/default/files", r'data-drupal-', r"drupal\.js"],
    "joomla": [r'content="Joomla', r"/media/jui/", r"/components/com_", r"/media/system/js/"],
    "magento": [r"Mage\.Cookies", r"/static/version\d+/", r"mage/cookies", r"Magento_"],
    "sitecore": [r"/-/media/", r"/sitecore/", r"sc_mode="],
    "sharepoint": [r"_spPageContextInfo", r"/_layouts/15/", r"SP\.ClientContext"],
}
DETECT_HEADERS = {
    "wordpress": ["x-pingback"],
    "drupal": ["x-drupal-cache", "x-drupal-dynamic-cache"],
    "magento": ["x-magento-cache-debug", "x-magento-tags"],
    "sharepoint": ["sprequestguid", "x-sharepointhealthscore", "microsoftsharepointteamservices"],
}
PROBES = {
    "wordpress": ["/feed/", "/wp-links-opml.php"],
    "drupal": ["/CHANGELOG.txt", "/core/CHANGELOG.txt"],
    "joomla": ["/administrator/manifests/files/joomla.xml", "/language/en-GB/en-GB.xml"],
    "magento": ["/magento_version"],
    "sitecore": ["/sitecore/shell/sitecore.version.xml"],
    "sharepoint": ["/_vti_pvt/buildversion.cnf"],
}
WP_PLUGIN = re.compile(r"/wp-content/plugins/([a-z0-9_-]+)/")
WP_THEME = re.compile(r"/wp-content/themes/([a-z0-9_-]+)/")
SITECORE_VER = re.compile(r"<major>(\d+)</major>\s*<minor>(\d+)</minor>(?:\s*<build>(\d*)</build>)?")


def scan_body(text: str) -> list[tuple[str, str, str, str]]:
    out, seen = [], set()
    low = text.lower()
    for rx, eco, name in BODY_PATTERNS:
        if eco is None:
            continue
        m = rx.search(text)
        if not m:
            continue
        ver = m.group(1) if m.groups() else None
        if name == "@atlassian":
            name = "confluence" if "confluence" in low else "jira" if "jira" in low else "atlassian"
        if name == "werkzeug":
            ver = None
        if (name, ver) in seen:
            continue
        seen.add((name, ver))
        snippet = text[max(0, m.start() - 10): m.end() + 10].replace("\n", " ")[:140]
        out.append((eco, name, ver, snippet))
    m = SITECORE_VER.search(text)
    if m:
        ver = ".".join(x for x in m.groups() if x)
        out.append(("generic", "sitecore", ver, m.group(0)[:100]))
    return out


def detect_platforms(html: str, headers) -> set[str]:
    found = set()
    for plat, pats in DETECT.items():
        if any(re.search(p, html) for p in pats):
            found.add(plat)
    for plat, hs in DETECT_HEADERS.items():
        if any(h in {k.lower() for k in headers.keys()} for h in hs):
            found.add(plat)
    return found


def wp_extensions(html: str) -> tuple[set[str], set[str]]:
    return set(WP_PLUGIN.findall(html)), set(WP_THEME.findall(html))
