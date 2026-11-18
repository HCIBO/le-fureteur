import { GuideContent } from "./types";

const c: GuideContent = {
  intro:
    "Le Fureteur is a Software Composition Analysis (SCA) platform. It finds the third-party components inside software (open-source libraries, frameworks, operating system packages), matches them against known security vulnerabilities and produces a remediation plan. It is installed on the organisation's own server; source code, files and findings never leave the organisation.",
  sections: [
    {
      id: "what",
      title: "What is Le Fureteur for?",
      blocks: [
        { p: "Most of the code in a modern application is not written by the organisation itself but comes from external components. When one of them has a vulnerability (e.g. Log4Shell), the application is affected too. Le Fureteur answers:" },
        { ul: [
          "Which components, in which versions, does the application contain? (inventory / SBOM)",
          "Which of them have known vulnerabilities, and how severe are they?",
          "Which ones are currently being actively exploited by attackers (CISA KEV)?",
          "Which version fixes them, and what should be fixed first?",
          "Do the licenses comply with the organisation's policy? Are there supply-chain risks (dependency confusion, unmaintained packages)?",
        ] },
        { p: "Outputs: a prioritised list of findings, a report with an executive summary (HTML / PDF / Word), CSV and standard SBOM files (CycloneDX, SPDX)." },
      ],
    },
    {
      id: "how",
      title: "How it works",
      blocks: [
        { ol: [
          "Collection: components are found according to the target type — lock files, package databases, build artefact metadata, web responses, mobile app contents.",
          "Inventory: detections of the same component in different places are merged; for each component the ecosystem, version, confidence, direct / transitive relation and evidence (file path / URL) are kept.",
          "Matching: the inventory is matched against the offline vulnerability database on the server (OSV; NVD for server software outside OSV coverage) using ecosystem-specific version comparison.",
          "Enrichment: each finding gets a CVSS severity, EPSS exploit probability and CISA KEV status; the fixed version is computed.",
          "Prioritisation: malicious package → active exploitation (KEV) → severity → EPSS.",
          "Reporting and tracking: findings are stored; re-scans track new / fixed / reopened findings.",
        ] },
        { note: "The analysis runs entirely on the server and offline. No source code or inventory is sent to third-party services. The internet is only used (optionally) to update the vulnerability database." },
      ],
    },
    {
      id: "types",
      title: "Analysis types and supported inputs",
      blocks: [
        { table: { head: ["Type", "Input", "What is found"], rows: [
          ["Whitebox — source", "Source code archive (zip / tar) or dependency files", "npm / yarn / pnpm, PyPI (requirements, Poetry, Pipfile), Maven / Gradle, Go, Composer, NuGet, Cargo, RubyGems, Pub, CocoaPods, SwiftPM; usage (import) analysis"],
          ["Whitebox — build", "JAR / WAR / EAR", "Nested JARs and Maven metadata"],
          ["Whitebox — container", "Image saved with docker save (.tar)", "Operating system packages (Debian / Ubuntu / Alpine / RHEL family) and application dependencies inside the image"],
          ["Whitebox — package list", "dpkg / rpm / apk output", "Operating system packages (distribution and release must be given, e.g. Debian:12)"],
          ["Blackbox — web", "Web address", "JavaScript / CSS libraries delivered to the browser, CDN URLs, source maps, license manifests, version-disclosing headers and error pages, CMS versions"],
          ["Blackbox — mobile", "APK / IPA", "Libraries embedded in the app (FairPlay-encrypted IPAs cannot be analysed)"],
          ["Blackbox — desktop", "Installer (.exe / .msi), Electron app", "Embedded DLLs, .NET assemblies, Electron / Node packages"],
        ] } },
        { p: "The confidence of a finding (high / medium / low) shows how precisely the version was determined. Blackbox analysis can only see externally visible components; server-side libraries require whitebox analysis." },
      ],
    },
    {
      id: "webaccess",
      title: "Blockers in web scanning and how they are solved",
      blocks: [
        {"p": "Web targets are scanned from outside; some sites block automated requests. Le Fureteur detects the kind of blocker and shows the reason and one-click solutions on the scan page. Most cases resolve themselves."},
        {"table": {"head": ["Situation", "What happens?"], "rows": [["WAF / bot protection (TLS fingerprint)", "With the HTTP client on \"Automatic\" the scan switches to browser-compatible TLS (curl_cffi) as soon as it is blocked and continues."], ["JavaScript challenge / CAPTCHA", "Not passed automatically. The browser helper opens a visible browser on your computer; you pass the check, crawling and upload are automatic. Or upload a HAR / Burp recording."], ["Geo-block, IP block, timeout", "Egress points (HTTP / SOCKS5 proxies) defined by an admin are tried in turn in Automatic mode; one can be pinned per target."], ["Redirect to login / SSO", "Configure authentication (form, cookie, Bearer, Basic) on the target page, or log in yourself in the browser helper."], ["Rate limit (429 / 503)", "Waits for the announced time, slows down and retries the request once."], ["TLS certificate error", "In trusted internal environments, disable TLS verification and rescan with one click."], ["DNS, connection refused, mTLS, maintenance", "The reason and next steps are explained on the scan page."]]}},
        {"ul": ["JS / CSS files loaded by the pages from other domains (CDN) are analysed too; tracking scripts are skipped and those servers are not crawled.", "On redirects such as linkedin.com → www.linkedin.com the scan continues on the new address.", "For file targets with no components, the reason (no lock file, encrypted IPA, protected APK, distroless image, unsupported archive) and fix commands are shown."]},
        {"note": "Internal network protection always applies: even through a proxy or the browser-compatible client, scans never connect to internal addresses (unless an admin explicitly allows it)."},
      ],
    },
    {
      id: "glossary",
      title: "Glossary",
      blocks: [
        { table: { head: ["Term", "Meaning"], rows: [
          ["SCA", "Software Composition Analysis — analysis of third-party components in software and their risks."],
          ["SBOM", "Software Bill of Materials — the list of components of a piece of software. Standards: CycloneDX and SPDX."],
          ["CVE", "Universal identifier of a vulnerability (e.g. CVE-2021-44228)."],
          ["GHSA / OSV", "GitHub security advisory ID / Google's open vulnerability database with affected version ranges per package ecosystem."],
          ["NVD / CPE", "US National Vulnerability Database / product naming scheme; used for server software outside OSV coverage."],
          ["CVSS", "Technical severity score of a vulnerability (0–10)."],
          ["EPSS", "Probability that a vulnerability will be exploited in the next 30 days (FIRST)."],
          ["KEV", "CISA's list of vulnerabilities known to be actively exploited in real attacks — highest priority."],
          ["PURL", "Package URL — ecosystem-independent identifier of a component (e.g. pkg:npm/lodash@4.17.20)."],
          ["Direct / transitive dependency", "A package added by the application itself / a package pulled in by another package."],
          ["Dependency confusion", "An internal package name that also exists in a public registry; an attacker can publish a fake package."],
          ["Copyleft", "Licenses requiring derived software to be released under the same license (GPL, AGPL…)."],
        ] } },
      ],
    },
    {
      id: "roles",
      title: "Roles and permissions",
      blocks: [
        { table: { head: ["Role", "Permissions"], rows: [
          ["Administrator", "Everything: users, organisations, settings (NVD key, SMTP, Jira), vulnerability database, notification channels, system status, audit log."],
          ["Analyst", "Projects, targets, scans and findings in all organisations; can view system status. Cannot change settings."],
          ["Customer", "Own organisation only: adds projects and targets, uploads files, scans, manages finding status, sends to Jira, downloads reports. Can only add web targets on the domains allowed for the organisation."],
        ] } },
      ],
    },
    {
      id: "start",
      title: "Step by step",
      blocks: [
        { ol: [
          "Administrator: Settings → Update database (mandatory on first install) and review the recommendations on the System status page.",
          "Organisations → add the customer organisation; for web scans, enter the allowed domains (example.com or *.example.com).",
          "Users → create analyst and customer accounts.",
          "Projects → new project; report language, license policy and Jira project key can be set in the project settings.",
          "Add target → web address (blackbox) or file upload (source code, APK, IPA, image, installer).",
          "Start scan → progress and log are shown on the scan page.",
          "Findings → filter, open details, set a status, comment, send to Jira.",
          "Scan → Reports tab: download the report and SBOM files.",
          "Add a scheduled scan on the target page for regular re-scans.",
        ] },
        { note: "Only scan systems for which you have written permission. Internal network addresses are blocked by default; an administrator can allow them in the settings." },
      ],
    },
    {
      id: "findings",
      title: "Findings and their life cycle",
      blocks: [
        { p: "A finding = one component + one vulnerability on one target. The same finding is unique across scans; first and last seen times are kept." },
        { table: { head: ["Status", "Meaning"], rows: [
          ["Open", "Newly found, awaiting action."],
          ["In progress", "Remediation has started."],
          ["Accepted risk", "Deliberately accepted (justification required). Shown in a separate section of the report."],
          ["False positive", "The finding is wrong (justification required)."],
          ["Not affected", "The component is present but the vulnerability cannot be triggered in this usage (justification required)."],
          ["Fixed", "Automatic: the component / version is no longer seen in a re-scan. If it reappears, the finding is reopened."],
        ] } },
        { p: "The Changes tab of a scan shows new, fixed and reopened findings compared with the previous scan. After changing statuses you can regenerate the report." },
        {"p": "The search box on the Findings page searches domain, target, project, customer, component, version, CVE / GHSA and description; several words return findings containing all of them. Filters for ecosystem, fix available / not, first seen and target type; the filtered list can be downloaded as CSV. If the searched target has no findings, matching targets are shown with links."},
      ],
    },
    {
      id: "collaboration",
      title: "Teamwork: assignment, approval, discussion, messages",
      blocks: [
        { p: "Le Fureteur includes collaboration tools to manage who fixes which finding, by when and with which decision." },
        { ul: [
          "Teams: each team has a manager, leads and members reporting to them. The team page shows the org chart, workload per person, the work queue and what was delivered in the last 30 days.",
          "Assignment: a finding is assigned to a person with a due date; the assignee is notified. Bulk assignment is available on the Findings screen.",
          "Approval workflow: accepted-risk, false-positive and \"not affected\" decisions go to the person's lead / team manager for approval. Approved and rejected requests stay under Approvals → Decided by me.",
          "Discussion room: when people disagree about a finding, open a discussion from it and add the people involved. Without agreement it is escalated to a manager, who decides or delegates the decision. The outcome is written to the finding history.",
          "Messages: write to people or a whole team. One tick means sent, two grey ticks delivered, two blue ticks read. Non-readers can be reminded once an hour.",
          "Reminders: leave yourself timed notes, also from a finding or a message. When due they land in your notifications.",
        ] },
        { note: "Customer users only see people of their own organisation and the consulting team; findings, discussions or messages of another organisation are never visible." },
      ],
    },
    {
      id: "reports",
      title: "Reports and outputs",
      blocks: [
        { table: { head: ["File", "Content"], rows: [
          ["report.html / .pdf / .docx", "Executive summary, remediation plan, finding details, usage analysis, license compliance, supply chain, scope limitations, appendices (inventory, detection locations)."],
          ["findings.csv", "Finding list for spreadsheets and other tools."],
          ["sbom.cdx.json", "CycloneDX 1.5 SBOM."],
          ["sbom.spdx.json", "SPDX 2.3 SBOM."],
        ] } },
        { p: "The report language is chosen in the project settings: Turkish, English, French, German." },
      ],
    },
    {
      id: "automation",
      title: "Scheduling, notifications and Jira",
      blocks: [
        { ul: [
          "Continuous / scheduled scan: from the target page or for all targets under project → Trend and continuous scanning; with the wizard (days, time window, frequency) or a cron expression. At most once an hour. Scans starting together are ordered by the project queue rule.",
          "Scheduled database update: from the Settings page (administrator); recommended once a day.",
          "Notifications (administrator): Slack, Microsoft Teams, e-mail or a generic webhook. Events: scan completed / failed, new findings above threshold, new KEV finding, database update failed. A channel can be limited to one organisation. Webhook bodies can be signed with HMAC-SHA256 (X-Scakit-Signature).",
          "Jira (Cloud and Server / Data Center): several Jira connections can be added; the admin decides who (roles, users) and which customers' findings may use each. On \"Add to Jira\", users allowed several connections are asked which one; not if the project has a default Jira. No second issue for the same finding; optional automatic issues and comments when fixed / reopened.",
        ] },
      ],
    },
    {
      id: "queue",
      title: "Scan queue, continuous scanning and trend",
      blocks: [
        {"ul": ["Queue panel (Scans page): running and queued scans; admins and analysts can reorder (move to front, up / down, to end).", "Project queue rule: each project's scans (manual, bulk, scheduled) run one by one, at most N at once or freely among themselves, with an optional wait between them. Other projects are not affected.", "When adding targets, the \"Queue (for these scans)\" card sets a rule just for those scans or makes it the project default. The start menu on the target page: move to front / normal / add to end.", "Server-wide rules (admin, Settings → Scan queue): scans per worker and wait between scans — the upper limit for project rules.", "Continuous scanning: under project → Trend and continuous scanning choose days, time window and frequency and apply to all targets at once (e.g. every 3 h between 09–18 on weekdays, twice a week).", "Trend: on the dashboard, project and target pages — open, new and fixed findings per hour / day / week and the change vs the previous period; Small / Medium / Large size and table view."]},
      ],
    },
    {
      id: "vulndb",
      title: "Vulnerability database",
      blocks: [
        { p: "Matching uses a local database on the server. Sources: OSV (package ecosystems and Linux distributions), EPSS, CISA KEV and optionally NVD (an API key is recommended)." },
        { ul: [
          "Update: Settings → Update database, or a scheduled update.",
          "Air-gapped install: download with `scakit db download folder` on another machine, copy the folder to the server and enter its path in Settings.",
          "Freshness: the System status page shows the age of each source; stale data raises a warning.",
          "Scans keep running while the database is updated (using the last committed data). A corrupted download is skipped and fetched again on the next update.",
          "Step-by-step air-gapped instructions and download: the Command line (scakit) page.",
        ] },
      ],
    },
    {
      id: "system",
      title: "System status and self-scan",
      blocks: [
        { p: "The System status page (administrator / analyst) shows the health of the application itself: workers, job queue, disk, database, vulnerability data freshness, external tools and configuration checks — each with a recommended action." },
        { ul: [
          "Self-scan: Le Fureteur scans its own Python, frontend and operating system packages against its own vulnerability database and recommends upgrades (offline).",
          "Latest version check (administrator, optional): only the names of Le Fureteur's own open-source dependencies are queried on PyPI and npm; no customer data is sent.",
        ] },
      ],
    },
    {
      id: "security",
      title: "Security and privacy",
      blocks: [
        { ul: [
          "On-premises: code, files, findings and reports stay on the organisation's server.",
          "Passwords are stored with Argon2; session cookie is httpOnly + SameSite=Strict; CSRF protection on all modifying requests; login attempt limiting.",
          "Secret settings (NVD key, SMTP password, Jira token, webhook URLs) are encrypted in the database and never sent back to the interface.",
          "Target guard: http / https only; customers can only scan allowed domains; internal network and cloud metadata addresses are blocked by default; the check is repeated at scan time.",
          "Organisation isolation: customer users cannot see any data of another organisation.",
          "Audit log: logins, settings, targets, scans, status changes, Jira and report downloads are recorded.",
          "Run behind HTTPS in production (SCAKIT_COOKIE_SECURE=1).",
        ] },
      ],
    },
    {
      id: "toolset",
      title: "Toolset",
      blocks: [
        { p: "Small, safe tools for everyday work: HTTP client, encoder / decoder (Base64, URL, HTML, Hex, Unicode, JWT, SHA), TCP ping and a personal notepad." },
        { ul: [
          "The HTTP client and ping never connect to internal addresses (127.0.0.1, 10.x, 169.254.169.254, etc.); redirects are checked too.",
          "Your session cookie is never sent to the target; only the headers you add are. Every request is audited and rate-limited per minute.",
          "The encoder runs entirely in the browser. The notepad is visible only to you.",
          "Network tools are disabled for customer users by default; if enabled they can only reach allowed domains (Settings → Toolset).",
        ] },
      ],
    },
    {
      id: "admin",
      title: "Administration: maintenance mode, sessions, audit",
      blocks: [
        { ul: [
          "Maintenance mode (System status → Maintenance): only administrators can log in; other users and API tokens see a maintenance screen and scheduled scans do not start.",
          "Login and API limits (Settings → Security & access): failed login attempts, lockout duration and API requests per user per minute.",
          "User details: login history (success / failure, IP, device), active sessions and recent actions. All sessions can be ended with one click. Everyone sees their own sessions under My account.",
          "Audit log: filter by user, action, object type, IP and time range; export as CSV.",
          "Backup: `scakit server backup file --encrypt` creates an encrypted backup; restore only into an empty installation.",
        ] },
      ],
    },
    {
      id: "cli",
      title: "Command line (CLI)",
      blocks: [
        { p: "The same analysis engine can also be used from the command line for consulting engagements:" },
        { code: "scakit init ~/work/customer --name \"Portal 2026\" --client \"Customer\" --lang en\nscakit add ~/work/customer ./source.zip app.apk https://example.com\nscakit db update\nscakit match ~/work/customer\nscakit report ~/work/customer --formats html,pdf,docx,cdx,spdx\n\n# web server\nscakit server init --email admin@company.com\nscakit server run --port 8800\nscakit server worker" },
        {"note": "For what scakit is, installation, all commands and preparing the database for air-gapped networks, see the Command line (scakit) page in the menu; admins and analysts can download the package there."},
      ],
    },
    {
      id: "faq",
      title: "Frequently asked questions",
      blocks: [
        { table: { head: ["Question", "Answer"], rows: [
          ["No findings — is the application secure?", "No, it only means no component with a known vulnerability was found. Blackbox analysis cannot see server-side components; scope limitations are stated in the report."],
          ["Why is a finding's confidence low?", "The version was estimated, or distribution packages may have backported patches without a version change. Check the evidence section."],
          ["Why does the upgrade recommendation skip a major version?", "Some vulnerabilities are only fixed in a new major version; the recommendation is the lowest version that fixes all known vulnerabilities."],
          ["A scan failed.", "Check the Log tab on the scan page; check the worker and database status on the System status page."],
        ] } },
      ],
    },
  ],
  api: {
    title: "API",
    groupsHead: ["Path", "Role", "Description"],
    groups: [
      ["/api/auth/*", "everyone", "Login, logout, current user, language, password change"],
      ["/api/orgs", "administrator (write)", "Organisations and allowed domains"],
      ["/api/users", "administrator", "User management"],
      ["/api/projects", "all (scoped)", "Projects, report language, license policy, Jira key"],
      ["/api/projects/{id}/targets, /api/targets/*", "all (scoped)", "Targets, file upload / delete, start scan"],
      ["/api/scans/*", "all (scoped)", "Scans, log, cancel, components, changes, reports"],
      ["/api/findings/*", "all (scoped)", "Finding list / details, status, comments, Jira issue"],
      ["/api/schedules/*", "all (database: administrator)", "Schedules and cron preview"],
      ["/api/notifications/*", "administrator", "Notification channels and test messages"],
      ["/api/settings, /api/vulndb/*", "administrator", "Settings, vulnerability database status and update"],
      ["/api/system/*", "administrator / analyst", "System status, self-scan, latest version check"],
      ["/api/jira/*", "administrator / all", "Jira connection test and status"],
      ["/api/dashboard, /api/audit", "all / administrator", "Dashboard summary, audit log"],
    ],
    fullListTitle: "All endpoints (live schema)",
    fullListNote: "The API uses the session cookie: log in with /api/auth/login first; for POST / PUT / PATCH / DELETE requests send the value of the scakit_csrf cookie in the X-CSRF-Token header. API tokens for machine-to-machine use (CI/CD) are on the roadmap.",
  },
};
export default c;
