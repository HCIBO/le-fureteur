import { GuideContent } from "./types";

const c: GuideContent = {
  intro:
    "Le Fureteur ist eine Plattform für Software-Kompositionsanalyse (SCA). Sie ermittelt die Drittanbieter-Komponenten in Software (Open-Source-Bibliotheken, Frameworks, Betriebssystempakete), gleicht sie mit bekannten Sicherheitslücken ab und erstellt einen Behebungsplan. Sie wird auf dem eigenen Server der Organisation installiert; Quellcode, Dateien und Befunde verlassen die Organisation nicht.",
  sections: [
    {
      id: "what",
      title: "Wofür ist Le Fureteur da?",
      blocks: [
        { p: "Der größte Teil des Codes einer modernen Anwendung wird nicht von der Organisation selbst geschrieben, sondern stammt aus externen Komponenten. Hat eine davon eine Schwachstelle (z. B. Log4Shell), ist auch die Anwendung betroffen. Le Fureteur beantwortet:" },
        { ul: [
          "Welche Komponenten in welchen Versionen enthält die Anwendung? (Inventar / SBOM)",
          "Welche davon haben bekannte Schwachstellen, und wie schwerwiegend sind sie?",
          "Welche werden derzeit aktiv von Angreifern ausgenutzt (CISA KEV)?",
          "Welche Version behebt sie, und was sollte zuerst behoben werden?",
          "Entsprechen die Lizenzen der Richtlinie der Organisation? Gibt es Lieferkettenrisiken (Dependency Confusion, nicht gepflegte Pakete)?",
        ] },
        { p: "Ergebnisse: priorisierte Befundliste, Bericht mit Management-Zusammenfassung (HTML / PDF / Word), CSV und standardisierte SBOM-Dateien (CycloneDX, SPDX)." },
      ],
    },
    {
      id: "how",
      title: "Funktionsweise",
      blocks: [
        { ol: [
          "Erfassung: Komponenten werden je nach Zieltyp ermittelt — Lock-Dateien, Paketdatenbanken, Metadaten von Build-Artefakten, Web-Antworten, Inhalte mobiler Apps.",
          "Inventar: Erkennungen derselben Komponente an verschiedenen Stellen werden zusammengeführt; für jede Komponente werden Ökosystem, Version, Konfidenz, direkte / transitive Beziehung und Nachweis (Dateipfad / URL) gespeichert.",
          "Abgleich: Das Inventar wird mit der Offline-Schwachstellendatenbank auf dem Server abgeglichen (OSV; NVD für Serversoftware außerhalb der OSV-Abdeckung), mit ökosystemspezifischem Versionsvergleich.",
          "Anreicherung: Jeder Befund erhält CVSS-Schweregrad, EPSS-Ausnutzungswahrscheinlichkeit und CISA-KEV-Status; die korrigierte Version wird berechnet.",
          "Priorisierung: Schadpaket → aktive Ausnutzung (KEV) → Schweregrad → EPSS.",
          "Berichte und Nachverfolgung: Befunde werden gespeichert; erneute Scans verfolgen neue / behobene / wieder geöffnete Befunde.",
        ] },
        { note: "Die Analyse läuft vollständig auf dem Server und offline. Weder Quellcode noch Inventar werden an Dienste Dritter übermittelt. Das Internet wird nur (optional) zur Aktualisierung der Schwachstellendatenbank genutzt." },
      ],
    },
    {
      id: "types",
      title: "Analysearten und unterstützte Eingaben",
      blocks: [
        { table: { head: ["Art", "Eingabe", "Was erkannt wird"], rows: [
          ["Whitebox — Quellcode", "Quellcode-Archiv (zip / tar) oder Abhängigkeitsdateien", "npm / yarn / pnpm, PyPI (requirements, Poetry, Pipfile), Maven / Gradle, Go, Composer, NuGet, Cargo, RubyGems, Pub, CocoaPods, SwiftPM; Nutzungsanalyse (Importe)"],
          ["Whitebox — Build", "JAR / WAR / EAR", "Verschachtelte JARs und Maven-Metadaten"],
          ["Whitebox — Container", "Mit docker save gespeichertes Image (.tar)", "Betriebssystempakete (Debian / Ubuntu / Alpine / RHEL-Familie) und Anwendungsabhängigkeiten im Image"],
          ["Whitebox — Paketliste", "Ausgabe von dpkg / rpm / apk", "Betriebssystempakete (Distribution und Release angeben, z. B. Debian:12)"],
          ["Blackbox — Web", "Webadresse", "An den Browser ausgelieferte JavaScript- / CSS-Bibliotheken, CDN-URLs, Source Maps, Lizenzmanifeste, versionsoffenlegende Header und Fehlerseiten, CMS-Versionen"],
          ["Blackbox — Mobil", "APK / IPA", "In die App eingebettete Bibliotheken (mit FairPlay verschlüsselte IPAs können nicht analysiert werden)"],
          ["Blackbox — Desktop", "Installer (.exe / .msi), Electron-App", "Eingebettete DLLs, .NET-Assemblies, Electron- / Node-Pakete"],
        ] } },
        { p: "Die Konfidenz eines Befunds (hoch / mittel / niedrig) zeigt, wie genau die Version bestimmt wurde. Eine Blackbox-Analyse sieht nur von außen sichtbare Komponenten; serverseitige Bibliotheken erfordern eine Whitebox-Analyse." },
      ],
    },
    {
      id: "webaccess",
      title: "Hindernisse beim Web-Scan und Lösungen",
      blocks: [
        {"p": "Web-Ziele werden von außen gescannt; manche Seiten blockieren automatisierte Anfragen. Le Fureteur erkennt die Art der Sperre und zeigt Ursache und Ein-Klick-Lösungen auf der Scan-Seite. Die meisten Fälle lösen sich von selbst."},
        {"table": {"head": ["Situation", "Was passiert?"], "rows": [["WAF / Bot-Schutz (TLS-Fingerabdruck)", "Mit HTTP-Client „Automatisch“ wechselt der Scan bei einer Sperre sofort zu browser-kompatiblem TLS (curl_cffi) und läuft weiter."], ["JavaScript-Prüfung / CAPTCHA", "Wird nicht automatisch bestanden. Der Browser-Helfer öffnet auf Ihrem Rechner einen sichtbaren Browser; Sie bestehen die Prüfung, Crawlen und Hochladen laufen automatisch. Oder HAR- / Burp-Aufzeichnung hochladen."], ["Geo-Sperre, IP-Sperre, Zeitüberschreitung", "Vom Admin definierte Ausgangspunkte (HTTP- / SOCKS5-Proxys) werden im Automatikmodus nacheinander probiert; einer kann pro Ziel festgelegt werden."], ["Umleitung zu Login / SSO", "Authentifizierung (Formular, Cookie, Bearer, Basic) auf der Zielseite einrichten oder im Browser-Helfer selbst anmelden."], ["Ratenbegrenzung (429 / 503)", "Wartet die angegebene Zeit, verlangsamt und wiederholt die Anfrage einmal."], ["TLS-Zertifikatsfehler", "In vertrauenswürdigen internen Umgebungen TLS-Prüfung per Klick deaktivieren und neu scannen."], ["DNS, Verbindung abgelehnt, mTLS, Wartung", "Ursache und nächste Schritte werden auf der Scan-Seite erklärt."]]}},
        {"ul": ["Von den Seiten geladene JS- / CSS-Dateien anderer Domains (CDN) werden ebenfalls analysiert; Tracking-Skripte werden übersprungen, diese Server werden nicht gecrawlt.", "Bei Umleitungen wie linkedin.com → www.linkedin.com läuft der Scan auf der neuen Adresse weiter.", "Bei Datei-Zielen ohne Komponenten werden Ursache (keine Lock-Datei, verschlüsselte IPA, geschützte APK, Distroless-Image, nicht unterstütztes Archiv) und Befehle zur Abhilfe angezeigt."]},
        {"note": "Der Schutz des internen Netzes gilt immer: Auch über Proxy oder den browser-kompatiblen Client verbindet sich der Scan nie mit internen Adressen (außer ein Admin erlaubt es ausdrücklich)."},
      ],
    },
    {
      id: "glossary",
      title: "Glossar",
      blocks: [
        { table: { head: ["Begriff", "Bedeutung"], rows: [
          ["SCA", "Software Composition Analysis — Analyse der Drittanbieter-Komponenten einer Software und ihrer Risiken."],
          ["SBOM", "Software Bill of Materials — Stückliste der Komponenten einer Software. Standards: CycloneDX und SPDX."],
          ["CVE", "Universelle Kennung einer Schwachstelle (z. B. CVE-2021-44228)."],
          ["GHSA / OSV", "GitHub-Security-Advisory-Kennung / offene Schwachstellendatenbank von Google mit betroffenen Versionsbereichen je Ökosystem."],
          ["NVD / CPE", "US-amerikanische National Vulnerability Database / Produktbenennungsschema; für Serversoftware außerhalb von OSV."],
          ["CVSS", "Technischer Schweregrad einer Schwachstelle (0–10)."],
          ["EPSS", "Wahrscheinlichkeit, dass eine Schwachstelle in den nächsten 30 Tagen ausgenutzt wird (FIRST)."],
          ["KEV", "Liste der CISA mit Schwachstellen, deren aktive Ausnutzung bekannt ist — höchste Priorität."],
          ["PURL", "Package URL — ökosystemunabhängige Kennung einer Komponente (z. B. pkg:npm/lodash@4.17.20)."],
          ["Direkte / transitive Abhängigkeit", "Von der Anwendung selbst hinzugefügtes Paket / über ein anderes Paket eingebundenes Paket."],
          ["Dependency Confusion", "Ein interner Paketname, der auch in einer öffentlichen Registry existiert; ein Angreifer kann dort ein gefälschtes Paket veröffentlichen."],
          ["Copyleft", "Lizenzen, die verlangen, dass abgeleitete Software unter derselben Lizenz veröffentlicht wird (GPL, AGPL …)."],
        ] } },
      ],
    },
    {
      id: "roles",
      title: "Rollen und Berechtigungen",
      blocks: [
        { table: { head: ["Rolle", "Berechtigungen"], rows: [
          ["Administrator", "Alles: Benutzer, Organisationen, Einstellungen (NVD-Schlüssel, SMTP, Jira), Schwachstellendatenbank, Benachrichtigungskanäle, Systemstatus, Audit-Log."],
          ["Analyst", "Projekte, Ziele, Scans und Befunde in allen Organisationen; Systemstatus einsehen. Kann keine Einstellungen ändern."],
          ["Kunde", "Nur die eigene Organisation: legt Projekte und Ziele an, lädt Dateien hoch, scannt, verwaltet den Befundstatus, sendet an Jira, lädt Berichte herunter. Kann als Webziele nur die für die Organisation freigegebenen Domains anlegen."],
        ] } },
      ],
    },
    {
      id: "start",
      title: "Schritt für Schritt",
      blocks: [
        { ol: [
          "Administrator: Einstellungen → Datenbank aktualisieren (bei der Erstinstallation Pflicht) und die Empfehlungen auf der Seite Systemstatus prüfen.",
          "Organisationen → Kundenorganisation anlegen; für Web-Scans die freigegebenen Domains eintragen (beispiel.de oder *.beispiel.de).",
          "Benutzer → Analysten- und Kundenkonten anlegen.",
          "Projekte → neues Projekt; Berichtssprache, Lizenzrichtlinie und Jira-Projektschlüssel lassen sich in den Projekteinstellungen festlegen.",
          "Ziel hinzufügen → Webadresse (Blackbox) oder Datei-Upload (Quellcode, APK, IPA, Image, Installer).",
          "Scan starten → Fortschritt und Log werden auf der Scan-Seite angezeigt.",
          "Befunde → filtern, Details öffnen, Status setzen, kommentieren, an Jira senden.",
          "Scan → Registerkarte Berichte: Bericht und SBOM-Dateien herunterladen.",
          "Auf der Zielseite einen geplanten Scan für regelmäßige erneute Scans hinzufügen.",
        ] },
        { note: "Scannen Sie nur Systeme, für die eine schriftliche Genehmigung vorliegt. Interne Netzwerkadressen sind standardmäßig gesperrt; ein Administrator kann sie in den Einstellungen zulassen." },
      ],
    },
    {
      id: "findings",
      title: "Befunde und ihr Lebenszyklus",
      blocks: [
        { p: "Ein Befund = eine Komponente + eine Schwachstelle auf einem Ziel. Derselbe Befund ist über Scans hinweg eindeutig; Zeitpunkte der ersten und letzten Erkennung bleiben erhalten." },
        { table: { head: ["Status", "Bedeutung"], rows: [
          ["Offen", "Neu gefunden, wartet auf Bearbeitung."],
          ["In Bearbeitung", "Die Behebung hat begonnen."],
          ["Akzeptiertes Risiko", "Bewusst akzeptiert (Begründung erforderlich). Erscheint in einem eigenen Abschnitt des Berichts."],
          ["Falsch-positiv", "Der Befund ist falsch (Begründung erforderlich)."],
          ["Nicht betroffen", "Die Komponente ist vorhanden, die Schwachstelle kann in dieser Nutzung aber nicht ausgelöst werden (Begründung erforderlich)."],
          ["Behoben", "Automatisch: Komponente / Version wird bei einem erneuten Scan nicht mehr gefunden. Taucht sie wieder auf, wird der Befund erneut geöffnet."],
        ] } },
        { p: "Die Registerkarte Änderungen eines Scans zeigt neue, behobene und wieder geöffnete Befunde im Vergleich zum vorherigen Scan. Nach Statusänderungen kann der Bericht neu erzeugt werden." },
        {"p": "Die Suche auf der Befundseite durchsucht Domain, Ziel, Projekt, Kunde, Komponente, Version, CVE / GHSA und Beschreibung; mehrere Wörter liefern Befunde, die alle enthalten. Filter für Ökosystem, Fix vorhanden / nicht, erstmals gesehen und Zieltyp; die gefilterte Liste lässt sich als CSV herunterladen. Hat das gesuchte Ziel keine Befunde, werden passende Ziele mit Links angezeigt."},
      ],
    },
    {
      id: "collaboration",
      title: "Teamarbeit: Zuweisung, Freigabe, Diskussion, Nachrichten",
      blocks: [
        { p: "Le Fureteur enthält Werkzeuge zur Zusammenarbeit: wer welchen Befund bis wann und mit welcher Entscheidung behebt." },
        { ul: [
          "Teams: Jedes Team hat eine Leitung, Verantwortliche und ihnen zugeordnete Mitglieder. Die Teamseite zeigt Organigramm, Auslastung pro Person, Arbeitswarteschlange und die Ergebnisse der letzten 30 Tage.",
          "Zuweisung: Ein Befund wird einer Person mit Frist zugewiesen; sie wird benachrichtigt. Sammelzuweisung ist im Befundbildschirm möglich.",
          "Freigabeprozess: Entscheidungen „Risiko akzeptiert“, „Falsch positiv“ und „Nicht betroffen“ gehen an Verantwortliche / Teamleitung zur Freigabe. Bearbeitete Anfragen bleiben unter Freigaben → Von mir entschieden.",
          "Diskussionsraum: Bei Meinungsverschiedenheiten zu einem Befund wird eine Diskussion eröffnet und Beteiligte hinzugefügt. Ohne Einigung wird an die Führungskraft eskaliert, die entscheidet oder delegiert. Das Ergebnis steht im Befundverlauf.",
          "Nachrichten: an Personen oder ein ganzes Team. Ein Haken = gesendet, zwei graue = zugestellt, zwei blaue = gelesen. Nicht-Leser können einmal pro Stunde erinnert werden.",
          "Erinnerungen: zeitgesteuerte Notizen, auch aus einem Befund oder einer Nachricht. Zum Termin erscheinen sie in den Benachrichtigungen.",
        ] },
        { note: "Kundenbenutzer sehen nur Personen ihrer Organisation und das Beratungsteam; Befunde, Diskussionen oder Nachrichten anderer Organisationen sind nie sichtbar." },
      ],
    },
    {
      id: "reports",
      title: "Berichte und Ergebnisse",
      blocks: [
        { table: { head: ["Datei", "Inhalt"], rows: [
          ["bericht.html / .pdf / .docx", "Management-Zusammenfassung, Behebungsplan, Befunddetails, Nutzungsanalyse, Lizenzkonformität, Lieferkette, Einschränkungen des Umfangs, Anhänge (Inventar, Fundorte)."],
          ["befunde.csv", "Befundliste für Tabellenkalkulationen und andere Werkzeuge."],
          ["sbom.cdx.json", "CycloneDX-1.5-SBOM."],
          ["sbom.spdx.json", "SPDX-2.3-SBOM."],
        ] } },
        { p: "Die Berichtssprache wird in den Projekteinstellungen gewählt: Türkisch, Englisch, Französisch, Deutsch." },
      ],
    },
    {
      id: "automation",
      title: "Zeitplanung, Benachrichtigungen und Jira",
      blocks: [
        { ul: [
          "Kontinuierlicher / geplanter Scan: auf der Zielseite oder für alle Ziele unter Projekt → Trend und kontinuierliches Scannen; per Assistent (Tage, Zeitfenster, Häufigkeit) oder Cron-Ausdruck. Höchstens stündlich. Gleichzeitig startende Scans folgen der Projekt-Warteschlangenregel.",
          "Geplante Datenbankaktualisierung: über die Seite Einstellungen (Administrator); empfohlen einmal täglich.",
          "Benachrichtigungen (Administrator): Slack, Microsoft Teams, E-Mail oder generischer Webhook. Ereignisse: Scan abgeschlossen / fehlgeschlagen, neue Befunde über dem Schwellenwert, neuer KEV-Befund, Datenbankaktualisierung fehlgeschlagen. Ein Kanal kann auf eine Organisation beschränkt werden. Webhook-Inhalte können mit HMAC-SHA256 signiert werden (X-Scakit-Signature).",
          "Jira (Cloud und Server / Data Center): mehrere Jira-Verbindungen möglich; der Admin legt fest, wer (Rollen, Benutzer) und für welche Kunden jede genutzt werden darf. Bei „Zu Jira hinzufügen“ wird bei mehreren erlaubten Verbindungen gefragt welche; nicht, wenn das Projekt ein Standard-Jira hat. Kein zweites Ticket für denselben Befund; optional automatische Tickets und Kommentare bei Behebung / Wiederöffnung.",
        ] },
      ],
    },
    {
      id: "queue",
      title: "Scan-Warteschlange, kontinuierliches Scannen und Trend",
      blocks: [
        {"ul": ["Warteschlangen-Panel (Seite Scans): laufende und wartende Scans; Admins und Analysten können umsortieren (nach vorn, hoch / runter, ans Ende).", "Projekt-Warteschlangenregel: Die Scans eines Projekts (manuell, gesammelt, geplant) laufen untereinander nacheinander, höchstens N gleichzeitig oder frei, optional mit Pause. Andere Projekte sind nicht betroffen.", "Beim Hinzufügen von Zielen legt die Karte „Warteschlange (für diese Scans)“ eine Regel nur für diese Scans fest oder macht sie zum Projektstandard. Startmenü auf der Zielseite: nach vorn / normal / ans Ende.", "Serverweite Regeln (Admin, Einstellungen → Scan-Warteschlange): Scans pro Worker und Pause zwischen Scans — Obergrenze für Projektregeln.", "Kontinuierliches Scannen: unter Projekt → Trend und kontinuierliches Scannen Tage, Zeitfenster und Häufigkeit wählen und auf alle Ziele anwenden (z. B. werktags 09–18 Uhr alle 3 Std., zweimal pro Woche).", "Trend: auf Dashboard, Projekt- und Zielseite — offene, neue und behobene Befunde pro Stunde / Tag / Woche und die Änderung zum Vorzeitraum; Größen Klein / Mittel / Groß und Tabellenansicht."]},
      ],
    },
    {
      id: "vulndb",
      title: "Schwachstellendatenbank",
      blocks: [
        { p: "Der Abgleich nutzt eine lokale Datenbank auf dem Server. Quellen: OSV (Paket-Ökosysteme und Linux-Distributionen), EPSS, CISA KEV und optional NVD (API-Schlüssel empfohlen)." },
        { ul: [
          "Aktualisierung: Einstellungen → Datenbank aktualisieren, oder geplante Aktualisierung.",
          "Installation ohne Internet: auf einem anderen Rechner mit `scakit db download ordner` herunterladen, den Ordner auf den Server kopieren und den Pfad in den Einstellungen angeben.",
          "Aktualität: Die Seite Systemstatus zeigt das Alter jeder Quelle; veraltete Daten lösen eine Warnung aus.",
          "Scans laufen während der Datenbankaktualisierung weiter (mit den zuletzt gespeicherten Daten). Ein beschädigt heruntergeladenes Archiv wird übersprungen und bei der nächsten Aktualisierung neu geladen.",
          "Schritt-für-Schritt-Anleitung für abgeschottete Netze und Download: Seite Kommandozeile (scakit).",
        ] },
      ],
    },
    {
      id: "system",
      title: "Systemstatus und Selbstscan",
      blocks: [
        { p: "Die Seite Systemstatus (Administrator / Analyst) zeigt den Zustand der Anwendung selbst: Worker, Auftragswarteschlange, Festplatte, Datenbank, Aktualität der Schwachstellendaten, externe Werkzeuge und Konfigurationsprüfungen — jeweils mit empfohlener Maßnahme." },
        { ul: [
          "Selbstscan: Le Fureteur scannt seine eigenen Python-, Frontend- und Betriebssystempakete mit der eigenen Schwachstellendatenbank und empfiehlt Aktualisierungen (offline).",
          "Prüfung auf neueste Versionen (Administrator, optional): Nur die Namen der eigenen Open-Source-Abhängigkeiten von Le Fureteur werden bei PyPI und npm abgefragt; es werden keine Kundendaten übermittelt.",
        ] },
      ],
    },
    {
      id: "security",
      title: "Sicherheit und Datenschutz",
      blocks: [
        { ul: [
          "On-Premises: Code, Dateien, Befunde und Berichte bleiben auf dem Server der Organisation.",
          "Passwörter werden mit Argon2 gespeichert; Sitzungs-Cookie httpOnly + SameSite=Strict; CSRF-Schutz für alle ändernden Anfragen; Begrenzung von Anmeldeversuchen.",
          "Geheime Einstellungen (NVD-Schlüssel, SMTP-Passwort, Jira-Token, Webhook-URLs) werden verschlüsselt gespeichert und nie an die Oberfläche zurückgegeben.",
          "Zielschutz: nur http / https; Kunden können nur freigegebene Domains scannen; interne Netzwerk- und Cloud-Metadatenadressen sind standardmäßig gesperrt; die Prüfung wird beim Scanstart wiederholt.",
          "Mandantentrennung: Kundenbenutzer sehen keine Daten anderer Organisationen.",
          "Audit-Log: Anmeldungen, Einstellungen, Ziele, Scans, Statusänderungen, Jira und Berichts-Downloads werden protokolliert.",
          "In der Produktion hinter HTTPS betreiben (SCAKIT_COOKIE_SECURE=1).",
        ] },
      ],
    },
    {
      id: "toolset",
      title: "Werkzeuge",
      blocks: [
        { p: "Kleine, sichere Werkzeuge für den Alltag: HTTP-Client, Kodierer / Dekodierer (Base64, URL, HTML, Hex, Unicode, JWT, SHA), TCP-Ping und ein persönliches Notizbuch." },
        { ul: [
          "HTTP-Client und Ping verbinden sich nie mit internen Adressen (127.0.0.1, 10.x, 169.254.169.254 usw.); auch Weiterleitungen werden geprüft.",
          "Ihr Sitzungscookie wird nie an das Ziel gesendet, nur Ihre eigenen Header. Jede Anfrage wird protokolliert und pro Minute begrenzt.",
          "Der Kodierer läuft vollständig im Browser. Das Notizbuch sehen nur Sie.",
          "Für Kundenbenutzer sind Netzwerkwerkzeuge standardmäßig deaktiviert; aktiviert erreichen sie nur erlaubte Domains (Einstellungen → Werkzeuge).",
        ] },
      ],
    },
    {
      id: "admin",
      title: "Verwaltung: Wartungsmodus, Sitzungen, Audit",
      blocks: [
        { ul: [
          "Wartungsmodus (Systemstatus → Wartung): Nur Administratoren können sich anmelden; andere Benutzer und API-Token sehen eine Wartungsseite, geplante Scans starten nicht.",
          "Anmelde- und API-Limits (Einstellungen → Sicherheit & Zugriff): Fehlanmeldungen, Sperrdauer und API-Anfragen pro Benutzer und Minute.",
          "Benutzerdetails: Anmeldeverlauf (Erfolg / Fehler, IP, Gerät), aktive Sitzungen und letzte Aktionen. Alle Sitzungen lassen sich mit einem Klick beenden. Jede Person sieht eigene Sitzungen unter Mein Konto.",
          "Audit-Log: Filter nach Benutzer, Aktion, Objekttyp, IP und Zeitraum; CSV-Export.",
          "Sicherung: `scakit server backup datei --encrypt` erstellt eine verschlüsselte Sicherung; Wiederherstellung nur in eine leere Installation.",
        ] },
      ],
    },
    {
      id: "cli",
      title: "Kommandozeile (CLI)",
      blocks: [
        { p: "Dieselbe Analyse-Engine ist für Beratungsprojekte auch über die Kommandozeile nutzbar:" },
        { code: "scakit init ~/projekte/kunde --name \"Portal 2026\" --client \"Kunde\" --lang de\nscakit add ~/projekte/kunde ./quellcode.zip app.apk https://beispiel.de\nscakit db update\nscakit match ~/projekte/kunde\nscakit report ~/projekte/kunde --formats html,pdf,docx,cdx,spdx\n\n# Webserver\nscakit server init --email admin@firma.de\nscakit server run --port 8800\nscakit server worker" },
        {"note": "Was scakit ist, Installation, alle Befehle und die Vorbereitung der Datenbank für abgeschottete Netze: siehe Seite Kommandozeile (scakit) im Menü; Admins und Analysten können das Paket dort herunterladen."},
      ],
    },
    {
      id: "faq",
      title: "Häufige Fragen",
      blocks: [
        { table: { head: ["Frage", "Antwort"], rows: [
          ["Keine Befunde — ist die Anwendung sicher?", "Nein, es bedeutet nur, dass keine Komponente mit bekannter Schwachstelle gefunden wurde. Eine Blackbox-Analyse sieht keine serverseitigen Komponenten; Einschränkungen des Umfangs stehen im Bericht."],
          ["Warum ist die Konfidenz eines Befunds niedrig?", "Die Version wurde geschätzt, oder in Distributionspaketen wurden Korrekturen ohne Versionsänderung zurückportiert. Prüfen Sie den Nachweisabschnitt."],
          ["Warum überspringt die Empfehlung eine Hauptversion?", "Manche Schwachstellen sind nur in einer neuen Hauptversion behoben; empfohlen wird die niedrigste Version, die alle bekannten Schwachstellen behebt."],
          ["Ein Scan ist fehlgeschlagen.", "Prüfen Sie die Registerkarte Log auf der Scan-Seite sowie den Worker- und Datenbankstatus auf der Seite Systemstatus."],
        ] } },
      ],
    },
  ],
  api: {
    title: "API",
    groupsHead: ["Pfad", "Rolle", "Beschreibung"],
    groups: [
      ["/api/auth/*", "alle", "Anmeldung, Abmeldung, aktueller Benutzer, Sprache, Passwortänderung"],
      ["/api/orgs", "Administrator (schreibend)", "Organisationen und freigegebene Domains"],
      ["/api/users", "Administrator", "Benutzerverwaltung"],
      ["/api/projects", "alle (eingeschränkt)", "Projekte, Berichtssprache, Lizenzrichtlinie, Jira-Schlüssel"],
      ["/api/projects/{id}/targets, /api/targets/*", "alle (eingeschränkt)", "Ziele, Datei-Upload / -Löschung, Scanstart"],
      ["/api/scans/*", "alle (eingeschränkt)", "Scans, Log, Abbruch, Komponenten, Änderungen, Berichte"],
      ["/api/findings/*", "alle (eingeschränkt)", "Befundliste / -details, Status, Kommentare, Jira-Ticket"],
      ["/api/schedules/*", "alle (Datenbank: Administrator)", "Zeitpläne und Cron-Vorschau"],
      ["/api/notifications/*", "Administrator", "Benachrichtigungskanäle und Testnachrichten"],
      ["/api/settings, /api/vulndb/*", "Administrator", "Einstellungen, Status und Aktualisierung der Schwachstellendatenbank"],
      ["/api/system/*", "Administrator / Analyst", "Systemstatus, Selbstscan, Prüfung auf neueste Versionen"],
      ["/api/jira/*", "Administrator / alle", "Jira-Verbindungstest und -Status"],
      ["/api/dashboard, /api/audit", "alle / Administrator", "Dashboard-Übersicht, Audit-Log"],
    ],
    fullListTitle: "Alle Endpunkte (Live-Schema)",
    fullListNote: "Die API verwendet das Sitzungs-Cookie: zuerst über /api/auth/login anmelden; bei POST / PUT / PATCH / DELETE den Wert des Cookies scakit_csrf im Header X-CSRF-Token senden. API-Token für die Maschine-zu-Maschine-Nutzung (CI/CD) sind in der Roadmap.",
  },
};
export default c;
