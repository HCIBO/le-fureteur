FR = {
    "title": "Rapport d'analyse de la composition logicielle (SCA)",
    "client": "Client",
    "engagement": "Mission",
    "date": "Date du rapport",
    "db_state": "État de la base de vulnérabilités",
    "summary": "Synthèse",
    "components": "Composants",
    "affected": "Composants vulnérables",
    "findings": "Constats",
    "kev": "Exploitées activement (CISA KEV)",
    "malicious": "Paquet malveillant",
    "sev": {"CRITICAL": "Critique", "HIGH": "Élevée", "MEDIUM": "Moyenne", "LOW": "Faible", "UNKNOWN": "Indéterminée",
            "NONE": "Aucune"},
    "plan": "Plan de remédiation (par priorité)",
    "plan_intro": ("Pour chaque composant, la version minimale corrigeant toutes les vulnérabilités connues est "
                   "recommandée. Ordre : paquet malveillant, exploitation avérée (KEV), sévérité, probabilité "
                   "d'exploitation (EPSS)."),
    "component": "Composant",
    "current": "Version actuelle",
    "recommended": "Version recommandée",
    "no_fix": "Aucune version corrigée",
    "vulns": "Vulnérabilités",
    "relation": "Relation",
    "direct": "Directe",
    "transitive": "Transitive",
    "via": "via",
    "details": "Détail des constats",
    "id": "Identifiant",
    "severity": "Sévérité",
    "fix": "Correctif",
    "confidence": "Confiance",
    "evidence": "Preuve",
    "conf": {"high": "Élevée", "medium": "Moyenne", "low": "Faible"},
    "inventory": "Inventaire des composants",
    "ecosystem": "Écosystème",
    "version": "Version",
    "license": "Licence",
    "scope": "Périmètre et méthode",
    "runs": "Sources analysées",
    "kind": {"source": "Boîte blanche – fichiers source / de dépendances",
             "archive": "Boîte blanche – artefact compilé",
             "image": "Boîte blanche – image de conteneur",
             "web": "Boîte noire – application web",
             "apk": "Boîte noire – application Android",
             "ipa": "Boîte noire – application iOS",
             "list": "Boîte blanche – liste de paquets",
             "desktop": "Boîte noire – application de bureau", "sbom": "Import de SBOM",
             "traffic": "Trafic navigateur / proxy (HAR, Burp)"},
    "limits": "Limites du périmètre et observations",
    "lim_unversioned": ("Les composants dont la version n'a pas pu être déterminée n'ont pas pu être rapprochés des "
                        "vulnérabilités"),
    "lim_estimated": "Composants dont la version a été estimée ou déterminée avec une confiance moyenne/faible",
    "lim_nocov": ("Composants appartenant à des écosystèmes non couverts par la base de vulnérabilités (inventaire "
                  "uniquement)"),
    "lim_blackbox": (
        "L'analyse en boîte noire ne permet d'identifier que les composants observables de l'extérieur. Les "
        "bibliothèques côté serveur qui ne laissent aucune trace dans les réponses ne peuvent pas être détectées ainsi ; "
        "l'absence d'une vulnérabilité dans cette section ne signifie pas que l'application n'est pas concernée."),
    "obs": {"missing-lockfile": "Pas de fichier de verrouillage — dépendances transitives et versions exactes possiblement manquantes",
            "dev-excluded": "Les dépendances de développement / test ont été exclues",
            "missing-sri": "Pas de Subresource Integrity (SRI) sur un script chargé depuis une origine externe",
            "sourcemap-exposed": "Fichier source map JavaScript accessible publiquement",
            "exposed-file": "Fichier de dépendances accessible via le web",
            "version-header": "Version du logiciel serveur divulguée dans un en-tête de réponse",
            "obfuscated": "Obfuscation de code détectée — certaines versions de composants peuvent être indéterminables",
            "unsupported-layer": "Format de couche d'image non pris en charge ignoré",
            "version-error-page": "Version du serveur / framework divulguée sur une page d'erreur",
            "version-disclosure": "Informations de version de la plateforme accessibles (fichier / flux de version du CMS)",
            "license-manifest": "Manifeste de licences tierces accessible (liste de paquets ; généralement sans version)",
            "private-registry": ("Paquet résolu depuis un registre interne — à vérifier au regard de la confusion de "
                                 "dépendances"),
            "internal-package": "Paquet interne (liste WB-31)",
            "dependency-confusion": "Risque de confusion de dépendances",
            "stale-package": "Aucune nouvelle version depuis longtemps (possiblement non maintenu)",
            "deprecated-package": "Version de paquet obsolète (deprecated)",
            "no-osv-coverage": "Aucun rapprochement automatique de vulnérabilités pour ce type de composant"},
    "method_text": (
        "Les composants ont été identifiés à partir des fichiers de dépendances / de verrouillage, de sorties de "
        "commandes, des métadonnées d'artefacts compilés, des bases de paquets des images de conteneurs et (boîte "
        "noire) de traces observées de l'extérieur. Les vulnérabilités ont été rapprochées à l'aide d'une copie hors "
        "ligne de la base OSV.dev ; la probabilité d'exploitation provient de FIRST EPSS et l'exploitation avérée du "
        "catalogue CISA KEV. Aucun code source ni inventaire n'a été transmis à des services en ligne tiers pendant "
        "l'analyse."),
    "none": "Aucun constat.",
    "count_line": "{f} constats sur {n} composants",
    "target": "Cible",
    "source": "Source",
    "time": "Heure",
    "detections": "Détections",
    "more": "… et {n} autres preuves",
    "summary_text": (
        "{n} composants ont été identifiés, dont {a} présentent des vulnérabilités connues. Sur {f} constats au "
        "total, {c} sont critiques et {h} de sévérité élevée."),
    "kev_text": ("{k} constats concernent des vulnérabilités dont l'exploitation active est confirmée par la CISA ; "
                 "ils doivent être corrigés en priorité."),
    "mal_text": ("{m} composants sont signalés comme paquets malveillants ; supprimez-les immédiatement et examinez "
                 "les systèmes."),
    "top_actions": "Actions prioritaires",
    "usage": {"imported": "importé dans le code", "not-imported": "aucun import direct observé dans le code"},
    "reach": {"called": "La fonction concernée est appelée", "not-called": "Aucun appel à la fonction concernée observé"},
    "usage_title": "Analyse d'utilisation",
    "usage_text": (
        "Le code source (boîte blanche) a été analysé pour déterminer si les paquets sont importés (JS/TS, Python, "
        "Java/Kotlin, C#, Go, Ruby). Pour les composants Go, l'appel des fonctions concernées par une vulnérabilité a "
        "également été vérifié. Il ne s'agit pas d'un graphe d'appels complet : des bibliothèques chargées "
        "indirectement à l'exécution (journalisation, pilotes, extensions) peuvent être utilisées sans être "
        "importées. Un résultat « aucun import observé » ne signifie donc pas que le composant est inutilisé ; il "
        "s'agit d'un indicateur d'aide à la priorisation."),
    "usage_stats": "{i} dépendances directes sont importées dans le code ; aucun import direct observé pour {n}.",
    "reach_stats": "Go : la fonction concernée est appelée dans {c} constats ; aucun appel observé dans {n}.",
    "nvd_note": (
        "Les logiciels serveur et bibliothèques natives hors du périmètre OSV (nginx, Apache, PHP, OpenSSL, sqlite, "
        "etc.) ont été rapprochés à l'aide des données CPE du NVD. Les paquets de distribution (Ubuntu, Debian, "
        "RHEL…) peuvent recevoir des correctifs rétroportés sans changement de version ; les constats NVD sur ces "
        "composants sont donc signalés avec une confiance faible et doivent être confirmés à l'aide des bulletins de "
        "sécurité de la distribution."),
    "lic_title": "Conformité des licences",
    "lic_text": (
        "Les licences des dépendances applicatives ont été normalisées en identifiants SPDX et évaluées selon {pol}. "
        "Les paquets du système d'exploitation et les composants détectés dans des binaires sont exclus. Cette "
        "section ne constitue pas un avis juridique ; les résultats « revue nécessaire » et « interdit » doivent être "
        "évalués par votre service juridique."),
    "pol_custom": "la politique de licences de votre organisation",
    "pol_default": ("la politique par défaut (permissives : autorisées ; LGPL/MPL/EPL/GPL : revue ; AGPL/SSPL et "
                    "licences à restriction commerciale : interdites)"),
    "decision": {"allowed": "Autorisée", "review": "Revue nécessaire", "denied": "Interdite / à risque",
                 "unknown": "Licence indéterminée"},
    "lic_cat": {"permissive": "Permissive", "weak-copyleft": "Copyleft faible", "strong-copyleft": "Copyleft fort",
                "network-copyleft": "Copyleft réseau", "restrictive": "Restrictive", "unknown": "Inconnue"},
    "decision_col": "Décision",
    "category_col": "Catégorie",
    "sc_title": "Chaîne d'approvisionnement",
    "sc_none": "Aucun risque lié à la chaîne d'approvisionnement n'a été identifié.",
    "online_method": ("Pour les contrôles de licence, de maintenance et de nom de paquet, seuls les noms et versions "
                      "des paquets ont été transmis à {svc} ; aucun code source ni fichier n'a été transmis."),
    "sup_title": "Risques acceptés et faux positifs",
    "sup_text": "Les constats suivants ont été retirés de la liste principale, avec leur justification.",
    "sup_kind": {"accepted-risk": "Risque accepté", "false-positive": "Faux positif", "not-affected": "Non concerné"},
    "reason": "Justification",
    "location": "Emplacement / Preuve",
    "target_loc": "Cible / Emplacement",
    "appendix_c": "Annexe C — Emplacements de détection",
    "appendix_c_text": ("Tous les emplacements (URL, chemin de fichier) et preuves où chaque composant vulnérable a "
                        "été détecté."),
    "method_col": "Méthode",
    "method": {"lockfile": "Fichier de verrouillage", "manifest": "Manifeste", "command-output": "Sortie de commande",
               "pkgdb": "Base de paquets", "jar-meta": "Métadonnées JAR", "installed-package": "Paquet installé",
               "signature": "Signature JS / CSS", "sourcemap": "Source map", "cdn-url": "URL CDN",
               "exposed-file": "Fichier exposé", "header": "En-tête HTTP", "meta-generator": "Meta generator",
               "query-version": "Paramètre de version dans l'URL", "license-manifest": "Manifeste de licences",
               "dex-strings": "Chaîne DEX", "binary-strings": "Chaîne binaire", "properties": "Fichier de version",
               "pe-version": "Informations de version PE", "image-config": "Configuration de l'image",
               "body-banner": "Contenu de la page", "error-page": "Page d'erreur",
               "cms-version": "Point de version du CMS", "platform": "Marqueur de plateforme", "sbom": "SBOM"},
    "upgrade_line": "{c} → {v} ({n} vulnérabilités)",
    "confidential": "CONFIDENTIEL",
    "page": "Page",
    "prepared": "Établi le",
    "toc": "Sommaire",
    "details_main": "Détail des constats (critiques, élevés et exploités activement)",
    "appendix_a": "Annexe A — Constats moyens, faibles et indéterminés",
    "appendix_b": "Annexe B — Inventaire des composants",
    "sev_dist": "Répartition par sévérité",
    "scope_table": "Sources analysées",
    "source_col": "Source",
    "status": "Statut",
    "inv_note": ("L'inventaire complet lisible par machine est livré séparément sous forme de fichier SBOM "
                 "CycloneDX."),
    "detail_col": "Détail",
}

DE = {
    "title": "Bericht zur Software-Kompositionsanalyse (SCA)",
    "client": "Kunde",
    "engagement": "Auftrag",
    "date": "Berichtsdatum",
    "db_state": "Stand der Schwachstellendatenbank",
    "summary": "Management-Zusammenfassung",
    "components": "Komponenten",
    "affected": "Verwundbare Komponenten",
    "findings": "Befunde",
    "kev": "Aktiv ausgenutzt (CISA KEV)",
    "malicious": "Schadpaket",
    "sev": {"CRITICAL": "Kritisch", "HIGH": "Hoch", "MEDIUM": "Mittel", "LOW": "Niedrig", "UNKNOWN": "Unbestimmt",
            "NONE": "Keine"},
    "plan": "Behebungsplan (nach Priorität)",
    "plan_intro": ("Für jede Komponente wird die niedrigste Version empfohlen, die alle bekannten Schwachstellen "
                   "behebt. Reihenfolge: Schadpaket, bekannte Ausnutzung (KEV), Schweregrad, "
                   "Ausnutzungswahrscheinlichkeit (EPSS)."),
    "component": "Komponente",
    "current": "Aktuelle Version",
    "recommended": "Empfohlene Version",
    "no_fix": "Keine korrigierte Version",
    "vulns": "Schwachstellen",
    "relation": "Beziehung",
    "direct": "Direkt",
    "transitive": "Transitiv",
    "via": "über",
    "details": "Befunddetails",
    "id": "Kennung",
    "severity": "Schweregrad",
    "fix": "Behebung",
    "confidence": "Konfidenz",
    "evidence": "Nachweis",
    "conf": {"high": "Hoch", "medium": "Mittel", "low": "Niedrig"},
    "inventory": "Komponenteninventar",
    "ecosystem": "Ökosystem",
    "version": "Version",
    "license": "Lizenz",
    "scope": "Umfang und Methode",
    "runs": "Analysierte Quellen",
    "kind": {"source": "Whitebox – Quell- / Abhängigkeitsdateien",
             "archive": "Whitebox – Build-Artefakt",
             "image": "Whitebox – Container-Image",
             "web": "Blackbox – Webanwendung",
             "apk": "Blackbox – Android-App",
             "ipa": "Blackbox – iOS-App",
             "list": "Whitebox – Paketliste",
             "desktop": "Blackbox – Desktop-Anwendung", "sbom": "SBOM-Import",
             "traffic": "Browser-/Proxy-Verkehr (HAR, Burp)"},
    "limits": "Einschränkungen des Umfangs und Beobachtungen",
    "lim_unversioned": ("Komponenten ohne bestimmbare Version konnten nicht mit Schwachstellen abgeglichen werden"),
    "lim_estimated": "Komponenten, deren Version geschätzt oder mit mittlerer/niedriger Konfidenz bestimmt wurde",
    "lim_nocov": ("Komponenten in Ökosystemen, die von der Schwachstellendatenbank nicht abgedeckt werden (nur "
                  "Inventar)"),
    "lim_blackbox": (
        "Eine Blackbox-Analyse kann nur von außen beobachtbare Komponenten erkennen. Serverseitige Bibliotheken, die "
        "in den Antworten keine Spuren hinterlassen, lassen sich so nicht erkennen; das Fehlen einer Schwachstelle in "
        "diesem Abschnitt bedeutet nicht, dass die Anwendung nicht betroffen ist."),
    "obs": {"missing-lockfile": "Keine Lock-Datei — transitive Abhängigkeiten und exakte Versionen fehlen möglicherweise",
            "dev-excluded": "Entwicklungs- / Testabhängigkeiten wurden ausgeschlossen",
            "missing-sri": "Keine Subresource Integrity (SRI) für ein Skript von einem externen Ursprung",
            "sourcemap-exposed": "JavaScript-Source-Map-Datei öffentlich zugänglich",
            "exposed-file": "Abhängigkeitsdatei über das Web zugänglich",
            "version-header": "Version der Serversoftware im Antwort-Header offengelegt",
            "obfuscated": "Code-Verschleierung erkannt — einige Komponentenversionen sind ggf. nicht bestimmbar",
            "unsupported-layer": "Nicht unterstütztes Image-Layer-Format übersprungen",
            "version-error-page": "Server- / Framework-Version auf Fehlerseite offengelegt",
            "version-disclosure": "Versionsinformationen der Plattform zugänglich (CMS-Versionsdatei / -Feed)",
            "license-manifest": "Lizenzmanifest von Drittanbietern zugänglich (Paketliste; meist ohne Versionen)",
            "private-registry": "Paket aus interner Registry aufgelöst — auf Dependency Confusion prüfen",
            "internal-package": "Internes Paket (WB-31-Liste)",
            "dependency-confusion": "Risiko einer Dependency Confusion",
            "stale-package": "Seit langem keine neue Version (möglicherweise nicht mehr gepflegt)",
            "deprecated-package": "Veraltete (deprecated) Paketversion",
            "no-osv-coverage": "Für diesen Komponententyp erfolgt kein automatischer Schwachstellenabgleich"},
    "method_text": (
        "Die Komponenten wurden aus Abhängigkeits- / Lock-Dateien, Befehlsausgaben, Metadaten von Build-Artefakten, "
        "Paketdatenbanken von Container-Images und (Blackbox) von außen beobachteten Spuren ermittelt. Der "
        "Schwachstellenabgleich erfolgte mit einer Offline-Kopie der OSV.dev-Datenbank; die "
        "Ausnutzungswahrscheinlichkeit stammt aus FIRST EPSS, bekannte Ausnutzungen aus dem CISA-KEV-Katalog. "
        "Während der Analyse wurden weder Quellcode noch Inventar an Online-Dienste Dritter übermittelt."),
    "none": "Keine Befunde.",
    "count_line": "{f} Befunde in {n} Komponenten",
    "target": "Ziel",
    "source": "Quelle",
    "time": "Zeit",
    "detections": "Erkennungen",
    "more": "… und {n} weitere Nachweise",
    "summary_text": (
        "Es wurden {n} Komponenten ermittelt, davon {a} mit bekannten Schwachstellen. Von insgesamt {f} Befunden "
        "sind {c} kritisch und {h} hoch."),
    "kev_text": ("{k} Befunde betreffen Schwachstellen, deren aktive Ausnutzung laut CISA bekannt ist; sie sollten "
                 "zuerst behoben werden."),
    "mal_text": ("{m} Komponenten sind als Schadpakete gekennzeichnet; entfernen Sie sie sofort und untersuchen Sie "
                 "die Systeme."),
    "top_actions": "Vorrangige Maßnahmen",
    "usage": {"imported": "im Code importiert", "not-imported": "kein direkter Import im Code gefunden"},
    "reach": {"called": "Betroffene Funktion wird aufgerufen", "not-called": "Kein Aufruf der betroffenen Funktion gefunden"},
    "usage_title": "Nutzungsanalyse",
    "usage_text": (
        "Der Quellcode (Whitebox) wurde daraufhin analysiert, ob Pakete importiert werden (JS/TS, Python, "
        "Java/Kotlin, C#, Go, Ruby). Bei Go-Komponenten wurde zusätzlich geprüft, ob die von einer Schwachstelle "
        "betroffenen Funktionen aufgerufen werden. Dies ist kein vollständiger Aufrufgraph: zur Laufzeit indirekt "
        "geladene Bibliotheken (z. B. Logging-Backends, Treiber, Plugins) können ohne Import verwendet werden. Ein "
        "Ergebnis „kein Import gefunden“ bedeutet daher nicht, dass die Komponente ungenutzt ist; es ist ein "
        "unterstützendes Signal für die Priorisierung."),
    "usage_stats": "{i} direkte Abhängigkeiten werden im Code importiert; für {n} wurde kein direkter Import gefunden.",
    "reach_stats": "Go: Die betroffene Funktion wird in {c} Befunden aufgerufen; in {n} wurde kein Aufruf gefunden.",
    "nvd_note": (
        "Serversoftware und native Bibliotheken außerhalb der OSV-Abdeckung (nginx, Apache, PHP, OpenSSL, sqlite "
        "usw.) wurden anhand von NVD-CPE-Daten abgeglichen. Distributionspakete (Ubuntu, Debian, RHEL …) können "
        "zurückportierte Sicherheitskorrekturen ohne Versionsänderung erhalten; NVD-Befunde für solche Komponenten "
        "werden daher mit niedriger Konfidenz gemeldet und sollten anhand der Sicherheitshinweise der Distribution "
        "bestätigt werden."),
    "lic_title": "Lizenzkonformität",
    "lic_text": (
        "Die Lizenzen der Anwendungsabhängigkeiten wurden auf SPDX-Kennungen normalisiert und gemäß {pol} bewertet. "
        "Betriebssystempakete und aus Binärdateien erkannte Komponenten sind ausgenommen. Dieser Abschnitt stellt "
        "keine Rechtsberatung dar; Ergebnisse „Prüfung erforderlich“ und „unzulässig“ sollten von Ihrer "
        "Rechtsabteilung bewertet werden."),
    "pol_custom": "der Lizenzrichtlinie Ihrer Organisation",
    "pol_default": ("der Standardrichtlinie (permissiv: zulässig; LGPL/MPL/EPL/GPL: Prüfung; AGPL/SSPL und kommerziell "
                    "eingeschränkte Lizenzen: unzulässig)"),
    "decision": {"allowed": "Zulässig", "review": "Prüfung erforderlich", "denied": "Unzulässig / riskant",
                 "unknown": "Lizenz unbestimmt"},
    "lic_cat": {"permissive": "Permissiv", "weak-copyleft": "Schwaches Copyleft", "strong-copyleft": "Starkes Copyleft",
                "network-copyleft": "Netzwerk-Copyleft", "restrictive": "Restriktiv", "unknown": "Unbekannt"},
    "decision_col": "Entscheidung",
    "category_col": "Kategorie",
    "sc_title": "Lieferkette",
    "sc_none": "Es wurden keine Lieferkettenrisiken festgestellt.",
    "online_method": ("Für Lizenz-, Wartungs- und Paketnamenprüfungen wurden nur Paketnamen und -versionen an {svc} "
                      "übermittelt; es wurden weder Quellcode noch Dateien übermittelt."),
    "sup_title": "Akzeptierte Risiken und Falsch-Positive",
    "sup_text": "Die folgenden Befunde wurden mit Begründung aus der Hauptliste herausgenommen.",
    "sup_kind": {"accepted-risk": "Akzeptiertes Risiko", "false-positive": "Falsch-positiv",
                 "not-affected": "Nicht betroffen"},
    "reason": "Begründung",
    "location": "Fundort / Nachweis",
    "target_loc": "Ziel / Fundort",
    "appendix_c": "Anhang C — Fundorte",
    "appendix_c_text": "Alle Fundorte (URL, Dateipfad) und Nachweise, an denen jede verwundbare Komponente erkannt wurde.",
    "method_col": "Methode",
    "method": {"lockfile": "Lock-Datei", "manifest": "Manifest", "command-output": "Befehlsausgabe",
               "pkgdb": "Paketdatenbank", "jar-meta": "JAR-Metadaten", "installed-package": "Installiertes Paket",
               "signature": "JS- / CSS-Signatur", "sourcemap": "Source Map", "cdn-url": "CDN-URL",
               "exposed-file": "Offengelegte Datei", "header": "HTTP-Header", "meta-generator": "Meta-Generator",
               "query-version": "Versionsparameter in der URL", "license-manifest": "Lizenzmanifest",
               "dex-strings": "DEX-String", "binary-strings": "Binär-String", "properties": "Versionsdatei",
               "pe-version": "PE-Versionsinformationen", "image-config": "Image-Konfiguration",
               "body-banner": "Seiteninhalt", "error-page": "Fehlerseite", "cms-version": "CMS-Versionsendpunkt",
               "platform": "Plattformmerkmal", "sbom": "SBOM"},
    "upgrade_line": "{c} → {v} ({n} Schwachstellen)",
    "confidential": "VERTRAULICH",
    "page": "Seite",
    "prepared": "Erstellt am",
    "toc": "Inhalt",
    "details_main": "Befunddetails (kritisch, hoch und aktiv ausgenutzt)",
    "appendix_a": "Anhang A — Mittlere, niedrige und unbestimmte Befunde",
    "appendix_b": "Anhang B — Komponenteninventar",
    "sev_dist": "Verteilung nach Schweregrad",
    "scope_table": "Analysierte Quellen",
    "source_col": "Quelle",
    "status": "Status",
    "inv_note": "Das vollständige maschinenlesbare Inventar wird separat als CycloneDX-SBOM-Datei geliefert.",
    "detail_col": "Detail",
}

MORE = {"fr": FR, "de": DE}


def lookup(key: str, lang: str, sub=None):
    d = MORE.get(lang)
    if not d:
        return None
    v = d.get(key)
    if sub is not None:
        v = v.get(sub) if isinstance(v, dict) else None
    return v if isinstance(v, str) else None
