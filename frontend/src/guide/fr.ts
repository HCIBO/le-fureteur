import { GuideContent } from "./types";

const c: GuideContent = {
  intro:
    "Le Fureteur est une plateforme d'analyse de la composition logicielle (SCA). Elle identifie les composants tiers présents dans les logiciels (bibliothèques open source, frameworks, paquets du système d'exploitation), les rapproche des vulnérabilités connues et établit un plan de remédiation. Elle s'installe sur le serveur de l'organisation ; le code source, les fichiers et les constats ne quittent jamais l'organisation.",
  sections: [
    {
      id: "what",
      title: "À quoi sert Le Fureteur ?",
      blocks: [
        { p: "L'essentiel du code d'une application moderne n'est pas écrit par l'organisation elle-même mais provient de composants externes. Lorsqu'un de ces composants présente une vulnérabilité (par ex. Log4Shell), l'application est également touchée. Le Fureteur répond aux questions suivantes :" },
        { ul: [
          "Quels composants, dans quelles versions, l'application contient-elle ? (inventaire / SBOM)",
          "Lesquels présentent des vulnérabilités connues, et quelle est leur gravité ?",
          "Lesquels sont actuellement exploités activement par des attaquants (CISA KEV) ?",
          "Quelle version corrige le problème, et que faut-il corriger en premier ?",
          "Les licences respectent-elles la politique de l'organisation ? Existe-t-il des risques liés à la chaîne d'approvisionnement (confusion de dépendances, paquets non maintenus) ?",
        ] },
        { p: "Livrables : liste de constats priorisée, rapport avec synthèse (HTML / PDF / Word), fichiers CSV et SBOM standard (CycloneDX, SPDX)." },
      ],
    },
    {
      id: "how",
      title: "Fonctionnement",
      blocks: [
        { ol: [
          "Collecte : les composants sont identifiés selon le type de cible — fichiers de verrouillage, bases de paquets, métadonnées d'artefacts compilés, réponses web, contenu des applications mobiles.",
          "Inventaire : les détections d'un même composant à différents endroits sont fusionnées ; pour chaque composant sont conservés l'écosystème, la version, le niveau de confiance, la relation directe / transitive et la preuve (chemin de fichier / URL).",
          "Rapprochement : l'inventaire est comparé à la base de vulnérabilités hors ligne du serveur (OSV ; NVD pour les logiciels serveur hors du périmètre OSV) avec une comparaison de versions propre à chaque écosystème.",
          "Enrichissement : chaque constat reçoit une sévérité CVSS, une probabilité d'exploitation EPSS et le statut CISA KEV ; la version corrigée est calculée.",
          "Priorisation : paquet malveillant → exploitation active (KEV) → sévérité → EPSS.",
          "Rapports et suivi : les constats sont enregistrés ; les nouvelles analyses suivent les constats nouveaux / corrigés / rouverts.",
        ] },
        { note: "L'analyse s'exécute entièrement sur le serveur et hors ligne. Aucun code source ni inventaire n'est transmis à des services tiers. Internet n'est utilisé (de façon facultative) que pour mettre à jour la base de vulnérabilités." },
      ],
    },
    {
      id: "types",
      title: "Types d'analyse et entrées prises en charge",
      blocks: [
        { table: { head: ["Type", "Entrée", "Ce qui est détecté"], rows: [
          ["Boîte blanche — source", "Archive du code source (zip / tar) ou fichiers de dépendances", "npm / yarn / pnpm, PyPI (requirements, Poetry, Pipfile), Maven / Gradle, Go, Composer, NuGet, Cargo, RubyGems, Pub, CocoaPods, SwiftPM ; analyse d'utilisation (imports)"],
          ["Boîte blanche — compilé", "JAR / WAR / EAR", "JAR imbriqués et métadonnées Maven"],
          ["Boîte blanche — conteneur", "Image exportée avec docker save (.tar)", "Paquets du système (famille Debian / Ubuntu / Alpine / RHEL) et dépendances applicatives de l'image"],
          ["Boîte blanche — liste de paquets", "Sortie dpkg / rpm / apk", "Paquets du système (la distribution et la version doivent être indiquées, par ex. Debian:12)"],
          ["Boîte noire — web", "Adresse web", "Bibliothèques JavaScript / CSS servies au navigateur, URL de CDN, source maps, manifestes de licences, en-têtes et pages d'erreur divulguant des versions, versions de CMS"],
          ["Boîte noire — mobile", "APK / IPA", "Bibliothèques embarquées dans l'application (les IPA chiffrées par FairPlay ne peuvent pas être analysées)"],
          ["Boîte noire — bureau", "Installeur (.exe / .msi), application Electron", "DLL embarquées, assemblies .NET, paquets Electron / Node"],
        ] } },
        { p: "Le niveau de confiance d'un constat (élevé / moyen / faible) indique la précision de la détermination de la version. L'analyse en boîte noire ne voit que les composants visibles de l'extérieur ; les bibliothèques côté serveur nécessitent une analyse en boîte blanche." },
      ],
    },
    {
      id: "webaccess",
      title: "Blocages lors de l'analyse web et solutions",
      blocks: [
        {"p": "Les cibles web sont analysées de l'extérieur ; certains sites bloquent les requêtes automatisées. Le Fureteur détecte le type de blocage et affiche la cause et des solutions en un clic sur la page d'analyse. La plupart des cas se résolvent d'eux-mêmes."},
        {"table": {"head": ["Situation", "Que se passe-t-il ?"], "rows": [["WAF / protection anti-bot (empreinte TLS)", "Avec le client HTTP sur « Automatique », l'analyse passe au TLS compatible navigateur (curl_cffi) dès le blocage et continue."], ["Vérification JavaScript / CAPTCHA", "Non franchie automatiquement. L'assistant navigateur ouvre un navigateur visible sur votre ordinateur ; vous passez la vérification, le parcours et l'envoi sont automatiques. Ou importez un enregistrement HAR / Burp."], ["Blocage géographique, IP, délai dépassé", "Les points de sortie (proxys HTTP / SOCKS5) définis par l'administrateur sont essayés tour à tour en mode Automatique ; l'un peut être fixé par cible."], ["Redirection vers connexion / SSO", "Configurez l'authentification (formulaire, cookie, Bearer, Basic) sur la page de la cible ou connectez-vous vous-même dans l'assistant navigateur."], ["Limite de débit (429 / 503)", "Attend le délai annoncé, ralentit et réessaie une fois."], ["Erreur de certificat TLS", "En environnement interne de confiance, désactivez la vérification TLS et relancez en un clic."], ["DNS, connexion refusée, mTLS, maintenance", "La cause et la marche à suivre sont expliquées sur la page d'analyse."]]}},
        {"ul": ["Les fichiers JS / CSS chargés depuis d'autres domaines (CDN) sont aussi analysés ; les scripts de suivi sont ignorés et ces serveurs ne sont pas parcourus.", "En cas de redirection comme linkedin.com → www.linkedin.com, l'analyse continue sur la nouvelle adresse.", "Pour les cibles fichier sans composant, la cause (pas de fichier de verrouillage, IPA chiffrée, APK protégé, image distroless, archive non prise en charge) et les commandes de correction sont affichées."]},
        {"note": "La protection du réseau interne s'applique toujours : même via un proxy ou le client compatible navigateur, l'analyse ne se connecte jamais à des adresses internes (sauf autorisation explicite d'un administrateur)."},
      ],
    },
    {
      id: "glossary",
      title: "Glossaire",
      blocks: [
        { table: { head: ["Terme", "Signification"], rows: [
          ["SCA", "Software Composition Analysis — analyse des composants tiers d'un logiciel et de leurs risques."],
          ["SBOM", "Software Bill of Materials — nomenclature des composants d'un logiciel. Standards : CycloneDX et SPDX."],
          ["CVE", "Identifiant universel d'une vulnérabilité (par ex. CVE-2021-44228)."],
          ["GHSA / OSV", "Identifiant d'avis de sécurité GitHub / base ouverte de vulnérabilités de Google, avec les plages de versions concernées par écosystème."],
          ["NVD / CPE", "Base nationale de vulnérabilités américaine / format d'identification de produits ; utilisé pour les logiciels serveur hors OSV."],
          ["CVSS", "Score de gravité technique d'une vulnérabilité (0–10)."],
          ["EPSS", "Probabilité d'exploitation d'une vulnérabilité dans les 30 prochains jours (FIRST)."],
          ["KEV", "Liste de la CISA des vulnérabilités dont l'exploitation active est avérée — priorité maximale."],
          ["PURL", "Package URL — identifiant d'un composant indépendant de l'écosystème (par ex. pkg:npm/lodash@4.17.20)."],
          ["Dépendance directe / transitive", "Paquet ajouté par l'application elle-même / paquet apporté par un autre paquet."],
          ["Confusion de dépendances", "Nom de paquet interne existant aussi dans un registre public ; un attaquant peut y publier un faux paquet."],
          ["Copyleft", "Licences imposant la diffusion des logiciels dérivés sous la même licence (GPL, AGPL…)."],
        ] } },
      ],
    },
    {
      id: "roles",
      title: "Rôles et droits",
      blocks: [
        { table: { head: ["Rôle", "Droits"], rows: [
          ["Administrateur", "Tout : utilisateurs, organisations, paramètres (clé NVD, SMTP, Jira), base de vulnérabilités, canaux de notification, état du système, journal d'audit."],
          ["Analyste", "Projets, cibles, analyses et constats de toutes les organisations ; consultation de l'état du système. Ne peut pas modifier les paramètres."],
          ["Client", "Uniquement sa propre organisation : ajoute projets et cibles, téléverse des fichiers, lance des analyses, gère le statut des constats, envoie vers Jira, télécharge les rapports. Ne peut ajouter comme cibles web que les domaines autorisés pour l'organisation."],
        ] } },
      ],
    },
    {
      id: "start",
      title: "Pas à pas",
      blocks: [
        { ol: [
          "Administrateur : Paramètres → Mettre à jour la base (obligatoire à la première installation), puis consulter les recommandations de la page État du système.",
          "Organisations → ajouter l'organisation cliente ; pour les analyses web, saisir les domaines autorisés (exemple.fr ou *.exemple.fr).",
          "Utilisateurs → créer les comptes analystes et clients.",
          "Projets → nouveau projet ; la langue du rapport, la politique de licences et la clé de projet Jira se règlent dans les paramètres du projet.",
          "Ajouter une cible → adresse web (boîte noire) ou téléversement (code source, APK, IPA, image, installeur).",
          "Lancer l'analyse → la progression et le journal s'affichent sur la page de l'analyse.",
          "Constats → filtrer, consulter le détail, attribuer un statut, commenter, envoyer vers Jira.",
          "Analyse → onglet Rapports : télécharger le rapport et les fichiers SBOM.",
          "Ajouter une analyse planifiée depuis la page de la cible pour des analyses régulières.",
        ] },
        { note: "N'analysez que des systèmes pour lesquels vous disposez d'une autorisation écrite. Les adresses du réseau interne sont bloquées par défaut ; un administrateur peut les autoriser dans les paramètres." },
      ],
    },
    {
      id: "findings",
      title: "Constats et cycle de vie",
      blocks: [
        { p: "Un constat = un composant + une vulnérabilité sur une cible. Un même constat est unique d'une analyse à l'autre ; les dates de première et dernière détection sont conservées." },
        { table: { head: ["Statut", "Signification"], rows: [
          ["Ouvert", "Nouvellement détecté, en attente de traitement."],
          ["En cours", "La remédiation a commencé."],
          ["Risque accepté", "Accepté délibérément (justification obligatoire). Présenté dans une section distincte du rapport."],
          ["Faux positif", "Le constat est erroné (justification obligatoire)."],
          ["Non concerné", "Le composant est présent mais la vulnérabilité ne peut pas être déclenchée dans cet usage (justification obligatoire)."],
          ["Corrigé", "Automatique : le composant / la version n'est plus détecté lors d'une nouvelle analyse. S'il réapparaît, le constat est rouvert."],
        ] } },
        { p: "L'onglet Modifications d'une analyse présente les constats nouveaux, corrigés et rouverts par rapport à l'analyse précédente. Après un changement de statut, le rapport peut être régénéré." },
        {"p": "La recherche de la page Vulnérabilités porte sur domaine, cible, projet, client, composant, version, CVE / GHSA et description ; plusieurs mots renvoient les vulnérabilités les contenant tous. Filtres écosystème, correctif disponible ou non, première détection et type de cible ; la liste filtrée peut être téléchargée en CSV. Si la cible recherchée n'a pas de vulnérabilité, les cibles correspondantes sont affichées avec des liens."},
      ],
    },
    {
      id: "collaboration",
      title: "Travail d'équipe : assignation, approbation, discussion, messages",
      blocks: [
        { p: "Le Fureteur comprend des outils collaboratifs pour décider qui corrige quel constat, avant quand et avec quelle décision." },
        { ul: [
          "Équipes : chaque équipe a un responsable, des référents et des membres rattachés. La page d'équipe montre l'organigramme, la charge par personne, la file de travail et ce qui a été livré ces 30 derniers jours.",
          "Assignation : un constat est assigné à une personne avec une échéance ; elle est notifiée. L'assignation groupée se fait depuis l'écran Constats.",
          "Approbation : les décisions « risque accepté », « faux positif » et « non concerné » partent en approbation chez le référent / responsable d'équipe. Les demandes traitées restent dans Approbations → Mes décisions.",
          "Salle de discussion : en cas de désaccord sur un constat, ouvrez une discussion et ajoutez les personnes concernées. Sans accord, elle remonte au responsable, qui tranche ou délègue. La décision est inscrite dans l'historique du constat.",
          "Messages : écrivez à des personnes ou à toute une équipe. Une coche = envoyé, deux coches grises = distribué, deux coches bleues = lu. Les non-lecteurs peuvent être relancés une fois par heure.",
          "Rappels : laissez-vous des notes programmées, aussi depuis un constat ou un message. À l'échéance, elles arrivent dans vos notifications.",
        ] },
        { note: "Les utilisateurs clients ne voient que les personnes de leur organisation et l'équipe de conseil ; les constats, discussions ou messages d'une autre organisation ne sont jamais visibles." },
      ],
    },
    {
      id: "reports",
      title: "Rapports et livrables",
      blocks: [
        { table: { head: ["Fichier", "Contenu"], rows: [
          ["rapport.html / .pdf / .docx", "Synthèse, plan de remédiation, détail des constats, analyse d'utilisation, conformité des licences, chaîne d'approvisionnement, limites du périmètre, annexes (inventaire, emplacements de détection)."],
          ["constats.csv", "Liste des constats pour tableurs et autres outils."],
          ["sbom.cdx.json", "SBOM CycloneDX 1.5."],
          ["sbom.spdx.json", "SBOM SPDX 2.3."],
        ] } },
        { p: "La langue du rapport se choisit dans les paramètres du projet : turc, anglais, français, allemand." },
      ],
    },
    {
      id: "automation",
      title: "Planification, notifications et Jira",
      blocks: [
        { ul: [
          "Analyse continue / planifiée : depuis la page de la cible ou pour toutes les cibles dans projet → Tendance et analyse continue ; avec l'assistant (jours, plage horaire, fréquence) ou une expression cron. Au plus une fois par heure. Les analyses démarrant ensemble suivent la règle de file du projet.",
          "Mise à jour planifiée de la base : depuis la page Paramètres (administrateur) ; une fois par jour recommandé.",
          "Notifications (administrateur) : Slack, Microsoft Teams, e-mail ou webhook générique. Événements : analyse terminée / échouée, nouveaux constats au-dessus du seuil, nouveau constat KEV, échec de mise à jour de la base. Un canal peut être limité à une organisation. Le corps des webhooks peut être signé en HMAC-SHA256 (X-Scakit-Signature).",
          "Jira (Cloud et Server / Data Center) : plusieurs connexions Jira peuvent être ajoutées ; l'administrateur décide qui (rôles, utilisateurs) et pour quels clients chacune peut être utilisée. Avec « Ajouter à Jira », si plusieurs connexions sont autorisées, l'utilisateur choisit ; pas si le projet a un Jira par défaut. Jamais de second ticket pour la même vulnérabilité ; tickets automatiques et commentaires optionnels.",
        ] },
      ],
    },
    {
      id: "queue",
      title: "File d'analyses, analyse continue et tendance",
      blocks: [
        {"ul": ["Panneau de file (page Analyses) : analyses en cours et en attente ; administrateurs et analystes peuvent réordonner (en tête, monter / descendre, en fin).", "Règle de file du projet : les analyses d'un projet (manuelles, groupées, planifiées) s'exécutent une par une, au plus N à la fois ou librement entre elles, avec une attente optionnelle. Les autres projets ne sont pas affectés.", "Lors de l'ajout de cibles, la carte « File (pour ces analyses) » définit une règle propre à ces analyses ou la rend par défaut pour le projet. Menu de démarrage de la cible : en tête / normale / en fin.", "Règles globales (administrateur, Paramètres → File d'analyses) : analyses par worker et attente entre analyses — limite supérieure des règles de projet.", "Analyse continue : dans projet → Tendance et analyse continue, choisissez jours, plage horaire et fréquence et appliquez-les à toutes les cibles (ex. toutes les 3 h de 09 à 18 h en semaine, deux fois par semaine).", "Tendance : sur le tableau de bord, le projet et la cible — vulnérabilités ouvertes, nouvelles et corrigées par heure / jour / semaine et écart avec la période précédente ; tailles Petit / Moyen / Grand et vue tableau."]},
      ],
    },
    {
      id: "vulndb",
      title: "Base de vulnérabilités",
      blocks: [
        { p: "Le rapprochement utilise une base locale sur le serveur. Sources : OSV (écosystèmes de paquets et distributions Linux), EPSS, CISA KEV et, en option, NVD (clé d'API recommandée)." },
        { ul: [
          "Mise à jour : Paramètres → Mettre à jour la base, ou mise à jour planifiée.",
          "Installation sans Internet : télécharger avec `scakit db download dossier` sur une autre machine, copier le dossier sur le serveur et saisir son chemin dans les Paramètres.",
          "Fraîcheur : la page État du système affiche l'âge de chaque source ; des données anciennes déclenchent un avertissement.",
          "Les analyses continuent pendant la mise à jour de la base (avec les dernières données validées). Une archive téléchargée corrompue est ignorée et retéléchargée à la mise à jour suivante.",
          "Procédure pas à pas pour réseau isolé et téléchargement : page Ligne de commande (scakit).",
        ] },
      ],
    },
    {
      id: "system",
      title: "État du système et auto-analyse",
      blocks: [
        { p: "La page État du système (administrateur / analyste) présente la santé de l'application elle-même : workers, file d'attente, disque, base de données, fraîcheur des données de vulnérabilités, outils externes et contrôles de configuration — chacun avec une action recommandée." },
        { ul: [
          "Auto-analyse : Le Fureteur analyse ses propres paquets Python, front-end et système avec sa propre base de vulnérabilités et recommande des mises à jour (hors ligne).",
          "Vérification des dernières versions (administrateur, facultative) : seuls les noms des dépendances open source de Le Fureteur sont interrogés sur PyPI et npm ; aucune donnée client n'est transmise.",
        ] },
      ],
    },
    {
      id: "security",
      title: "Sécurité et confidentialité",
      blocks: [
        { ul: [
          "Installation sur site : code, fichiers, constats et rapports restent sur le serveur de l'organisation.",
          "Mots de passe stockés avec Argon2 ; cookie de session httpOnly + SameSite=Strict ; protection CSRF sur toutes les requêtes de modification ; limitation des tentatives de connexion.",
          "Les paramètres secrets (clé NVD, mot de passe SMTP, jeton Jira, URL de webhooks) sont chiffrés en base et ne sont jamais renvoyés à l'interface.",
          "Protection des cibles : http / https uniquement ; les clients ne peuvent analyser que les domaines autorisés ; les adresses internes et de métadonnées cloud sont bloquées par défaut ; le contrôle est répété au lancement de l'analyse.",
          "Isolation des organisations : un utilisateur client ne voit aucune donnée d'une autre organisation.",
          "Journal d'audit : connexions, paramètres, cibles, analyses, changements de statut, Jira et téléchargements de rapports sont enregistrés.",
          "En production, exécuter derrière HTTPS (SCAKIT_COOKIE_SECURE=1).",
        ] },
      ],
    },
    {
      id: "toolset",
      title: "Boîte à outils",
      blocks: [
        { p: "De petits outils sûrs pour le quotidien : client HTTP, encodeur / décodeur (Base64, URL, HTML, Hex, Unicode, JWT, SHA), ping TCP et bloc-notes personnel." },
        { ul: [
          "Le client HTTP et le ping ne se connectent jamais aux adresses internes (127.0.0.1, 10.x, 169.254.169.254, etc.) ; les redirections sont aussi contrôlées.",
          "Votre cookie de session n'est jamais envoyé à la cible ; seuls vos en-têtes le sont. Chaque requête est journalisée et limitée par minute.",
          "L'encodeur fonctionne entièrement dans le navigateur. Le bloc-notes n'est visible que par vous.",
          "Les outils réseau sont désactivés par défaut pour les clients ; s'ils sont activés, seuls les domaines autorisés sont accessibles (Paramètres → Boîte à outils).",
        ] },
      ],
    },
    {
      id: "admin",
      title: "Administration : mode maintenance, sessions, audit",
      blocks: [
        { ul: [
          "Mode maintenance (État du système → Maintenance) : seuls les administrateurs peuvent se connecter ; les autres utilisateurs et les jetons API voient un écran de maintenance et les analyses planifiées ne démarrent pas.",
          "Limites de connexion et d'API (Paramètres → Sécurité et accès) : échecs de connexion, durée de blocage et requêtes API par utilisateur et par minute.",
          "Détail utilisateur : historique de connexion (succès / échec, IP, appareil), sessions actives et actions récentes. Toutes les sessions peuvent être terminées en un clic. Chacun voit ses sessions dans Mon compte.",
          "Journal d'audit : filtre par utilisateur, action, type d'objet, IP et période ; export CSV.",
          "Sauvegarde : `scakit server backup fichier --encrypt` crée une sauvegarde chiffrée ; la restauration se fait uniquement sur une installation vide.",
        ] },
      ],
    },
    {
      id: "cli",
      title: "Ligne de commande (CLI)",
      blocks: [
        { p: "Le même moteur d'analyse est aussi utilisable en ligne de commande pour les missions de conseil :" },
        { code: "scakit init ~/missions/client --name \"Portail 2026\" --client \"Client\" --lang fr\nscakit add ~/missions/client ./source.zip app.apk https://exemple.fr\nscakit db update\nscakit match ~/missions/client\nscakit report ~/missions/client --formats html,pdf,docx,cdx,spdx\n\n# serveur web\nscakit server init --email admin@entreprise.fr\nscakit server run --port 8800\nscakit server worker" },
        {"note": "Pour savoir ce qu'est scakit, l'installer, voir toutes les commandes et préparer la base en réseau isolé, consultez la page Ligne de commande (scakit) du menu ; administrateurs et analystes peuvent y télécharger le paquet."},
      ],
    },
    {
      id: "faq",
      title: "Questions fréquentes",
      blocks: [
        { table: { head: ["Question", "Réponse"], rows: [
          ["Aucun constat — l'application est-elle sûre ?", "Non, cela signifie seulement qu'aucun composant présentant une vulnérabilité connue n'a été trouvé. L'analyse en boîte noire ne voit pas les composants côté serveur ; les limites du périmètre sont indiquées dans le rapport."],
          ["Pourquoi la confiance d'un constat est-elle faible ?", "La version a été estimée, ou des correctifs ont pu être rétroportés dans des paquets de distribution sans changement de version. Consultez la section preuve."],
          ["Pourquoi la recommandation saute-t-elle une version majeure ?", "Certaines vulnérabilités ne sont corrigées que dans une nouvelle version majeure ; la recommandation est la version minimale corrigeant toutes les vulnérabilités connues."],
          ["Une analyse a échoué.", "Consultez l'onglet Journal de la page de l'analyse, ainsi que l'état des workers et de la base sur la page État du système."],
        ] } },
      ],
    },
  ],
  api: {
    title: "API",
    groupsHead: ["Chemin", "Rôle", "Description"],
    groups: [
      ["/api/auth/*", "tous", "Connexion, déconnexion, utilisateur courant, langue, changement de mot de passe"],
      ["/api/orgs", "administrateur (écriture)", "Organisations et domaines autorisés"],
      ["/api/users", "administrateur", "Gestion des utilisateurs"],
      ["/api/projects", "tous (périmètre)", "Projets, langue du rapport, politique de licences, clé Jira"],
      ["/api/projects/{id}/targets, /api/targets/*", "tous (périmètre)", "Cibles, téléversement / suppression de fichiers, lancement d'analyse"],
      ["/api/scans/*", "tous (périmètre)", "Analyses, journal, annulation, composants, modifications, rapports"],
      ["/api/findings/*", "tous (périmètre)", "Liste / détail des constats, statut, commentaires, ticket Jira"],
      ["/api/schedules/*", "tous (base : administrateur)", "Planifications et aperçu cron"],
      ["/api/notifications/*", "administrateur", "Canaux de notification et messages de test"],
      ["/api/settings, /api/vulndb/*", "administrateur", "Paramètres, état et mise à jour de la base de vulnérabilités"],
      ["/api/system/*", "administrateur / analyste", "État du système, auto-analyse, vérification des versions"],
      ["/api/jira/*", "administrateur / tous", "Test de connexion et état Jira"],
      ["/api/dashboard, /api/audit", "tous / administrateur", "Tableau de bord, journal d'audit"],
    ],
    fullListTitle: "Tous les points de terminaison (schéma en direct)",
    fullListNote: "L'API utilise le cookie de session : connectez-vous d'abord via /api/auth/login ; pour les requêtes POST / PUT / PATCH / DELETE, envoyez la valeur du cookie scakit_csrf dans l'en-tête X-CSRF-Token. Les jetons d'API pour l'usage machine à machine (CI/CD) sont prévus dans la feuille de route.",
  },
};
export default c;
