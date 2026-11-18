from content import L

TITLE = L("Yazılım Bileşen Analizi (SCA) Hizmeti", "Software Composition Analysis (SCA) Service")

LEGEND = [
    ("S1", L("Yalnızca hedef / uygulama dosyası. Kaynak kod veya geliştirme dosyası gerekmez.",
             "Only the target / application file. No source code or development files needed.")),
    ("S2", L("Minimum'a ek olarak bağımlılık dosyaları. Kaynak kod gerekmez.",
             "Minimum plus dependency files. No source code needed.")),
    ("S3", L("Önerilen'e ek olarak kaynak kod ve dağıtım dosyaları.",
             "Recommended plus source code and deployment files.")),
    ("O", L("Her seviyede sonuçların kapsamını artırır.",
            "Increases coverage at any level.")),
]

TIER_HEADER = [L("Seviye", "Level"), L("Sizden istenen", "What we need"),
               L("Elde edilen sonuç", "What you get"), L("Kapsam dışı kalan", "Not covered")]
TIER_WIDTHS = [27, 49, 54, 50]


def tier_select(card_id):
    return {"id": f"{card_id}-00", "level": "S1", "text": L("Seçilen analiz seviyesi", "Selected analysis level"),
            "hint": L("Seçtiğiniz seviyedeki ve altındaki seviyelerdeki maddeleri sağlayınız.",
                      "Provide the items of the selected level and of all levels below it."),
            "opts": [L("Minimum", "Minimum"), L("Önerilen", "Recommended"), L("Tam", "Full")]}


def intro(what_tr, what_en, other_tr, other_en):
    return {"type": "para", "text": L(
        f"Bu kart, yalnızca {what_tr} için SCA (yazılım bileşen analizi) talep edildiğinde kullanılır ve tek "
        f"başına doldurulabilir. {other_tr} Birden fazla uygulama veya firma geneli analiz için \"Ön "
        f"Gereksinimler ve Bilgi Toplama Formu\"nu kullanınız. Maddelerin nasıl hazırlanacağı, parantez içinde "
        f"verilen kodlarla \"Veri Hazırlama ve Teslim Kılavuzu\"nda adım adım anlatılmıştır.",
        f"This card is used when SCA (software composition analysis) is requested for {what_en} only, and can be "
        f"completed on its own. {other_en} For multiple applications or an organization-wide analysis, use the "
        f"\"Prerequisites and Information Request Form\". How to prepare each item is explained step by step in "
        f"the \"Data Preparation and Delivery Guide\", under the codes given in parentheses.")}


def common_tail(card_id, n):
    return [
        {"title": L(f"{n}. Teslim ve Gizlilik", f"{n}. Delivery and Confidentiality"), "blocks": [
            {"type": "items", "rows": [
                {"id": f"{card_id}-90", "level": "S2",
                 "text": L("Dosya teslim yöntemi (Kılavuz: Bölüm 2)", "File delivery method (Guide: Section 2)"),
                 "hint": L("Şifreli arşivin parolası farklı bir kanaldan (SMS/telefon) iletilir.",
                           "The encrypted archive's password is sent over a separate channel (SMS/phone)."),
                 "opts": [L("Şifreli arşiv", "Encrypted archive"), L("Salt-okunur erişim", "Read-only access"),
                          L("Yerinde / VDI", "On-site / VDI")]},
                {"id": f"{card_id}-91", "level": "S1",
                 "text": L("Gizlilik sözleşmesi (NDA) imzalandı", "Non-disclosure agreement (NDA) signed")},
                {"id": f"{card_id}-92", "level": "S1",
                 "text": L("Rapor dili", "Report language"),
                 "opts": [L("Türkçe", "Turkish"), L("İngilizce", "English"), L("İkisi", "Both")]},
            ]},
        ]},
        {"title": L(f"{n + 1}. İletişim ve Onay", f"{n + 1}. Contact and Approval"), "blocks": [
            {"type": "fields", "rows": [
                L("Firma adı", "Company name"),
                L("İrtibat kişisi (ad, unvan)", "Point of contact (name, title)"),
                L("E-posta / telefon", "E-mail / phone"),
                L("Teknik irtibat kişisi", "Technical contact"),
                L("Tarih", "Date"),
                {"label": L("İmza / kaşe", "Signature / stamp"), "tall": True},
            ]},
        ]},
    ]


MOBILE = {
    "file": ("SCA_Senaryo_Karti_Mobil_TR", "SCA_Scenario_Card_Mobile_EN"),
    "title": TITLE,
    "subtitle": L("Senaryo Kartı: Mobil Uygulama (Android / iOS)", "Scenario Card: Mobile Application (Android / iOS)"),
    "legend_at": 2, "breaks": (2,), "legend": LEGEND,
    "sections": [
        {"title": L("1. Sadece APK / IPA versek yeter mi?", "1. Is an APK / IPA alone enough?"), "blocks": [
            intro("bir mobil uygulama", "a mobile application",
                  "Mobil uygulama sızma testiyle birlikte yürütülebilir.",
                  "It can be carried out together with a mobile application penetration test."),
            {"type": "answer",
             "title": L("Kısa cevap: Analiz yapılabilir, ancak sonuç kısmi olur. Kaynak kod vermeden tam sonuç için "
                        "bir ek dosya yeterlidir.",
                        "Short answer: the analysis can be done, but the result will be partial. For a complete "
                        "result without sharing source code, one additional file is enough."),
             "text": L(
                 "Yalnızca APK (Android) veya IPA (iOS) ile, uygulamanın içine paketlenmiş kütüphaneler, SDK'lar "
                 "(ör. analitik, ödeme, bildirim) ve native bileşenler tespit edilir ve bilinen güvenlik açıkları "
                 "raporlanır. Ancak yayın (release) sürümlerinde uygulanan küçültme ve kod karartma (R8/ProGuard) "
                 "nedeniyle bazı bileşenlerin sürümü kesin olarak belirlenemez; bu bulgular \"tahmini sürüm\" olarak "
                 "raporlanır. Uygulamanın bağımlılık listesini veren bir komut çıktısı veya lock dosyası "
                 "(geliştirme ekibiniz için kısa bir iş) eklendiğinde tüm sürümler kesinleşir; kaynak kod paylaşmanız "
                 "gerekmez. Uygulamanın bağlandığı API / sunucu tarafı, APK veya IPA ile analiz edilemez; API de "
                 "kapsamdaysa \"Senaryo Kartı: API\"yi ayrıca doldurunuz. iOS için App Store'dan indirilen IPA "
                 "şifreli olduğundan analize uygun değildir; geliştirme ekibinizin ürettiği IPA dosyası gereklidir.",
                 "With an APK (Android) or IPA (iOS) alone, the libraries, SDKs (e.g. analytics, payments, "
                 "notifications) and native components packaged inside the application are identified and their "
                 "known vulnerabilities are reported. However, due to shrinking and obfuscation (R8/ProGuard) "
                 "applied to release builds, the version of some components cannot be determined with certainty; "
                 "these findings are reported as \"estimated version\". Adding one command output or lock file that "
                 "lists the application's dependencies (a short task for your development team) makes all versions "
                 "exact; you do not need to share source code. The API / server side the application connects to "
                 "cannot be analysed from the APK or IPA; if the API is also in scope, please also complete "
                 "\"Scenario Card: API\". For iOS, IPAs downloaded from the App Store are encrypted and not suitable "
                 "for analysis; an IPA file produced by your development team is required.")},
        ]},
        {"title": L("2. Analiz Seviyeleri", "2. Analysis Levels"), "blocks": [
            {"type": "table", "header": TIER_HEADER, "widths": TIER_WIDTHS, "rows": [
                [L("Minimum", "Minimum"),
                 L("APK / AAB ve/veya IPA dosyası, mağaza bağlantısı",
                   "APK / AAB and/or IPA file, store link"),
                 L("Uygulama içi kütüphane ve SDK envanteri, bilinen zafiyetler; sürümlerin bir kısmı tahmini",
                   "Inventory of in-app libraries and SDKs, known vulnerabilities; some versions estimated"),
                 L("Kesin sürümler (karartılmış bileşenler), lisans analizi (sınırlı), API / sunucu tarafı",
                   "Exact versions (obfuscated components), license analysis (limited), API / server side")],
                [L("Önerilen", "Recommended"),
                 L("Minimum + bağımlılık komut çıktısı / lock dosyaları (kaynak kod gerekmez)",
                   "Minimum + dependency command output / lock files (no source code needed)"),
                 L("Tüm doğrudan ve dolaylı bağımlılıklar kesin sürümleriyle, SBOM, lisans analizi",
                   "All direct and transitive dependencies with exact versions, SBOM, license analysis"),
                 L("API / sunucu tarafı", "API / server side")],
                [L("Tam", "Full"),
                 L("Önerilen + mobil uygulama kaynak kodu; API kapsamdaysa API kartı",
                   "Recommended + mobile application source code; API card if the API is in scope"),
                 L("Koda gömülü kütüphaneler dahil tam envanter; API kartıyla birlikte uygulama ve sunucu tek raporda",
                   "Complete inventory including vendored libraries; with the API card, app and server in one report"),
                 L("—", "—")],
            ]},
            {"type": "note", "text": L(
                "Önerimiz: Önerilen seviye. Minimum seviyeye göre ek efor çok düşüktür ve kaynak kod paylaşımı "
                "gerektirmeden kesin sonuç verir.",
                "Our recommendation: the Recommended level. The extra effort compared to Minimum is very low and it "
                "gives exact results without sharing source code.")},
        ]},
        {"title": L("3. Uygulama Bilgileri ve Talep Edilen Dosyalar",
                    "3. Application Information and Requested Files"), "blocks": [
            {"type": "para", "text": L(
                "Her madde için durumu işaretleyiniz. Seviye sütunu, maddenin hangi analiz seviyesinde gerektiğini "
                "gösterir:",
                "Mark the status of each item. The Level column shows at which analysis level the item is "
                "required:")},
            {"type": "items", "rows": [
                tier_select("MOB"),
                {"id": "MOB-01", "level": "S1",
                 "text": L("Platform", "Platform"),
                 "opts": [L("Android", "Android"), L("iOS", "iOS"), L("İkisi", "Both")]},
                {"id": "MOB-02", "level": "S1",
                 "text": L("Uygulamanın geliştirildiği teknoloji", "Technology the application is built with"),
                 "hint": L("Emin değilseniz geliştirme ekibinize sorunuz; talep edilecek dosyalar buna göre değişir.",
                           "If unsure, ask your development team; the requested files depend on it."),
                 "opts": [L("Native", "Native"), L("Flutter", "Flutter"), L("React Native", "React Native"),
                          L("Diğer", "Other")]},
                {"id": "MOB-03", "level": "S1",
                 "text": L("Mağaza bağlantısı veya paket adı / bundle ID ve analiz edilecek sürüm numarası (BB-03)",
                           "Store link or package name / bundle ID, and the version number to be analysed (BB-03)"),
                 "field": True, "lines": 2},
                {"id": "MOB-04", "level": "S1",
                 "text": L("Android: APK veya AAB dosyası — mağazadaki sürümle aynı (WB-12)",
                           "Android: APK or AAB file — same version as in the store (WB-12)")},
                {"id": "MOB-05", "level": "S1",
                 "text": L("iOS: geliştirme ekibinin ürettiği IPA veya .xcarchive — App Store'dan indirilen değil (WB-12)",
                           "iOS: IPA or .xcarchive produced by the development team — not downloaded from the "
                           "App Store (WB-12)")},
                {"id": "MOB-10", "level": "S2",
                 "text": L("Android bağımlılık listesi: release yapılandırmasının Gradle çıktısı + build.gradle "
                           "dosyaları (Bölüm 4)",
                           "Android dependency list: Gradle output of the release configuration + build.gradle "
                           "files (Section 4)")},
                {"id": "MOB-11", "level": "S2",
                 "text": L("iOS bağımlılık dosyaları: Podfile.lock / Package.resolved / Cartfile.resolved (Bölüm 4)",
                           "iOS dependency files: Podfile.lock / Package.resolved / Cartfile.resolved (Section 4)")},
                {"id": "MOB-12", "level": "S2",
                 "text": L("Flutter: pubspec.yaml + pubspec.lock; React Native: package.json + lock dosyası "
                           "(Bölüm 4)",
                           "Flutter: pubspec.yaml + pubspec.lock; React Native: package.json + lock file (Section 4)"),
                 "hint": L("Yalnızca MOB-02'de Flutter veya React Native seçildiyse. Android ve iOS tarafının "
                           "dosyaları (MOB-10, MOB-11) de ayrıca gereklidir.",
                           "Only if Flutter or React Native was selected in MOB-02. The Android and iOS side files "
                           "(MOB-10, MOB-11) are also required.")},
                {"id": "MOB-13", "level": "S2",
                 "text": L("Projeye elle eklenen kütüphaneler (.aar, .jar, .framework, .xcframework) ve sürümleri "
                           "(WB-32)",
                           "Libraries added manually to the project (.aar, .jar, .framework, .xcframework) and their "
                           "versions (WB-32)")},
                {"id": "MOB-20", "level": "S3",
                 "text": L("Mobil uygulamanın kaynak kodu ve mağazadaki sürümün commit / tag bilgisi (WB-01, WB-02)",
                           "Mobile application source code and the commit / tag of the store version (WB-01, WB-02)")},
                {"id": "MOB-21", "level": "O",
                 "text": L("Ticari / lisanslı SDK'lar ve sürümleri (WB-33)",
                           "Commercial / licensed SDKs and their versions (WB-33)")},
            ]},
        ]},
        {"title": L("4. Bağımlılık Dosyalarının Hazırlanması (Önerilen seviye)",
                    "4. Preparing the Dependency Files (Recommended level)"), "blocks": [
            {"type": "para", "text": L(
                "Komutları, mağazaya gönderilen sürümün kaynak kodunun bulunduğu proje dizininde çalıştırınız. "
                "Komutlar yalnızca listeleme yapar, projede değişiklik yapmaz.",
                "Run the commands in the project directory containing the source of the version submitted to the "
                "store. The commands only list information; they do not change the project.")},
            {"type": "code", "code":
                "# Android (Native)\n"
                "./gradlew :app:dependencies --configuration releaseRuntimeClasspath > android-deps.txt\n"
                "\n"
                "# Flutter\n"
                "flutter pub deps > flutter-deps.txt       # L:ayrıca pubspec.lock dosyasını ekleyiniz|also add the pubspec.lock file\n"
                "cd android && ./gradlew :app:dependencies --configuration releaseRuntimeClasspath > ../android-deps.txt\n"
                "\n"
                "# React Native\n"
                "cd android && ./gradlew :app:dependencies --configuration releaseRuntimeClasspath > ../android-deps.txt\n"
                "# L:ayrıca package.json ve package-lock.json / yarn.lock dosyalarını ekleyiniz|also add package.json and package-lock.json / yarn.lock\n"
                "\n"
                "# iOS (Native / Flutter / React Native)\n"
                "# L:ios/Podfile.lock dosyasını ve SPM kullanılıyorsa Package.resolved dosyasını ekleyiniz|add ios/Podfile.lock and, if SPM is used, the Package.resolved file\n"
                "\n"
                "# L:Elle eklenen kütüphaneleri listeleme|Listing manually added libraries\n"
                "find . -path ./node_modules -prune -o \\( -name '*.aar' -o -name '*.jar' \\\n"
                "  -o -name '*.xcframework' -o -name '*.framework' \\) -print > manual-libs.txt"},
            {"type": "para", "text": L(
                "Uygulama modülünün adı \"app\" değilse komuttaki \":app\" kısmını kendi modül adınızla değiştiriniz. "
                "Uygulamada farklı ürün türleri (flavor) varsa yapılandırma adı \"[flavor]ReleaseRuntimeClasspath\" "
                "biçimindedir (ör. prodReleaseRuntimeClasspath). Windows'ta \"./gradlew\" yerine \"gradlew.bat\" "
                "kullanınız.",
                "If the application module is not named \"app\", replace \":app\" in the command with your module "
                "name. If the app has product flavors, the configuration name is \"[flavor]ReleaseRuntimeClasspath\" "
                "(e.g. prodReleaseRuntimeClasspath). On Windows use \"gradlew.bat\" instead of \"./gradlew\".")},
        ]},
    ] + common_tail("MOB", 5),
}

WEB = {
    "file": ("SCA_Senaryo_Karti_Web_TR", "SCA_Scenario_Card_Web_EN"),
    "title": TITLE,
    "subtitle": L("Senaryo Kartı: Web Uygulaması", "Scenario Card: Web Application"),
    "legend_at": 2, "breaks": (2,), "legend": LEGEND,
    "sections": [
        {"title": L("1. Sadece web adresini versek yeter mi?", "1. Is the web address alone enough?"), "blocks": [
            intro("bir web uygulaması", "a web application",
                  "Web uygulaması sızma testiyle birlikte yürütülebilir.",
                  "It can be carried out together with a web application penetration test."),
            {"type": "answer",
             "title": L("Kısa cevap: Analiz yapılabilir, ancak yalnızca dışarıdan görünen kısım analiz edilir. "
                        "Güvenilir sonuç için sunucu tarafının bağımlılık dosyaları gerekir.",
                        "Short answer: the analysis can be done, but only the externally visible part is analysed. "
                        "A reliable result requires the server side's dependency files."),
             "text": L(
                 "Yalnızca web adresi ile tarayıcıya gönderilen bileşenler (JavaScript kütüphaneleri, ön yüz "
                 "framework'leri) ve sunucunun dışarıya verdiği sürüm bilgileri analiz edilir. Ancak web "
                 "uygulamalarında kritik zafiyetlerin önemli bir kısmı sunucu tarafında çalışan kütüphanelerde "
                 "(Java, .NET, PHP, Node.js, Python bağımlılıkları) bulunur ve bunlar dışarıdan görünmez. Bu nedenle "
                 "yalnızca web adresi ile yapılan analizde bulgu çıkmaması, uygulamanın bu açıdan güvenli olduğu "
                 "anlamına gelmez. Kaynak kod paylaşmadan güvenilir sonuç için ön yüz ve sunucu tarafının "
                 "bağımlılık (lock) dosyaları veya bağımlılık komut çıktıları ile sunucu yazılımı bilgisi yeterlidir.",
                 "With the web address alone, components sent to the browser (JavaScript libraries, front-end "
                 "frameworks) and version information exposed by the server are analysed. However, a significant "
                 "share of critical vulnerabilities in web applications lies in libraries running on the server side "
                 "(Java, .NET, PHP, Node.js, Python dependencies), which are not visible from outside. Therefore, the "
                 "absence of findings in an analysis based on the web address alone does not mean the application is "
                 "secure in this respect. For a reliable result without sharing source code, the dependency (lock) "
                 "files or dependency command outputs of the front end and the server side, plus server software "
                 "information, are sufficient.")},
        ]},
        {"title": L("2. Analiz Seviyeleri", "2. Analysis Levels"), "blocks": [
            {"type": "table", "header": TIER_HEADER, "widths": TIER_WIDTHS, "rows": [
                [L("Minimum", "Minimum"),
                 L("Web adresleri ve yazılı test izni", "Web addresses and written test authorization"),
                 L("Ön yüz JavaScript kütüphaneleri, sunucu / framework sürüm izleri; her tespit kanıt ve güven "
                   "seviyesiyle",
                   "Front-end JavaScript libraries, server / framework version traces; every detection with "
                   "evidence and confidence level"),
                 L("Sunucu tarafı kütüphaneler, kesin envanter, lisans analizi",
                   "Server-side libraries, exact inventory, license analysis")],
                [L("Önerilen", "Recommended"),
                 L("Minimum + ön yüz ve sunucu tarafı bağımlılık dosyaları + sunucu yazılımı bilgisi "
                   "(kaynak kod gerekmez)",
                   "Minimum + front-end and server-side dependency files + server software information "
                   "(no source code needed)"),
                 L("Ön yüz ve sunucu tarafı tam bağımlılık envanteri kesin sürümleriyle, SBOM, lisans analizi",
                   "Complete front-end and server-side dependency inventory with exact versions, SBOM, license "
                   "analysis"),
                 L("İşletim sistemi / container katmanı, koda gömülü kütüphaneler",
                   "Operating system / container layer, vendored libraries")],
                [L("Tam", "Full"),
                 L("Önerilen + kaynak kod + container imajı veya canlıya dağıtılan paket",
                   "Recommended + source code + container image or the package deployed to production"),
                 L("İşletim sistemi paketleri ve gömülü kütüphaneler dahil tam envanter",
                   "Complete inventory including operating system packages and vendored libraries"),
                 L("—", "—")],
            ]},
            {"type": "note", "text": L(
                "Önerimiz: en az Önerilen seviye. Web uygulamasının asıl riskli bileşenleri sunucu tarafındadır.",
                "Our recommendation: at least the Recommended level. The riskiest components of a web application "
                "are on the server side.")},
        ]},
        {"title": L("3. Uygulama Bilgileri ve Talep Edilen Dosyalar",
                    "3. Application Information and Requested Files"), "blocks": [
            {"type": "para", "text": L(
                "Her madde için durumu işaretleyiniz. Seviye sütunu, maddenin hangi analiz seviyesinde gerektiğini "
                "gösterir:",
                "Mark the status of each item. The Level column shows at which analysis level the item is "
                "required:")},
            {"type": "items", "rows": [
                tier_select("WEB"),
                {"id": "WEB-01", "level": "S1",
                 "text": L("Web adresleri (URL) ve test edilecek ortam (canlı / test) (BB-01, BB-14)",
                           "Web addresses (URLs) and the environment to be tested (production / test) "
                           "(BB-01, BB-14)"),
                 "field": True, "lines": 2},
                {"id": "WEB-02", "level": "S1",
                 "text": L("İmzalı yazılı test izni (BB-10)", "Signed written test authorization (BB-10)")},
                {"id": "WEB-03", "level": "S1",
                 "text": L("Ön yüz teknolojisi", "Front-end technology"),
                 "hint": L("SPA: React, Angular, Vue vb. Sunucu taraflı: sayfalar sunucuda üretilir (JSP, ASP.NET MVC, "
                           "PHP vb.).",
                           "SPA: React, Angular, Vue, etc. Server-side: pages are rendered on the server (JSP, "
                           "ASP.NET MVC, PHP, etc.)."),
                 "opts": [L("SPA", "SPA"), L("Sunucu taraflı", "Server-side"), L("Bilinmiyor", "Unknown")]},
                {"id": "WEB-04", "level": "S1",
                 "text": L("Sunucu tarafı teknolojisi", "Server-side technology"),
                 "opts": [L("Java", "Java"), L(".NET", ".NET"), L("PHP", "PHP"), L("Node.js", "Node.js"),
                          L("Python", "Python"), L("Diğer", "Other")]},
                {"id": "WEB-05", "level": "O",
                 "text": L("Test kullanıcı hesabı (giriş sonrası sayfalardaki bileşenler için) (BB-30)",
                           "Test user account (for components on post-login pages) (BB-30)")},
                {"id": "WEB-10", "level": "S2",
                 "text": L("Ön yüz bağımlılık dosyaları: package.json + package-lock.json / yarn.lock / "
                           "pnpm-lock.yaml (Bölüm 4)",
                           "Front-end dependency files: package.json + package-lock.json / yarn.lock / "
                           "pnpm-lock.yaml (Section 4)"),
                 "hint": L("Yalnızca WEB-03'te SPA seçildiyse.",
                           "Only if SPA was selected in WEB-03.")},
                {"id": "WEB-11", "level": "S2",
                 "text": L("Sunucu tarafı bağımlılık dosyaları veya komut çıktısı (Bölüm 4)",
                           "Server-side dependency files or command output (Section 4)")},
                {"id": "WEB-12", "level": "S2",
                 "text": L("Sunucu yazılımı ve runtime bilgisi: işletim sistemi, web / uygulama sunucusu (IIS, "
                           "Tomcat, nginx vb.), Java / .NET / PHP / Node.js sürümü (WB-23)",
                           "Server software and runtime information: operating system, web / application server "
                           "(IIS, Tomcat, nginx, etc.), Java / .NET / PHP / Node.js version (WB-23)")},
                {"id": "WEB-20", "level": "S3",
                 "text": L("Kaynak kod ve canlıdaki sürümün commit / tag bilgisi (WB-01, WB-02)",
                           "Source code and the commit / tag of the production version (WB-01, WB-02)")},
                {"id": "WEB-21", "level": "S3",
                 "text": L("Container imajı veya canlıya dağıtılan paket (WAR, publish dizini vb.) (WB-10, WB-11)",
                           "Container image or the package deployed to production (WAR, publish directory, etc.) "
                           "(WB-10, WB-11)")},
            ]},
        ]},
        {"title": L("4. Bağımlılık Dosyalarının Hazırlanması (Önerilen seviye)",
                    "4. Preparing the Dependency Files (Recommended level)"), "blocks": [
            {"type": "para", "text": L(
                "Lock dosyası (package-lock.json, composer.lock, poetry.lock vb.) projede varsa yalnızca o dosyayı ve "
                "manifest dosyasını iletmeniz yeterlidir. Yoksa, kullandığınız teknolojinin komutunu canlıya çıkan "
                "sürümün build ortamında çalıştırınız:",
                "If a lock file (package-lock.json, composer.lock, poetry.lock, etc.) exists in the project, "
                "providing that file and the manifest is sufficient. Otherwise, run the command for your technology "
                "in the build environment of the production release:")},
            {"type": "code", "code":
                "npm ls --all --json > npm-deps.json                          # Node.js / L:ön yüz|front end\n"
                "mvn -B dependency:tree -DoutputType=text -DappendOutput=true \\\n"
                "    -DoutputFile=\"$(pwd)/maven-dependency-tree.txt\"          # Java (Maven)\n"
                "./gradlew -q dependencies --configuration runtimeClasspath > gradle-deps.txt  # Java (Gradle)\n"
                "dotnet list <cozum>.sln package --include-transitive > dotnet-deps.txt     # .NET\n"
                "composer show --tree > composer-tree.txt                     # PHP\n"
                "python -m pip freeze --all > python-deps.txt                 # Python (L:canlı ortamda|in production)"},
            {"type": "para", "text": L(
                "Diğer teknolojiler, çok modüllü projeler ve lock dosyası hiç olmayan durumlar için Kılavuz "
                "Bölüm 4'e bakınız.",
                "For other technologies, multi-module projects and cases with no lock file at all, see Guide "
                "Section 4.")},
        ]},
    ] + common_tail("WEB", 5),
}

API = {
    "file": ("SCA_Senaryo_Karti_API_TR", "SCA_Scenario_Card_API_EN"),
    "title": TITLE,
    "subtitle": L("Senaryo Kartı: API", "Scenario Card: API"),
    "legend_at": 2, "breaks": (2,), "legend": LEGEND,
    "sections": [
        {"title": L("1. Sadece API adresini / Swagger dosyasını versek yeter mi?",
                    "1. Is the API address / Swagger file alone enough?"), "blocks": [
            intro("bir API (web servisi)", "an API (web service)",
                  "API sızma testiyle birlikte yürütülebilir.",
                  "It can be carried out together with an API penetration test."),
            {"type": "answer",
             "title": L("Kısa cevap: Hayır, tek başına yeterli değildir. En az API'nin bağımlılık dosyaları "
                        "gerekir; kaynak kod gerekmez.",
                        "Short answer: no, it is not sufficient on its own. At least the API's dependency files are "
                        "required; source code is not."),
             "text": L(
                 "API'ler istemciye kütüphane kodu göndermez. Bu nedenle dışarıdan yalnızca HTTP başlıkları, hata "
                 "mesajları ve framework davranışlarından sınırlı sayıda bileşen tahmin edilebilir; API'nin "
                 "kullandığı kütüphanelerin neredeyse tamamı görünmez kalır. Swagger / OpenAPI dosyası sızma testi "
                 "için çok faydalıdır, ancak bileşen ve sürüm bilgisi içermediği için SCA'ya katkısı yoktur. "
                 "Anlamlı bir SCA için API projesinin bağımlılık (lock) dosyaları veya bağımlılık komut çıktısı ile "
                 "sunucu / runtime bilgisi gereklidir. Bunlar kaynak kod paylaşmadan sağlanabilir.",
                 "APIs do not send library code to the client. Therefore only a limited number of components can be "
                 "inferred from outside, from HTTP headers, error messages and framework behaviour; almost all "
                 "libraries used by the API remain invisible. A Swagger / OpenAPI file is very useful for a "
                 "penetration test, but it contains no component or version information and therefore does not "
                 "contribute to SCA. A meaningful SCA requires the API project's dependency (lock) files or a "
                 "dependency command output, plus server / runtime information. These can be provided without "
                 "sharing source code.")},
        ]},
        {"title": L("2. Analiz Seviyeleri", "2. Analysis Levels"), "blocks": [
            {"type": "table", "header": TIER_HEADER, "widths": TIER_WIDTHS, "rows": [
                [L("Minimum", "Minimum"),
                 L("API adresleri, varsa Swagger / Postman, yazılı test izni",
                   "API addresses, Swagger / Postman if available, written test authorization"),
                 L("Yalnızca dışarıdan görünen sunucu / framework sürümleri; sonuçlar sınırlıdır",
                   "Only externally visible server / framework versions; results are limited"),
                 L("API kütüphanelerinin neredeyse tamamı, lisans analizi",
                   "Almost all API libraries, license analysis")],
                [L("Önerilen", "Recommended"),
                 L("Minimum + bağımlılık dosyaları / komut çıktısı + sunucu ve API ağ geçidi bilgisi "
                   "(kaynak kod gerekmez)",
                   "Minimum + dependency files / command output + server and API gateway information "
                   "(no source code needed)"),
                 L("API'nin tam bağımlılık envanteri kesin sürümleriyle, SBOM, lisans analizi",
                   "Complete dependency inventory of the API with exact versions, SBOM, license analysis"),
                 L("İşletim sistemi / container katmanı, koda gömülü kütüphaneler",
                   "Operating system / container layer, vendored libraries")],
                [L("Tam", "Full"),
                 L("Önerilen + kaynak kod + container imajı veya canlıya dağıtılan paket",
                   "Recommended + source code + container image or the package deployed to production"),
                 L("İşletim sistemi paketleri ve gömülü kütüphaneler dahil tam envanter",
                   "Complete inventory including operating system packages and vendored libraries"),
                 L("—", "—")],
            ]},
            {"type": "note", "text": L(
                "Önerimiz: en az Önerilen seviye. API için Minimum seviye yalnızca ön bilgi niteliğindedir.",
                "Our recommendation: at least the Recommended level. For APIs, the Minimum level provides only "
                "preliminary information.")},
        ]},
        {"title": L("3. API Bilgileri ve Talep Edilen Dosyalar", "3. API Information and Requested Files"), "blocks": [
            {"type": "para", "text": L(
                "Her madde için durumu işaretleyiniz. Seviye sütunu, maddenin hangi analiz seviyesinde gerektiğini "
                "gösterir:",
                "Mark the status of each item. The Level column shows at which analysis level the item is "
                "required:")},
            {"type": "items", "rows": [
                tier_select("API"),
                {"id": "API-01", "level": "S1",
                 "text": L("API adresleri (base URL) ve test edilecek ortam (canlı / test) (BB-02, BB-14)",
                           "API addresses (base URLs) and the environment to be tested (production / test) "
                           "(BB-02, BB-14)"),
                 "field": True, "lines": 2},
                {"id": "API-02", "level": "S1",
                 "text": L("İmzalı yazılı test izni (BB-10)", "Signed written test authorization (BB-10)")},
                {"id": "API-03", "level": "S1",
                 "text": L("API'nin geliştirildiği teknoloji", "Technology the API is built with"),
                 "opts": [L("Java", "Java"), L(".NET", ".NET"), L("Node.js", "Node.js"), L("PHP", "PHP"),
                          L("Python", "Python"), L("Go", "Go"), L("Diğer", "Other")]},
                {"id": "API-04", "level": "O",
                 "text": L("Swagger / OpenAPI dosyası veya Postman koleksiyonu (BB-02)",
                           "Swagger / OpenAPI file or Postman collection (BB-02)")},
                {"id": "API-05", "level": "O",
                 "text": L("Test kullanıcı hesabı / API anahtarı (BB-30)", "Test user account / API key (BB-30)")},
                {"id": "API-10", "level": "S2",
                 "text": L("API projesinin bağımlılık dosyaları veya komut çıktısı (Bölüm 4)",
                           "Dependency files or command output of the API project (Section 4)")},
                {"id": "API-11", "level": "S2",
                 "text": L("Sunucu yazılımı ve runtime bilgisi: işletim sistemi, uygulama sunucusu, Java / .NET / "
                           "Node.js vb. sürümü (WB-23)",
                           "Server software and runtime information: operating system, application server, Java / "
                           ".NET / Node.js, etc. version (WB-23)")},
                {"id": "API-12", "level": "S2",
                 "text": L("API ağ geçidi / ara katman ürünleri ve sürümleri (ör. Kong, Apigee, Azure API "
                           "Management, nginx)",
                           "API gateway / middleware products and their versions (e.g. Kong, Apigee, Azure API "
                           "Management, nginx)"),
                 "hint": L("Kullanılmıyorsa \"U/D\" işaretleyiniz.", "Mark \"N/A\" if not used.")},
                {"id": "API-20", "level": "S3",
                 "text": L("Kaynak kod ve canlıdaki sürümün commit / tag bilgisi (WB-01, WB-02)",
                           "Source code and the commit / tag of the production version (WB-01, WB-02)")},
                {"id": "API-21", "level": "S3",
                 "text": L("Container imajı veya canlıya dağıtılan paket (WB-10, WB-11)",
                           "Container image or the package deployed to production (WB-10, WB-11)")},
            ]},
        ]},
        {"title": L("4. Bağımlılık Dosyalarının Hazırlanması (Önerilen seviye)",
                    "4. Preparing the Dependency Files (Recommended level)"), "blocks": [
            {"type": "para", "text": L(
                "Lock dosyası (package-lock.json, composer.lock, go.sum, poetry.lock vb.) projede varsa yalnızca o "
                "dosyayı ve manifest dosyasını iletmeniz yeterlidir. Yoksa, kullandığınız teknolojinin komutunu "
                "canlıya çıkan sürümün build ortamında çalıştırınız:",
                "If a lock file (package-lock.json, composer.lock, go.sum, poetry.lock, etc.) exists in the project, "
                "providing that file and the manifest is sufficient. Otherwise, run the command for your technology "
                "in the build environment of the production release:")},
            {"type": "code", "code":
                "mvn -B dependency:tree -DoutputType=text -DappendOutput=true \\\n"
                "    -DoutputFile=\"$(pwd)/maven-dependency-tree.txt\"          # Java (Maven)\n"
                "./gradlew -q dependencies --configuration runtimeClasspath > gradle-deps.txt  # Java (Gradle)\n"
                "dotnet list <cozum>.sln package --include-transitive > dotnet-deps.txt     # .NET\n"
                "npm ls --all --json > npm-deps.json                          # Node.js\n"
                "composer show --tree > composer-tree.txt                     # PHP\n"
                "python -m pip freeze --all > python-deps.txt                 # Python (L:canlı ortamda|in production)\n"
                "go list -m all > go-modules.txt                              # Go"},
            {"type": "para", "text": L(
                "Diğer teknolojiler, çok modüllü projeler ve lock dosyası hiç olmayan durumlar için Kılavuz "
                "Bölüm 4'e bakınız.",
                "For other technologies, multi-module projects and cases with no lock file at all, see Guide "
                "Section 4.")},
        ]},
    ] + common_tail("API", 5),
}


DESKTOP = {
    "file": ("SCA_Senaryo_Karti_Masaustu_TR", "SCA_Scenario_Card_Desktop_EN"),
    "title": TITLE,
    "subtitle": L("Senaryo Kartı: Masaüstü Uygulaması (Windows / macOS / Linux)",
                  "Scenario Card: Desktop Application (Windows / macOS / Linux)"),
    "legend_at": 2, "breaks": (2,), "legend": LEGEND,
    "sections": [
        {"title": L("1. Sadece kurulum dosyasını (EXE / MSI) versek yeter mi?",
                    "1. Is the installer (EXE / MSI) alone enough?"), "blocks": [
            intro("bir masaüstü uygulaması", "a desktop application",
                  "Masaüstü uygulama (thick client) sızma testiyle birlikte yürütülebilir.",
                  "It can be carried out together with a desktop application (thick client) penetration test."),
            {"type": "answer",
             "title": L("Kısa cevap: Çoğu durumda büyük ölçüde yeterlidir. Sonucu kesinleştirmek için bağımlılık "
                        "dosyaları önerilir.",
                        "Short answer: in most cases it is largely sufficient. Dependency files are recommended to "
                        "make the result exact."),
             "text": L(
                 "Masaüstü uygulamalar, kullandıkları kütüphaneleri genellikle ayrı dosyalar olarak (DLL, JAR, "
                 "Electron uygulamalarında paketlenmiş Node.js modülleri) ve çoğu zaman yanlarında bir çalışma "
                 "ortamıyla (Java, .NET, Chromium) birlikte dağıtır. Bu nedenle kurulum dosyası veya kurulu uygulama "
                 "dizini ile bileşenlerin büyük bölümü ve sürümleri tespit edilebilir; .NET, Java ve Electron "
                 "uygulamalarında sürümler çoğunlukla kesin olarak belirlenir. C/C++ ile geliştirilmiş ve "
                 "kütüphaneleri statik olarak içine derlenmiş uygulamalarda ise bazı bileşenlerin sürümü tahmini "
                 "kalır. Bağımlılık dosyaları veya komut çıktısı eklendiğinde tüm sürümler kesinleşir; kaynak kod "
                 "paylaşmanız gerekmez. Uygulamanın bağlandığı sunucu / API bu yöntemle analiz edilemez; kapsamdaysa "
                 "\"Senaryo Kartı: API\"yi ayrıca doldurunuz.",
                 "Desktop applications usually ship the libraries they use as separate files (DLLs, JARs, Node.js "
                 "modules packaged in Electron apps), often together with a bundled runtime (Java, .NET, Chromium). "
                 "Therefore most components and their versions can be identified from the installer or the installed "
                 "application directory; in .NET, Java and Electron applications versions are mostly determined "
                 "exactly. In applications developed in C/C++ with libraries statically compiled in, the version of "
                 "some components remains estimated. Adding dependency files or command output makes all versions "
                 "exact; you do not need to share source code. The server / API the application connects to cannot "
                 "be analysed this way; if it is in scope, please also complete \"Scenario Card: API\".")},
        ]},
        {"title": L("2. Analiz Seviyeleri", "2. Analysis Levels"), "blocks": [
            {"type": "table", "header": TIER_HEADER, "widths": TIER_WIDTHS, "rows": [
                [L("Minimum", "Minimum"),
                 L("Kullanıcılara dağıtılan sürümün kurulum dosyası veya kurulu uygulama dizini",
                   "Installer of the version distributed to users, or the installed application directory"),
                 L("Paketlenmiş kütüphaneler ve gömülü çalışma ortamları (Java, .NET, Chromium), bilinen zafiyetler; "
                   "native bileşenlerde bazı sürümler tahmini",
                   "Packaged libraries and bundled runtimes (Java, .NET, Chromium), known vulnerabilities; some "
                   "versions of native components estimated"),
                 L("Statik derlenmiş bazı native kütüphaneler, lisans analizi (sınırlı), sunucu / API",
                   "Some statically compiled native libraries, license analysis (limited), server / API")],
                [L("Önerilen", "Recommended"),
                 L("Minimum + bağımlılık dosyaları / komut çıktısı + üçüncü taraf bileşen listesi "
                   "(kaynak kod gerekmez)",
                   "Minimum + dependency files / command output + third-party component list "
                   "(no source code needed)"),
                 L("Tüm bağımlılıklar kesin sürümleriyle, SBOM, lisans analizi",
                   "All dependencies with exact versions, SBOM, license analysis"),
                 L("Sunucu / API", "Server / API")],
                [L("Tam", "Full"),
                 L("Önerilen + kaynak kod + kurulum paketi tanımları",
                   "Recommended + source code + installer package definitions"),
                 L("Koda gömülü kütüphaneler dahil tam envanter",
                   "Complete inventory including vendored libraries"),
                 L("—", "—")],
            ]},
            {"type": "note", "text": L(
                "Önerimiz: .NET, Java ve Electron uygulamalarında Minimum seviye çoğu zaman iyi sonuç verir; C/C++ "
                "uygulamalarında ve kesin SBOM gerekiyorsa Önerilen seviye.",
                "Our recommendation: for .NET, Java and Electron applications the Minimum level often gives good "
                "results; for C/C++ applications, or when an exact SBOM is required, the Recommended level.")},
        ]},
        {"title": L("3. Uygulama Bilgileri ve Talep Edilen Dosyalar",
                    "3. Application Information and Requested Files"), "blocks": [
            {"type": "para", "text": L(
                "Her madde için durumu işaretleyiniz. Seviye sütunu, maddenin hangi analiz seviyesinde gerektiğini "
                "gösterir:",
                "Mark the status of each item. The Level column shows at which analysis level the item is "
                "required:")},
            {"type": "items", "rows": [
                tier_select("DSK"),
                {"id": "DSK-01", "level": "S1",
                 "text": L("İşletim sistemi", "Operating system"),
                 "opts": [L("Windows", "Windows"), L("macOS", "macOS"), L("Linux", "Linux"),
                          L("Birden fazla", "Multiple")]},
                {"id": "DSK-02", "level": "S1",
                 "text": L("Uygulamanın geliştirildiği teknoloji", "Technology the application is built with"),
                 "hint": L(".NET: WinForms, WPF, MAUI. C / C++: Qt, MFC, Win32 vb. Emin değilseniz geliştirme "
                           "ekibinize sorunuz.",
                           ".NET: WinForms, WPF, MAUI. C / C++: Qt, MFC, Win32, etc. If unsure, ask your "
                           "development team."),
                 "opts": [L(".NET", ".NET"), L("Java", "Java"), L("Electron", "Electron"), L("C / C++", "C / C++"),
                          L("Diğer", "Other")]},
                {"id": "DSK-03", "level": "S1",
                 "text": L("Uygulama adı ve analiz edilecek sürüm numarası",
                           "Application name and the version number to be analysed"),
                 "field": True, "lines": 2},
                {"id": "DSK-04", "level": "S1",
                 "text": L("Kullanıcılara dağıtılan sürümün kurulum dosyası (EXE, MSI, PKG, DMG, DEB, RPM) veya kurulu "
                           "uygulama dizininin arşivi (WB-11)",
                           "Installer of the version distributed to users (EXE, MSI, PKG, DMG, DEB, RPM) or an archive "
                           "of the installed application directory (WB-11)"),
                 "hint": L("Kurulum sırasında internetten ek bileşen indiriliyorsa kurulu dizinin arşivi tercih "
                           "edilmelidir (Bölüm 4).",
                           "If the installer downloads additional components from the internet, the archive of the "
                           "installed directory is preferred (Section 4).")},
                {"id": "DSK-05", "level": "O",
                 "text": L("Otomatik güncelleme mekanizması ve kullanılan güncelleme bileşeni (ör. Squirrel, Sparkle, "
                           "electron-updater, ClickOnce)",
                           "Automatic update mechanism and the update component used (e.g. Squirrel, Sparkle, "
                           "electron-updater, ClickOnce)")},
                {"id": "DSK-10", "level": "S2",
                 "text": L("Bağımlılık dosyaları veya komut çıktısı (Bölüm 4)",
                           "Dependency files or command output (Section 4)")},
                {"id": "DSK-11", "level": "S2",
                 "text": L("Elle eklenen ve ticari üçüncü taraf bileşenler (DLL, SDK, raporlama / grafik "
                           "kütüphaneleri) ve sürümleri (WB-32, WB-33)",
                           "Manually added and commercial third-party components (DLLs, SDKs, reporting / charting "
                           "libraries) and their versions (WB-32, WB-33)")},
                {"id": "DSK-12", "level": "S2",
                 "text": L("Uygulamayla dağıtılan veya ön koşul olarak kurulan çalışma ortamları ve sürümleri (Java / "
                           "JRE, .NET runtime, Visual C++ Redistributable, WebView2 vb.)",
                           "Runtimes shipped with the application or installed as prerequisites, and their versions "
                           "(Java / JRE, .NET runtime, Visual C++ Redistributable, WebView2, etc.)")},
                {"id": "DSK-20", "level": "S3",
                 "text": L("Kaynak kod ve dağıtılan sürümün commit / tag bilgisi (WB-01, WB-02)",
                           "Source code and the commit / tag of the distributed version (WB-01, WB-02)")},
                {"id": "DSK-21", "level": "S3",
                 "text": L("Kurulum paketi tanımları (WiX .wxs, NSIS .nsi, InstallShield projesi, electron-builder "
                           "yapılandırması vb.)",
                           "Installer package definitions (WiX .wxs, NSIS .nsi, InstallShield project, "
                           "electron-builder configuration, etc.)")},
            ]},
        ]},
        {"title": L("4. Dosyaların Hazırlanması", "4. Preparing the Files"), "blocks": [
            {"type": "para", "text": L(
                "Kurulu uygulama dizininin arşivi (DSK-04), uygulamanın kurulu olduğu bir bilgisayarda:",
                "Archive of the installed application directory (DSK-04), on a computer where the application is "
                "installed:")},
            {"type": "code", "code":
                "# Windows (PowerShell)\n"
                "Compress-Archive -Path \"C:\\Program Files\\<Uygulama>\\*\" -DestinationPath app-dir.zip\n"
                "\n"
                "# macOS\n"
                "ditto -c -k --keepParent \"/Applications/<Uygulama>.app\" app-dir.zip\n"
                "\n"
                "# Linux\n"
                "tar -czf app-dir.tar.gz /opt/<Uygulama>"},
            {"type": "para", "text": L(
                "Bağımlılık dosyaları (DSK-10), lock dosyası projede yoksa dağıtılan sürümün build ortamında:",
                "Dependency files (DSK-10), if the lock file is not in the project, in the build environment of the "
                "distributed version:")},
            {"type": "code", "code":
                "dotnet list <cozum>.sln package --include-transitive > dotnet-deps.txt     # .NET\n"
                "mvn -B dependency:tree -DoutputType=text -DappendOutput=true \\\n"
                "    -DoutputFile=\"$(pwd)/maven-dependency-tree.txt\"          # Java (Maven)\n"
                "./gradlew -q dependencies --configuration runtimeClasspath > gradle-deps.txt  # Java (Gradle)\n"
                "npm ls --omit=dev --all --json > npm-deps.json               # Electron\n"
                "conan graph info . --format=json > conan-graph.json          # C / C++ (Conan 2)\n"
                "vcpkg list > vcpkg-list.txt                                  # C / C++ (vcpkg)\n"
                "qmake -query QT_VERSION                                      # Qt"},
            {"type": "para", "text": L(
                ".NET Framework projelerinde packages.config dosyaları ve Electron projelerinde package.json ile lock "
                "dosyası (package-lock.json / yarn.lock) varsa komut çalıştırmaya gerek yoktur. Paket yöneticisi "
                "kullanılmayan C/C++ projelerinde kütüphane listesini Kılavuz WB-32'deki tablo formatında veriniz.",
                "In .NET Framework projects with packages.config files, and in Electron projects with package.json "
                "and a lock file (package-lock.json / yarn.lock), no command needs to be run. For C/C++ projects "
                "without a package manager, provide the library list in the table format of Guide WB-32.")},
        ]},
    ] + common_tail("DSK", 5),
}

INFRA = {
    "file": ("SCA_Senaryo_Karti_Container_Altyapi_TR", "SCA_Scenario_Card_Container_Infrastructure_EN"),
    "title": TITLE,
    "subtitle": L("Senaryo Kartı: Container ve Altyapı (Kubernetes / Docker / Sunucu)",
                  "Scenario Card: Containers and Infrastructure (Kubernetes / Docker / Server)"),
    "legend_at": 2, "breaks": (2,), "legend": LEGEND,
    "sections": [
        {"title": L("1. Sadece container imajlarını veya IP adreslerini versek yeter mi?",
                    "1. Are container images or IP addresses alone enough?"), "blocks": [
            intro("container imajları, Kubernetes / Docker ortamları veya sunucular", "container images, Kubernetes / "
                  "Docker environments or servers",
                  "Altyapı veya container güvenlik testiyle birlikte yürütülebilir.",
                  "It can be carried out together with an infrastructure or container security test."),
            {"type": "answer",
             "title": L("Kısa cevap: Container imajları büyük ölçüde yeterlidir. Yalnızca IP adresleri ile sonuç "
                        "sınırlı kalır.",
                        "Short answer: container images are largely sufficient. With IP addresses alone the result "
                        "is limited."),
             "text": L(
                 "Container imajları, içlerindeki işletim sistemi paketlerinin ve uygulama kütüphanelerinin kurulum "
                 "kayıtlarını taşır. Bu nedenle imajlar sağlandığında bileşenler kesin sürümleriyle tespit edilir; "
                 "kaynak kod veya ek dosya gerekmez. İmaj içine derlenmiş ve sürüm bilgisi taşımayan bazı binary "
                 "dosyalar ile imaj dışında kalan bileşenler (sunucu / node işletim sistemi, Kubernetes ve ingress, "
                 "service mesh gibi cluster bileşenleri) ise ayrıca bilgi verilmedikçe kapsam dışında kalır. "
                 "Yalnızca IP adresleri verildiğinde analiz, ağ üzerinden açık servislerin dışarıya verdiği sürüm "
                 "bilgileriyle sınırlıdır; sürüm bilgisini gizleyen servisler ve iç bileşenler tespit edilemez.",
                 "Container images carry the installation records of the operating system packages and application "
                 "libraries inside them. Therefore, when images are provided, components are identified with exact "
                 "versions; no source code or additional files are needed. Some binaries compiled into the image "
                 "without version metadata, and components outside the image (server / node operating system, "
                 "cluster components such as Kubernetes, ingress and service mesh), are out of scope unless "
                 "information about them is provided separately. When only IP addresses are given, the analysis is "
                 "limited to version information exposed by services open on the network; services that hide their "
                 "version and internal components cannot be identified.")},
        ]},
        {"title": L("2. Analiz Seviyeleri", "2. Analysis Levels"), "blocks": [
            {"type": "table", "header": TIER_HEADER, "widths": TIER_WIDTHS, "rows": [
                [L("Minimum", "Minimum"),
                 L("IP adresleri / sunucu adları, yazılı test izni ve port / servis taraması izni",
                   "IP addresses / host names, written test authorization and port / service scanning permission"),
                 L("Ağa açık servislerin dışarıya verdiği sürüm bilgileri ve bilinen zafiyetleri",
                   "Version information exposed by network services and their known vulnerabilities"),
                 L("Sürümünü gizleyen servisler, container ve sunucu içindeki tüm bileşenler",
                   "Services hiding their version, all components inside containers and servers")],
                [L("Önerilen", "Recommended"),
                 L("Çalışan imajların listesi (digest) ve imajların kendisi; container kullanılmayan sunucularda "
                   "paket listeleri",
                   "List of running images (digests) and the images themselves; package lists for servers not "
                   "using containers"),
                 L("İşletim sistemi paketleri ve imaj içi kütüphaneler kesin sürümleriyle, base imaj analizi, SBOM",
                   "OS packages and in-image libraries with exact versions, base image analysis, SBOM"),
                 L("Cluster bileşenleri, Kubernetes yapılandırması",
                   "Cluster components, Kubernetes configuration")],
                [L("Tam", "Full"),
                 L("Önerilen + Kubernetes / Helm tanımları, Dockerfile'lar, cluster bileşen sürümleri",
                   "Recommended + Kubernetes / Helm definitions, Dockerfiles, cluster component versions"),
                 L("Sidecar ve init container'lar dahil tüm imajlar, base imaj zinciri, cluster bileşenleri",
                   "All images including sidecar and init containers, base image chain, cluster components"),
                 L("—", "—")],
            ]},
            {"type": "note", "text": L(
                "Önerimiz: Önerilen seviye. Container ortamlarında kesin sonucun ana kaynağı imajların kendisidir; "
                "Minimum seviye yalnızca dışarıdan görünen yüzeyi kapsar.",
                "Our recommendation: the Recommended level. In container environments the main source of exact "
                "results is the images themselves; the Minimum level covers only the externally visible surface.")},
        ]},
        {"title": L("3. Ortam Bilgileri ve Talep Edilen Dosyalar",
                    "3. Environment Information and Requested Files"), "blocks": [
            {"type": "para", "text": L(
                "Her madde için durumu işaretleyiniz. Seviye sütunu, maddenin hangi analiz seviyesinde gerektiğini "
                "gösterir:",
                "Mark the status of each item. The Level column shows at which analysis level the item is "
                "required:")},
            {"type": "items", "rows": [
                tier_select("INF"),
                {"id": "INF-01", "level": "S1",
                 "text": L("Ortam türü", "Environment type"),
                 "opts": [L("Kubernetes", "Kubernetes"), L("Docker", "Docker"), L("Sunucu (VM)", "Server (VM)"),
                          L("Birden fazla", "Multiple")]},
                {"id": "INF-02", "level": "S1",
                 "text": L("Kubernetes dağıtımı (Kubernetes kullanılıyorsa)",
                           "Kubernetes distribution (if Kubernetes is used)"),
                 "hint": L("Yönetilen: AWS EKS, Azure AKS, Google GKE. Diğer: Rancher, kubeadm, Tanzu vb.",
                           "Managed: AWS EKS, Azure AKS, Google GKE. Other: Rancher, kubeadm, Tanzu, etc."),
                 "opts": [L("OpenShift", "OpenShift"), L("Yönetilen", "Managed"), L("Diğer", "Other"),
                          L("U/D", "N/A")]},
                {"id": "INF-03", "level": "S1",
                 "text": L("IP adresleri / aralıkları veya sunucu adları; kapsamdaki namespace'ler (BB-04, WB-03)",
                           "IP addresses / ranges or host names; in-scope namespaces (BB-04, WB-03)"),
                 "field": True, "lines": 2},
                {"id": "INF-04", "level": "S1",
                 "text": L("İmzalı yazılı test izni ve port / servis taraması izni (BB-10, BB-21)",
                           "Signed written test authorization and port / service scanning permission (BB-10, BB-21)")},
                {"id": "INF-05", "level": "O",
                 "text": L("Kapsam dışı tutulacak sunucu / namespace / imaj listesi (BB-05)",
                           "Servers / namespaces / images to exclude (BB-05)"),
                 "field": True},
                {"id": "INF-10", "level": "S2",
                 "text": L("Canlıda çalışan imajların listesi, digest dahil (WB-10, Bölüm 4)",
                           "List of images running in production, including digests (WB-10, Section 4)")},
                {"id": "INF-11", "level": "S2",
                 "text": L("İmajların kendisi: registry'ye yalnızca pull yetkili erişim veya dışa aktarılmış imaj "
                           "dosyaları (WB-10)",
                           "The images themselves: pull-only registry access or exported image files (WB-10)")},
                {"id": "INF-12", "level": "S2",
                 "text": L("Container kullanılmayan sunucularda işletim sistemi sürümü ve kurulu paket listesi (WB-23)",
                           "For servers not using containers: operating system version and installed package list "
                           "(WB-23)"),
                 "hint": L("Yalnızca INF-01'de Sunucu (VM) veya Birden fazla seçildiyse.",
                           "Only if Server (VM) or Multiple was selected in INF-01.")},
                {"id": "INF-20", "level": "S3",
                 "text": L("Kubernetes workload tanımları ve Helm values dosyaları — parolalar maskelenmiş (WB-21)",
                           "Kubernetes workload definitions and Helm values files — passwords masked (WB-21)")},
                {"id": "INF-21", "level": "S3",
                 "text": L("Dockerfile'lar (WB-20)", "Dockerfiles (WB-20)")},
                {"id": "INF-22", "level": "S3",
                 "text": L("Cluster bileşen sürümleri: Kubernetes, node işletim sistemi ve container runtime, ingress "
                           "controller, service mesh, operatörler (Bölüm 4)",
                           "Cluster component versions: Kubernetes, node operating system and container runtime, "
                           "ingress controller, service mesh, operators (Section 4)")},
            ]},
        ]},
        {"title": L("4. Dosyaların Hazırlanması", "4. Preparing the Files"), "blocks": [
            {"type": "para", "text": L(
                "Çalışan imajların listesi (INF-10) ve imajların dışa aktarılması (INF-11):",
                "List of running images (INF-10) and exporting the images (INF-11):")},
            {"type": "code", "code":
                "# Kubernetes\n"
                "COLS='NS:.metadata.namespace,POD:.metadata.name'\n"
                "COLS=\"$COLS,IMAGES:.status.containerStatuses[*].imageID\"\n"
                "COLS=\"$COLS,INIT:.status.initContainerStatuses[*].imageID\"\n"
                "kubectl get pods -A -o custom-columns=\"$COLS\" > k8s-images.txt\n"
                "\n"
                "# Docker\n"
                "docker ps --format '{{.Image}}' | sort -u > docker-images.txt\n"
                "docker save <registry>/<imaj>:<etiket> | gzip > <imaj>_<etiket>.tar.gz"},
            {"type": "para", "text": L(
                "Sunucu paket listesi (INF-12) ve cluster bileşen sürümleri (INF-22):",
                "Server package list (INF-12) and cluster component versions (INF-22):")},
            {"type": "code", "code":
                "dpkg-query -W -f='${Package}\\t${Version}\\t${source:Package}\\t${source:Version}\\n' \\\n    > os-packages.txt                                                    # Debian / Ubuntu\n"
                "rpm -qa --qf '%{NAME}\\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\\t%{SOURCERPM}\\n' \\\n    > os-packages.txt                                               # RHEL / CentOS / Rocky / Alma\n"
                "\n"
                "kubectl version > cluster-versions.txt\n"
                "kubectl get nodes -o wide >> cluster-versions.txt   # L:node OS, kernel, container runtime|node OS, kernel, container runtime\n"
                "helm list -A > helm-releases.txt                    # L:Helm ile kurulan bileşenlerin sürümleri|versions of components installed with Helm"},
            {"type": "note", "text": L(
                "Dikkat: Kubernetes Secret nesnelerini, kubeconfig dosyalarını ve parola içeren Helm values "
                "dosyalarını maskelemeden göndermeyiniz. Ayrıntılar: Kılavuz WB-10 ve WB-21.",
                "Caution: do not send Kubernetes Secret objects, kubeconfig files or Helm values files containing "
                "passwords without masking. Details: Guide WB-10 and WB-21.")},
        ]},
    ] + common_tail("INF", 5),
}

CARDS = [MOBILE, WEB, API, DESKTOP, INFRA]
