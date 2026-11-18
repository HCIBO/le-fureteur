def L(tr, en):
    return {"tr": tr, "en": en}


def resolve(obj, lang):
    if isinstance(obj, dict):
        if set(obj) == {"tr", "en"}:
            return obj[lang]
        return {k: resolve(v, lang) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [resolve(v, lang) for v in obj]
    return obj


VERSION = "1.0"

LEVELS = {
    "Z": L("Zorunlu", "Mandatory"),
    "K": L("Koşullu", "Conditional"),
    "O": L("Opsiyonel", "Optional"),
    "S1": L("Minimum", "Minimum"),
    "S2": L("Önerilen", "Recommended"),
    "S3": L("Tam", "Full"),
}

OPTS = {
    "vyu": [L("Var", "Yes"), L("Yok", "No"), L("U/D", "N/A")],
    "eh": [L("Evet", "Yes"), L("Hayır", "No")],
    "eco": [L("Manifest + lock", "Manifest + lock"),
            L("Komut çıktısı", "Command output"),
            L("Kullanılmıyor", "Not used")],
}

UI = {
    "col_id": L("No", "No"),
    "col_item": L("Gereksinim", "Requirement"),
    "col_level": L("Seviye", "Level"),
    "col_status": L("Durum", "Status"),
    "col_note": L("Açıklama / Konum", "Notes / Location"),
    "col_tech": L("Teknoloji", "Technology"),
    "col_files": L("Sağlanacak dosyalar", "Files to provide"),
    "col_cmd": L("Lock dosyası yoksa", "If no lock file"),
    "manifest": L("Manifest", "Manifest"),
    "lock": L("Lock", "Lock"),
    "confidential": L("GİZLİ", "CONFIDENTIAL"),
    "page": L("Sayfa", "Page"),
    "version": L("Sürüm", "Version"),
}

TITLE = L("Yazılım Bileşen Analizi (SCA) Hizmeti",
          "Software Composition Analysis (SCA) Service")
SUBTITLE = L("Ön Gereksinimler ve Bilgi Toplama Formu",
             "Prerequisites and Information Request Form")

SECTIONS = [
    {
        "title": L("1. SCA Nedir?", "1. What is SCA?"),
        "blocks": [
            {"type": "para", "text": L(
                "Yazılım Bileşen Analizi (Software Composition Analysis – SCA), uygulamalarınızın kullandığı "
                "açık kaynak ve üçüncü taraf bileşenlerin (kütüphane, framework, paket, container imajı, SDK vb.) "
                "tespit edilmesi ve bu bileşenlerdeki bilinen güvenlik açıklarının, lisans risklerinin ve tedarik "
                "zinciri risklerinin raporlanması sürecidir.",
                "Software Composition Analysis (SCA) is the process of identifying the open-source and third-party "
                "components your applications rely on (libraries, frameworks, packages, container images, SDKs, etc.) "
                "and reporting the known security vulnerabilities, license risks and supply-chain risks they carry.")},
            {"type": "para", "text": L(
                "Modern uygulamalarda kodun önemli bir bölümü üçüncü taraf bileşenlerden oluşur. Bu bileşenlerden "
                "birinde yayımlanan bir güvenlik açığı, kendi kodunuzda hiçbir hata olmasa bile uygulamanızı "
                "doğrudan etkileyebilir. SCA hizmeti iki farklı yaklaşımla sunulmaktadır:",
                "In modern applications a significant share of the code base consists of third-party components. "
                "A vulnerability published in one of them can affect your application directly, even when your own "
                "code contains no flaw. The SCA service is offered in two approaches:")},
            {"type": "sub", "title": L("Whitebox (Beyaz Kutu) SCA", "Whitebox SCA")},
            {"type": "para", "text": L(
                "Kaynak kod, bağımlılık dosyaları ve derlenmiş çıktılar tarafımıza sağlanır. Bileşen envanteri "
                "doğrudan bu dosyalardan çıkarıldığı için en kapsamlı ve en kesin sonucu verir: doğrudan ve dolaylı "
                "(transitive) tüm bağımlılıklar, container imajları ve lisanslar analiz edilir. Analiz çevrimdışı "
                "yapılır; hedef sistemlerinize herhangi bir istek gönderilmez.",
                "Source code, dependency files and build outputs are provided to us. Because the component inventory "
                "is extracted directly from these files, this approach gives the most complete and most accurate "
                "result: all direct and transitive dependencies, container images and licenses are analysed. The "
                "analysis is performed offline; no requests are sent to your systems.")},
            {"type": "sub", "title": L("Blackbox (Siyah Kutu) SCA", "Blackbox SCA")},
            {"type": "para", "text": L(
                "Tarafımıza kaynak kod veya dosya sağlanmaz; yalnızca hedef bilgisi (web uygulaması, API, mobil "
                "uygulama, altyapı) ve yazılı test izni verilir. Bileşenler ve sürümleri, dışarıdan gözlemlenebilen "
                "izlerden (JavaScript dosyaları, HTTP yanıtları ve başlıkları, hata mesajları, mobil uygulama paketi, "
                "servis bilgileri vb.) tespit edilir. Gerçek bir saldırganın göreceği görünümü yansıtır.",
                "No source code or files are provided; only the target information (web application, API, mobile "
                "application, infrastructure) and a written test authorization. Components and their versions are "
                "identified from externally observable traces (JavaScript files, HTTP responses and headers, error "
                "messages, the mobile application package, service banners, etc.). It reflects the view a real "
                "attacker would have.")},
            {"type": "sub", "title": L("Hibrit SCA (Önerilen)", "Hybrid SCA (Recommended)")},
            {"type": "para", "text": L(
                "Her iki yaklaşım birlikte uygulanır ve sonuçlar tek bir bileşen envanterinde birleştirilir. "
                "Whitebox tam envanteri, blackbox ise bu bileşenlerden hangilerinin dışarıdan görünür ve "
                "erişilebilir olduğunu ortaya koyar.",
                "Both approaches are applied and the results are merged into a single component inventory. "
                "Whitebox provides the complete inventory; blackbox shows which of those components are visible "
                "and reachable from the outside.")},
            {"type": "table",
             "header": [L("", ""), L("Whitebox", "Whitebox"), L("Blackbox", "Blackbox")],
             "rows": [
                 [L("Sizden beklenen", "What we need from you"),
                  L("Kaynak kod, bağımlılık dosyaları, artefaktlar (Bölüm 3)",
                    "Source code, dependency files, artefacts (Section 3)"),
                  L("Hedef listesi ve yazılı test izni (Bölüm 4)",
                    "Target list and written test authorization (Section 4)")],
                 [L("Kapsam", "Coverage"),
                  L("Tüm doğrudan ve dolaylı bağımlılıklar, container imajları, lisanslar",
                    "All direct and transitive dependencies, container images, licenses"),
                  L("Yalnızca dışarıdan gözlemlenebilen bileşenler",
                    "Only externally observable components")],
                 [L("Kesinlik", "Accuracy"),
                  L("Yüksek — sürümler dosyalardan okunur",
                    "High — versions are read from files"),
                  L("Değişken — sürümler gözlemden çıkarılır; her tespit kanıtı ve güven seviyesiyle raporlanır",
                    "Variable — versions are inferred; every detection is reported with its evidence and confidence level")],
                 [L("Lisans analizi", "License analysis"),
                  L("Tam", "Full"), L("Sınırlı", "Limited")],
                 [L("SBOM (CycloneDX / SPDX)", "SBOM (CycloneDX / SPDX)"),
                  L("Tam envanter", "Complete inventory"),
                  L("Kısmi — yalnızca tespit edilen bileşenler", "Partial — detected components only")],
                 [L("Sistemlerinize etkisi", "Impact on your systems"),
                  L("Yok — çevrimdışı analiz", "None — offline analysis"),
                  L("Düşük — varsayılan pasif analizdir; aktif doğrulama yalnızca onayınızla yapılır",
                    "Low — passive analysis by default; active verification only with your approval")],
                 [L("Ne zaman tercih edilir", "When to choose"),
                  L("Regülasyon / uyum gereksinimleri, tam envanter ihtiyacı, SBOM talebi",
                    "Regulatory / compliance requirements, full inventory, SBOM requests"),
                  L("Saldırgan bakış açısı, kaynak kodun paylaşılamadığı durumlar",
                    "Attacker's perspective, when source code cannot be shared")],
             ]},
            {"type": "note", "text": L(
                "Blackbox sınırlaması: Blackbox analizde yalnızca dışarıdan gözlemlenebilen bileşenler tespit "
                "edilebilir. Sunucu tarafında çalışan ve yanıtlara iz bırakmayan kütüphaneler bu yöntemle tespit "
                "edilemez. Bu nedenle blackbox sonuçlarında bir zafiyetin raporlanmamış olması, uygulamanın ilgili "
                "zafiyetten etkilenmediği anlamına gelmez. Tam envanter ve uyum gereksinimleri için whitebox veya "
                "hibrit analiz önerilir.",
                "Blackbox limitation: blackbox analysis can only identify externally observable components. "
                "Server-side libraries that leave no trace in responses cannot be detected this way. Therefore, the "
                "absence of a vulnerability in blackbox results does not mean the application is unaffected by it. "
                "For a complete inventory and compliance requirements, whitebox or hybrid analysis is recommended.")},
        ],
    },
    {
        "title": L("2. Genel Bilgiler ve Hizmet Seçimi", "2. General Information and Service Selection"),
        "blocks": [
            {"type": "para", "text": L(
                "Formu doldurma: Her madde için durumu işaretleyiniz. Zorunlu maddeler eksikse analiz başlatılamaz "
                "veya kapsam daraltılır. Koşullu maddeler, ilgili teknoloji/durum sizde mevcutsa zorunludur. "
                "Opsiyonel maddeler sonuçların kapsamını ve doğruluğunu artırır. Yalnızca seçtiğiniz hizmete ait "
                "bölümü doldurmanız yeterlidir (Whitebox: Bölüm 3, Blackbox: Bölüm 4, Hibrit: her ikisi). "
                "Bölüm 2, 5 ve 7 tüm hizmetler için doldurulmalıdır.",
                "How to fill in this form: mark the status of each item. If a Mandatory item is missing, the analysis "
                "cannot start or the scope will be reduced. Conditional items are mandatory when the related "
                "technology/situation applies to you. Optional items increase the coverage and accuracy of the "
                "results. Only the section for the selected service needs to be completed (Whitebox: Section 3, "
                "Blackbox: Section 4, Hybrid: both). Sections 2, 5 and 7 must be completed for all services.")},
            {"type": "sub", "title": L("2.1 İletişim Bilgileri", "2.1 Contact Information")},
            {"type": "fields", "rows": [
                L("Firma adı", "Company name"),
                L("Proje / uygulama adı", "Project / application name"),
                L("İrtibat kişisi (ad, unvan)", "Point of contact (name, title)"),
                L("E-posta / telefon", "E-mail / phone"),
                L("Teknik irtibat kişisi", "Technical contact"),
                L("Acil durum irtibatı (test sırasında)", "Emergency contact (during testing)"),
                L("Planlanan analiz tarihleri", "Planned analysis dates"),
            ]},
            {"type": "sub", "title": L("2.2 Hizmet ve Rapor Tercihleri", "2.2 Service and Report Preferences")},
            {"type": "items", "rows": [
                {"id": "GN-01", "level": "Z",
                 "text": L("Talep edilen hizmet türü", "Requested service type"),
                 "opts": [L("Whitebox", "Whitebox"), L("Blackbox", "Blackbox"), L("Hibrit", "Hybrid")]},
                {"id": "GN-02", "level": "Z",
                 "text": L("Rapor dili", "Report language"),
                 "opts": [L("Türkçe", "Turkish"), L("İngilizce", "English"), L("İkisi", "Both")]},
                {"id": "GN-03", "level": "O",
                 "text": L("SBOM formatı", "SBOM format"),
                 "hint": L("SBOM: yazılım bileşen envanterinin makine tarafından okunabilir listesi.",
                           "SBOM: machine-readable list of the software component inventory."),
                 "opts": [L("CycloneDX", "CycloneDX"), L("SPDX", "SPDX"), L("İkisi", "Both")]},
                {"id": "GN-04", "level": "O",
                 "text": L("Bulguların aktarılacağı ek format", "Additional findings export format"),
                 "hint": L("Kendi zafiyet yönetimi / takip sisteminize aktarım için.",
                           "For import into your own vulnerability management / tracking system."),
                 "opts": [L("Excel/CSV", "Excel/CSV"), L("JSON", "JSON"), L("Gerekmez", "Not needed")]},
            ]},
            {"type": "sub", "title": L("2.3 Kapsamdaki Uygulamalar", "2.3 Applications in Scope")},
            {"type": "para", "text": L(
                "Her uygulama/servis için: adı, türü (web, API, mobil, masaüstü, backend servisi), kullanılan ana "
                "teknolojiler ve kritiklik seviyesi.",
                "For each application/service: name, type (web, API, mobile, desktop, backend service), main "
                "technologies used and criticality level.")},
            {"type": "bigfield", "name": "GN-apps", "lines": 4},
        ],
    },
    {
        "title": L("3. Whitebox SCA — Talep Edilen Bilgi ve Dosyalar",
                   "3. Whitebox SCA — Requested Information and Files"),
        "blocks": [
            {"type": "sub", "title": L("3.1 Kaynak Kod ve Sürüm Bilgisi", "3.1 Source Code and Version")},
            {"type": "items", "rows": [
                {"id": "WB-01", "level": "Z",
                 "text": L("Kaynak kodun tamamı (repo salt-okunur erişimi veya .zip/.tar.gz arşivi)",
                           "Complete source code (read-only repository access or .zip/.tar.gz archive)")},
                {"id": "WB-02", "level": "Z",
                 "text": L("Canlı ortamda (production) çalışan sürümün commit hash / tag bilgisi",
                           "Commit hash / tag of the version running in production"),
                 "hint": L("Analiz, canlıdaki sürümle birebir aynı kod üzerinde yapılmalıdır. Varsayılan dal "
                           "(main/master) çoğu zaman canlıdaki sürümü yansıtmaz.",
                           "The analysis must be performed on exactly the code running in production. The default "
                           "branch (main/master) often does not reflect the production version.")},
                {"id": "WB-03", "level": "K",
                 "text": L("Monorepo ise kapsamdaki dizin / modül / servis listesi",
                           "If monorepo: list of in-scope directories / modules / services")},
                {"id": "WB-04", "level": "O",
                 "text": L("Git geçmişi (.git dizini dahil)", "Git history (including the .git directory)"),
                 "hint": L("Bağımlılıkların ne zaman eklendiğini/güncellendiğini görmek için. Gizlilik nedeniyle "
                           "istenmiyorsa hariç bırakılabilir.",
                           "To see when dependencies were added/updated. May be excluded for confidentiality reasons.")},
            ]},
            {"type": "sub", "title": L("3.2 Bağımlılık Dosyaları (Teknoloji Bazında)",
                                       "3.2 Dependency Files (per Technology)")},
            {"type": "para", "text": L(
                "Kullandığınız her teknoloji için manifest VE lock dosyasının tamamını (tüm modüller/alt projeler "
                "dahil) sağlayınız. Lock dosyası, dolaylı bağımlılıkların kesin sürümlerini içerir; yalnızca manifest "
                "ile yapılan analiz eksik ve hatalı sonuç verir. Lock dosyası kullanılmıyorsa, sağdaki komutun "
                "çıktısını canlıya çıkan sürümün build ortamında çalıştırarak iletiniz. Bu bölüm zorunludur: "
                "kullandığınız her teknoloji için bir seçim yapınız.",
                "For every technology in use, provide the complete manifest AND lock file (including all modules / "
                "sub-projects). The lock file contains the exact versions of transitive dependencies; an analysis based "
                "on the manifest alone is incomplete and inaccurate. If no lock file is used, run the command on the "
                "right in the build environment of the production release and send its output. This section is "
                "mandatory: make a selection for each technology you use.")},
            {"type": "eco", "rows": [
                ("JavaScript / TypeScript\n(npm, yarn, pnpm)", "package.json",
                 "package-lock.json, npm-shrinkwrap.json,\nyarn.lock, pnpm-lock.yaml", "npm ls --all --json"),
                ("Python", "requirements*.txt, pyproject.toml,\nPipfile, setup.py / setup.cfg",
                 "poetry.lock, Pipfile.lock, uv.lock, pdm.lock", "pip freeze\n(L:çalışan ortamda|in the running environment)"),
                ("Java — Maven", "pom.xml (L:tüm modüller|all modules)", "—",
                 "mvn dependency:tree\n-DoutputType=text"),
                ("Java / Kotlin — Gradle\n(L:Android dahil|incl. Android)",
                 "build.gradle(.kts), settings.gradle(.kts),\ngradle/libs.versions.toml",
                 "gradle.lockfile", "./gradlew dependencies\n(L:her modül için|per module)"),
                (".NET / C#", "*.csproj, Directory.Packages.props,\npackages.config",
                 "packages.lock.json,\nobj/project.assets.json", "dotnet list package\n--include-transitive"),
                ("PHP", "composer.json", "composer.lock", "composer show --tree"),
                ("Go", "go.mod", "go.sum", "go list -m all"),
                ("Ruby", "Gemfile", "Gemfile.lock", "bundle list"),
                ("Rust", "Cargo.toml", "Cargo.lock", "cargo tree"),
                ("Dart / Flutter", "pubspec.yaml", "pubspec.lock", "flutter pub deps"),
                ("iOS — Swift / Obj-C", "Podfile, Package.swift, Cartfile",
                 "Podfile.lock, Package.resolved,\nCartfile.resolved",
                 "L:Kullanılan kütüphane ve sürüm listesi|List of libraries and versions used"),
                ("C / C++", "conanfile.txt/.py, vcpkg.json,\nCMakeLists.txt", "conan.lock",
                 "L:Kullanılan kütüphane ve sürüm listesi|List of libraries and versions used"),
            ]},
            {"type": "items", "rows": [
                {"id": "WB-05", "level": "K",
                 "text": L("Yukarıda listelenmeyen diğer teknolojiler ve bağımlılık dosyaları",
                           "Other technologies and dependency files not listed above"),
                 "field": True},
            ]},
            {"type": "sub", "title": L("3.3 Derlenmiş Çıktılar ve Çalışan Artefaktlar",
                                       "3.3 Build Outputs and Deployed Artefacts")},
            {"type": "items", "rows": [
                {"id": "WB-10", "level": "K",
                 "text": L("Container imajları: imaj adı:etiket ve digest (sha256) listesi; registry salt-okunur "
                           "erişimi veya 'docker save' çıktısı",
                           "Container images: list of image name:tag and digest (sha256); read-only registry access "
                           "or 'docker save' output"),
                 "hint": L("İşletim sistemi paketleri ve imaj içindeki tüm bileşenler bu yolla analiz edilir.",
                           "OS packages and all components inside the image are analysed this way.")},
                {"id": "WB-11", "level": "O",
                 "text": L("Canlıya dağıtılan paketler: JAR/WAR/EAR, DLL/EXE, wheel, binary vb.",
                           "Packages deployed to production: JAR/WAR/EAR, DLL/EXE, wheel, binaries, etc."),
                 "hint": L("Kaynak kod ile canlıdaki çıktının eşleştiğini doğrulamak ve paketlenmiş bileşenleri "
                           "tespit etmek için.",
                           "To verify that the source code matches the production build and to detect bundled components.")},
                {"id": "WB-12", "level": "K",
                 "text": L("Mobil uygulama build dosyaları (canlıdaki sürüm): APK/AAB, IPA",
                           "Mobile application builds (production version): APK/AAB, IPA")},
            ]},
            {"type": "sub", "title": L("3.4 Build ve Dağıtım Ortamı", "3.4 Build and Deployment Environment")},
            {"type": "items", "rows": [
                {"id": "WB-20", "level": "K",
                 "text": L("Dockerfile ve docker-compose dosyaları", "Dockerfiles and docker-compose files")},
                {"id": "WB-21", "level": "K",
                 "text": L("Kubernetes manifestleri / Helm chart ve values dosyaları (sidecar ve init container dahil)",
                           "Kubernetes manifests / Helm charts and values files (including sidecar and init containers)")},
                {"id": "WB-22", "level": "O",
                 "text": L("CI/CD pipeline tanımları (Jenkinsfile, .gitlab-ci.yml, GitHub Actions, Azure Pipelines vb.)",
                           "CI/CD pipeline definitions (Jenkinsfile, .gitlab-ci.yml, GitHub Actions, Azure Pipelines, etc.)"),
                 "hint": L("Build sırasında indirilen ek paket/araçları ve üçüncü taraf pipeline eklentilerini tespit "
                           "etmek için.",
                           "To identify additional packages/tools downloaded at build time and third-party pipeline plugins.")},
                {"id": "WB-23", "level": "K",
                 "text": L("Runtime ve sunucu bilgisi: JDK / Node.js / Python / .NET sürümleri, işletim sistemi, "
                           "uygulama/web sunucusu (Tomcat, IIS, nginx, JBoss vb.) sürümleri",
                           "Runtime and server information: JDK / Node.js / Python / .NET versions, operating system, "
                           "application/web server (Tomcat, IIS, nginx, JBoss, etc.) versions"),
                 "hint": L("Container imajı (WB-10) sağlanmıyorsa zorunludur.",
                           "Mandatory if container images (WB-10) are not provided.")},
            ]},
            {"type": "sub", "title": L("3.5 Kurum İçi ve Üçüncü Taraf Bileşenler",
                                       "3.5 Internal and Third-Party Components")},
            {"type": "items", "rows": [
                {"id": "WB-30", "level": "O",
                 "text": L("Kurum içi paket deposu bilgisi (Nexus, Artifactory, Azure Artifacts, private npm/PyPI vb.) "
                           "ve salt-okunur erişim",
                           "Internal package repository details (Nexus, Artifactory, Azure Artifacts, private npm/PyPI, "
                           "etc.) and read-only access")},
                {"id": "WB-31", "level": "O",
                 "text": L("Kurum içinde geliştirilen paketlerin isim listesi (scope / namespace / groupId dahil)",
                           "List of internally developed package names (including scope / namespace / groupId)"),
                 "hint": L("Bağımlılık karışıklığı (dependency confusion) riskinin analizi için.",
                           "For dependency confusion risk analysis.")},
                {"id": "WB-32", "level": "K",
                 "text": L("Kaynak koda gömülü (vendored) üçüncü taraf kütüphaneler: /lib, /vendor, /third_party "
                           "dizinleri, kopyalanmış JAR/DLL/JS dosyaları ve bilinen sürümleri",
                           "Third-party libraries embedded (vendored) in the source: /lib, /vendor, /third_party "
                           "directories, copied JAR/DLL/JS files and their known versions")},
                {"id": "WB-33", "level": "K",
                 "text": L("Ticari / lisanslı üçüncü taraf SDK ve bileşenler (ödeme, harita, analitik, raporlama vb.) "
                           "ve sürümleri",
                           "Commercial / licensed third-party SDKs and components (payment, maps, analytics, "
                           "reporting, etc.) and their versions")},
            ]},
            {"type": "sub", "title": L("3.6 Politika ve Kapsam Tercihleri", "3.6 Policy and Scope Preferences")},
            {"type": "items", "rows": [
                {"id": "WB-40", "level": "O",
                 "text": L("Lisans politikası: izin verilen / yasaklanan lisans listesi",
                           "License policy: list of allowed / prohibited licenses"),
                 "hint": L("Belirtilmezse güçlü copyleft lisanslar (GPL, AGPL vb.) risk olarak raporlanır.",
                           "If not specified, strong copyleft licenses (GPL, AGPL, etc.) are reported as risks.")},
                {"id": "WB-41", "level": "Z",
                 "text": L("Geliştirme / test bağımlılıkları (devDependencies, test scope) kapsama dahil edilsin mi?",
                           "Should development / test dependencies (devDependencies, test scope) be included?"),
                 "opts": "eh"},
                {"id": "WB-42", "level": "O",
                 "text": L("Kapsam dışı tutulacak dizin / modül listesi", "Directories / modules to exclude"),
                 "field": True},
                {"id": "WB-43", "level": "O",
                 "text": L("Önceki SCA / SBOM raporları ve kabul edilmiş riskler listesi",
                           "Previous SCA / SBOM reports and list of accepted risks"),
                 "hint": L("Önceden kabul edilmiş bulguların ayrıştırılması ve karşılaştırmalı raporlama için.",
                           "To separate previously accepted findings and enable comparative reporting.")},
            ]},
            {"type": "sub", "title": L("3.7 Dosya Teslim Yöntemi", "3.7 File Delivery Method")},
            {"type": "items", "rows": [
                {"id": "WB-50", "level": "Z",
                 "text": L("Tercih edilen teslim yöntemi", "Preferred delivery method"),
                 "hint": L("Şifreli arşiv: AES-256 ile şifrelenmiş arşiv; parola farklı bir kanaldan (SMS/telefon) "
                           "iletilir. Salt-okunur erişim: repo/registry hesabı. Yerinde: sizin ortamınızda "
                           "(ofis/VDI) analiz.",
                           "Encrypted archive: AES-256 encrypted archive; password sent over a separate channel "
                           "(SMS/phone). Read-only access: repository/registry account. On-site: analysis inside your "
                           "environment (office/VDI)."),
                 "opts": [L("Şifreli arşiv", "Encrypted archive"), L("Salt-okunur erişim", "Read-only access"),
                          L("Yerinde / VDI", "On-site / VDI")]},
            ]},
        ],
    },
    {
        "title": L("4. Blackbox SCA — Talep Edilen Bilgiler", "4. Blackbox SCA — Requested Information"),
        "blocks": [
            {"type": "para", "text": L(
                "Blackbox analizde tarafımıza dosya sağlanmaz. Analizin yasal ve güvenli şekilde yürütülebilmesi "
                "için hedeflerin, yetkilendirmenin ve test sınırlarının net olarak belirlenmesi gerekir.",
                "No files are provided for blackbox analysis. For the analysis to be carried out lawfully and safely, "
                "targets, authorization and test boundaries must be clearly defined.")},
            {"type": "sub", "title": L("4.1 Hedefler", "4.1 Targets")},
            {"type": "items", "rows": [
                {"id": "BB-01", "level": "K",
                 "text": L("Web uygulamaları: URL / alan adı / alt alan adı listesi",
                           "Web applications: list of URLs / domains / subdomains"),
                 "field": True, "lines": 3},
                {"id": "BB-02", "level": "K",
                 "text": L("API'ler: base URL listesi", "APIs: list of base URLs"),
                 "hint": L("Varsa API dokümantasyonu (Swagger/OpenAPI, Postman koleksiyonu) kapsamı artırır.",
                           "API documentation (Swagger/OpenAPI, Postman collection), if available, increases coverage."),
                 "field": True, "lines": 3},
                {"id": "BB-03", "level": "K",
                 "text": L("Mobil uygulamalar: mağaza linki veya paket adı (Android package name / iOS bundle ID)",
                           "Mobile applications: store link or package name (Android package name / iOS bundle ID)"),
                 "field": True, "lines": 3},
                {"id": "BB-04", "level": "O",
                 "text": L("Altyapı: IP adresi / aralığı (sunucu ve servis bileşen sürümlerinin tespiti için)",
                           "Infrastructure: IP addresses / ranges (to identify server and service component versions)"),
                 "field": True, "lines": 3},
                {"id": "BB-05", "level": "Z",
                 "text": L("Kapsam dışı tutulacak hedef / yol / uç nokta listesi",
                           "Targets / paths / endpoints to exclude from scope"),
                 "hint": L("Yoksa 'Yok' yazınız.", "Write 'None' if not applicable."),
                 "field": True},
            ]},
            {"type": "sub", "title": L("4.2 Yetkilendirme ve Koordinasyon", "4.2 Authorization and Coordination")},
            {"type": "items", "rows": [
                {"id": "BB-10", "level": "Z",
                 "text": L("İmzalı yazılı test izni ve kapsam onayı", "Signed written test authorization and scope approval"),
                 "hint": L("Yetkilendirme olmadan hiçbir hedefe test yapılmaz.",
                           "No target is tested without authorization.")},
                {"id": "BB-11", "level": "K",
                 "text": L("Hedefler üçüncü taraf / bulut sağlayıcıda barınıyorsa (AWS, Azure, GCP, CDN, hosting "
                           "firması vb.) sağlayıcı bilgisi ve gerekiyorsa sağlayıcı onayı",
                           "If targets are hosted by a third party / cloud provider (AWS, Azure, GCP, CDN, hosting "
                           "company, etc.): provider details and, where required, provider approval")},
                {"id": "BB-12", "level": "O",
                 "text": L("Test kaynak IP adreslerimiz için WAF / IPS koordinasyonu",
                           "WAF / IPS coordination for our source IP addresses"),
                 "hint": L("WAF/IPS engellemesi, tespitlerin eksik kalmasına neden olabilir.",
                           "WAF/IPS blocking may cause detections to be incomplete."),
                 "opts": [L("Beyaz liste", "Whitelist"), L("SOC bilgilendirme", "Notify SOC"),
                          L("Gerekmez", "Not needed")]},
                {"id": "BB-13", "level": "Z",
                 "text": L("İzin verilen test zaman aralığı (gün / saat)", "Permitted testing window (days / hours)"),
                 "field": True},
                {"id": "BB-14", "level": "Z",
                 "text": L("Test edilecek ortam", "Environment to be tested"),
                 "hint": L("Aktif doğrulama (BB-20) seçilecekse test/staging ortamı önerilir. Test ortamının canlı "
                           "ortamla aynı sürümde olduğunu belirtiniz.",
                           "A test/staging environment is recommended if active verification (BB-20) is selected. "
                           "Please confirm that it runs the same version as production."),
                 "opts": [L("Canlı (prod)", "Production"), L("Test / staging", "Test / staging"),
                          L("İkisi", "Both")]},
            ]},
            {"type": "sub", "title": L("4.3 Test Derinliği", "4.3 Testing Depth")},
            {"type": "items", "rows": [
                {"id": "BB-20", "level": "Z",
                 "text": L("Analiz seviyesi", "Analysis level"),
                 "hint": L("Pasif: yalnızca normal kullanıcı trafiği düzeyinde gözlem (sayfalar, JavaScript dosyaları, "
                           "HTTP başlıkları, mobil paket analizi). Aktif doğrulama: tespit edilen kritik zafiyetlerin "
                           "hedef sistemde zarar vermeyen yöntemlerle doğrulanması. Hizmet kesintisine (DoS) yol "
                           "açabilecek testler hiçbir koşulda yapılmaz.",
                           "Passive: observation at normal user-traffic level only (pages, JavaScript files, HTTP "
                           "headers, mobile package analysis). Active verification: confirming detected critical "
                           "vulnerabilities on the target using non-destructive methods. Tests that could cause "
                           "service disruption (DoS) are never performed."),
                 "opts": [L("Pasif", "Passive"), L("Pasif + aktif", "Passive + active")]},
                {"id": "BB-21", "level": "O",
                 "text": L("Port / servis taraması izni (altyapı bileşen sürümlerinin tespiti için)",
                           "Port / service scanning permission (to identify infrastructure component versions)"),
                 "opts": "eh"},
                {"id": "BB-22", "level": "O",
                 "text": L("İstek hızı sınırı (varsa saniyedeki azami istek sayısı)",
                           "Request rate limit (maximum requests per second, if any)"),
                 "field": True},
            ]},
            {"type": "sub", "title": L("4.4 Kapsamı Artıran Opsiyonel Bilgiler", "4.4 Optional Information that Increases Coverage")},
            {"type": "items", "rows": [
                {"id": "BB-30", "level": "O",
                 "text": L("Test kullanıcı hesabı (giriş sonrası sayfalarda yüklenen bileşenlerin tespiti için)",
                           "Test user account (to identify components loaded on post-login pages)"),
                 "hint": L("Hesap sağlanmazsa analiz yalnızca giriş gerektirmeyen yüzeyle sınırlıdır.",
                           "Without an account, the analysis is limited to the unauthenticated surface.")},
                {"id": "BB-31", "level": "K",
                 "text": L("Mobil uygulama dosyası (APK/IPA) — uygulama mağazada yayımlanmıyorsa veya kurum içi "
                           "dağıtılıyorsa",
                           "Mobile application file (APK/IPA) — if the app is not published in a store or is "
                           "distributed internally")},
            ]},
        ],
    },
    {
        "title": L("5. Gizlilik ve Veri Yönetimi", "5. Confidentiality and Data Handling"),
        "blocks": [
            {"type": "para", "text": L(
                "Sağlanan kaynak kod ve dosyalar yalnızca bu analiz amacıyla kullanılır, şifreli olarak saklanır ve "
                "üçüncü taraf çevrimiçi tarama servislerine yüklenmez.",
                "Source code and files provided are used solely for this analysis, stored encrypted, and are not "
                "uploaded to third-party online scanning services.")},
            {"type": "items", "rows": [
                {"id": "GZ-01", "level": "Z",
                 "text": L("Gizlilik sözleşmesi (NDA) imzalandı", "Non-disclosure agreement (NDA) signed")},
                {"id": "GZ-02", "level": "O",
                 "text": L("Analiz sonrası veri imhası ve imha tutanağı talep ediliyor",
                           "Data destruction and a destruction certificate are requested after the analysis"),
                 "opts": "eh"},
                {"id": "GZ-03", "level": "O",
                 "text": L("Verilerin belirli bir lokasyonda / yurt içinde işlenmesi şartı var (KVKK, BDDK vb.)",
                           "Data must be processed in a specific location / in-country (KVKK, BDDK, etc.)"),
                 "opts": "eh"},
            ]},
        ],
    },
    {
        "title": L("6. Teslim Edilecek Çıktılar", "6. Deliverables"),
        "blocks": [
            {"type": "bullets", "items": [
                L("Yönetici özeti: genel risk durumu ve öncelikli aksiyonlar.",
                  "Executive summary: overall risk posture and priority actions."),
                L("Bileşen envanteri (SBOM): CycloneDX ve/veya SPDX formatında.",
                  "Component inventory (SBOM): in CycloneDX and/or SPDX format."),
                L("Önceliklendirilmiş zafiyet listesi: CVE/GHSA kimliği, CVSS puanı, istismar olasılığı (EPSS), "
                  "aktif istismar bilgisi (CISA KEV), etkilenen bileşen ve bağımlılık yolu.",
                  "Prioritized vulnerability list: CVE/GHSA ID, CVSS score, exploit probability (EPSS), known "
                  "exploitation status (CISA KEV), affected component and dependency path."),
                L("Düzeltme önerileri: güvenli sürüm ve yükseltme yolu.",
                  "Remediation guidance: fixed version and upgrade path."),
                L("Lisans uyum raporu (whitebox).", "License compliance report (whitebox)."),
                L("Tedarik zinciri bulguları: zararlı veya bakımı bırakılmış paketler, bağımlılık karışıklığı "
                  "(dependency confusion) riski.",
                  "Supply-chain findings: malicious or abandoned packages, dependency confusion risk."),
                L("Blackbox tespitleri için kanıt: bileşenin tespit edildiği konum, kanıt ve güven seviyesi.",
                  "Evidence for blackbox detections: location where the component was detected, evidence and "
                  "confidence level."),
            ]},
        ],
    },
    {
        "title": L("7. Onay", "7. Approval"),
        "blocks": [
            {"type": "para", "text": L(
                "Bu formda verilen bilgilerin doğru olduğunu ve belirtilen kapsamda analiz yapılmasını onaylıyoruz.",
                "We confirm that the information provided in this form is accurate and approve the analysis within "
                "the stated scope.")},
            {"type": "fields", "rows": [
                L("Ad soyad", "Full name"),
                L("Unvan", "Title"),
                L("Tarih", "Date"),
                {"label": L("İmza / kaşe", "Signature / stamp"), "tall": True},
            ]},
        ],
    },
]
