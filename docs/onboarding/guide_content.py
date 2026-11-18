from content import L, VERSION

TITLE = L("Yazılım Bileşen Analizi (SCA) Hizmeti", "Software Composition Analysis (SCA) Service")
SUBTITLE = L("Veri Hazırlama ve Teslim Kılavuzu", "Data Preparation and Delivery Guide")


def H(t):
    return {"type": "sub", "title": t}


def P(t):
    return {"type": "para", "text": t}


def C(code):
    return {"type": "code", "code": code}


def B(*items):
    return {"type": "bullets", "items": list(items)}


def N(t):
    return {"type": "note", "text": t}


def T(header, rows, widths):
    return {"type": "table", "header": header, "rows": rows, "widths": widths}


SECTIONS = [
    {"title": L("1. Bu Kılavuz Hakkında", "1. About This Guide"), "blocks": [
        P(L("Bu kılavuz, \"SCA Hizmeti – Ön Gereksinimler ve Bilgi Toplama Formu\"nda talep edilen her bilgi ve "
            "dosyanın nasıl hazırlanacağını ve tarafımıza nasıl teslim edileceğini adım adım açıklar. Başlıklardaki "
            "madde kodları (ör. **WB-01**, **BB-10**) formdaki maddelerle birebir aynıdır; yalnızca formda "
            "işaretlediğiniz maddelerin bölümlerini uygulamanız yeterlidir.",
            "This guide explains, step by step, how to prepare each piece of information and each file requested "
            "in the \"SCA Service – Prerequisites and Information Request Form\" and how to deliver it to us. The "
            "item codes in the headings (e.g. **WB-01**, **BB-10**) match the items in the form exactly; you only "
            "need to follow the sections for the items you marked in the form.")),
        P(L("Komutlar Linux/macOS (bash) için verilmiştir; Windows için farklılık gösterenler ayrıca belirtilmiştir. "
            "`<...>` ile gösterilen alanları kendi değerlerinizle değiştiriniz. Komutlar yalnızca okuma/listeleme "
            "yapar; sistemlerinizde değişiklik yapmaz.",
            "Commands are given for Linux/macOS (bash); Windows variants are noted where they differ. Replace "
            "fields shown as `<...>` with your own values. The commands only read/list information; they do not "
            "change your systems.")),
        N(L("Önemli: Bilgileri canlı ortamda (production) çalışan sürümden alınız. Geliştirme dalından veya "
            "geliştirici bilgisayarından alınan bilgiler canlıdaki durumu yansıtmayabilir ve analiz sonucunu "
            "geçersiz kılabilir.",
            "Important: collect the information from the version running in production. Information taken from a "
            "development branch or a developer's workstation may not reflect production and can invalidate the "
            "analysis result.")),
    ]},
    {"title": L("2. Paketleme, Şifreleme ve Teslim", "2. Packaging, Encryption and Delivery"), "blocks": [
        H(L("2.1 Klasör yapısı", "2.1 Folder structure")),
        P(L("Tüm dosyaları aşağıdaki yapıda tek bir klasörde toplayınız. Kullanılmayan klasörleri boş "
            "bırakabilir veya silebilirsiniz.",
            "Collect all files in a single folder using the structure below. Unused folders may be left empty "
            "or removed.")),
        C("SCA_<Firma>_<YYYY-AA-GG>/\n"
          "  00_BILGI.txt                 # L:commit hash, uygulama listesi, notlar|commit hash, application list, notes\n"
          "  01_kaynak_kod/               # WB-01..WB-04\n"
          "  02_bagimlilik_ciktilari/     # 3.2, WB-05\n"
          "  03_container/                # WB-10\n"
          "  04_artefaktlar/              # WB-11, WB-12\n"
          "  05_build_deploy/             # WB-20..WB-23\n"
          "  06_ucuncu_taraf/             # WB-30..WB-33\n"
          "  07_politika/                 # WB-40..WB-43"),
        H(L("2.2 Dahil edilmemesi gerekenler", "2.2 What not to include")),
        B(L("`.env`, sertifika/anahtar dosyaları (`*.pem`, `*.key`, `*.pfx`, `*.jks`), parola içeren yapılandırma "
            "dosyaları. SCA analizi bunlara ihtiyaç duymaz.",
            "`.env`, certificate/key files (`*.pem`, `*.key`, `*.pfx`, `*.jks`), configuration files containing "
            "passwords. SCA analysis does not need them."),
          L("`node_modules/`, `target/`, `bin/`, `obj/`, `build/` gibi derleme/kurulum dizinleri (lock dosyası "
            "sağlandığında gereksizdir; WB-11 kapsamında istenen artefaktlar hariç).",
            "Build/install directories such as `node_modules/`, `target/`, `bin/`, `obj/`, `build/` (unnecessary "
            "when lock files are provided; except artefacts requested under WB-11)."),
          L("Gerçek müşteri verisi, veritabanı yedekleri, log dosyaları.",
            "Real customer data, database backups, log files."),
          L("Kubernetes `Secret` nesneleri ve CI/CD değişkenlerindeki parolalar.",
            "Kubernetes `Secret` objects and passwords stored in CI/CD variables.")),
        H(L("2.3 Bütünlük listesi (SHA-256)", "2.3 Integrity list (SHA-256)")),
        P(L("Klasörün içindeyken tüm dosyaların SHA-256 özetini çıkarınız:",
            "From inside the folder, generate SHA-256 hashes of all files:")),
        C("# Linux / macOS\n"
          "find . -type f ! -name SHA256SUMS.txt -exec sha256sum {} + > SHA256SUMS.txt\n"
          "\n"
          "# Windows (PowerShell)\n"
          "Get-ChildItem -Recurse -File | Get-FileHash -Algorithm SHA256 |\n"
          "  Select-Object Hash, Path | Export-Csv ..\\SHA256SUMS.csv -NoTypeInformation"),
        H(L("2.4 Şifreli arşiv (WB-50: Şifreli arşiv)", "2.4 Encrypted archive (WB-50: Encrypted archive)")),
        P(L("Arşivi 7-Zip ile **AES-256** ve **dosya adı şifreleme** açık olarak oluşturunuz. Parola en az 16 "
            "karakter olmalı ve arşivden **farklı bir kanaldan** (SMS veya telefon) iletilmelidir; e-posta ile "
            "gönderilmemelidir.",
            "Create the archive with 7-Zip using **AES-256** with **file name encryption** enabled. The password "
            "must be at least 16 characters and sent over a **different channel** (SMS or phone) than the archive; "
            "it must not be sent by e-mail.")),
        C("# Linux / macOS (p7zip / 7zz) — L:parola sorulur|you will be prompted for the password\n"
          "7z a -t7z -mhe=on -p SCA_<Firma>_<YYYY-AA-GG>.7z SCA_<Firma>_<YYYY-AA-GG>/\n"
          "\n"
          "# L:2 GB'lık parçalara bölmek için|To split into 2 GB volumes\n"
          "7z a -t7z -mhe=on -p -v2g SCA_<Firma>_<YYYY-AA-GG>.7z SCA_<Firma>_<YYYY-AA-GG>/\n"
          "\n"
          "# L:Arşivin özeti (bu değeri parolayla birlikte iletiniz)|Hash of the archive (send it together with the password)\n"
          "sha256sum SCA_<Firma>_<YYYY-AA-GG>.7z"),
        P(L("Windows (grafik arayüz): klasöre sağ tıklayın → **7-Zip → Arşive ekle** → Arşiv biçimi: **7z**, "
            "Şifreleme yöntemi: **AES-256**, **Dosya adlarını şifrele** kutusunu işaretleyin, parolayı girin. "
            "Windows özeti: `Get-FileHash .\\SCA_<Firma>_<YYYY-AA-GG>.7z -Algorithm SHA256`.",
            "Windows (GUI): right-click the folder → **7-Zip → Add to archive** → Archive format: **7z**, "
            "Encryption method: **AES-256**, tick **Encrypt file names**, enter the password. Windows hash: "
            "`Get-FileHash .\\SCA_<Company>_<YYYY-MM-DD>.7z -Algorithm SHA256`.")),
        P(L("Arşivi tarafımızca iletilecek güvenli dosya paylaşım bağlantısına yükleyiniz.",
            "Upload the archive to the secure file-sharing link we will provide.")),
        H(L("2.5 Salt-okunur erişim (WB-50: Salt-okunur erişim)", "2.5 Read-only access (WB-50: Read-only access)")),
        P(L("Erişimi analize özel, süreli bir hesap veya token ile veriniz; analiz bitiminde iptal ediniz. "
            "Önerilen en düşük yetkiler:",
            "Grant access through a dedicated, time-limited account or token for the analysis and revoke it when "
            "the analysis ends. Recommended minimum permissions:")),
        T([L("Platform", "Platform"), L("Önerilen yetki", "Recommended permission")], [
            ["GitHub", L("Depoya **Read** rolüyle ekleme veya yalnızca *Contents: Read-only* izinli fine-grained token",
                         "Add to the repository with the **Read** role, or a fine-grained token with *Contents: Read-only* only")],
            ["GitLab", L("Projede **Reporter** rolü veya `read_repository` kapsamlı proje erişim tokenı",
                         "**Reporter** role on the project, or a project access token with `read_repository` scope")],
            ["Azure DevOps", L("Projede **Readers** grubu veya *Code (Read)* kapsamlı PAT",
                               "**Readers** group on the project, or a PAT with *Code (Read)* scope")],
            ["Bitbucket", L("Depoda **Read** yetkisi veya yalnızca okuma izinli erişim tokenı",
                            "**Read** permission on the repository, or an access token with read-only permission")],
            [L("Container registry", "Container registry"),
             L("Yalnızca *pull* yetkili hesap: Harbor robot hesabı, AWS ECR `AmazonEC2ContainerRegistryReadOnly`, "
               "Azure ACR `AcrPull`, GCP Artifact Registry `roles/artifactregistry.reader`",
               "Pull-only account: Harbor robot account, AWS ECR `AmazonEC2ContainerRegistryReadOnly`, "
               "Azure ACR `AcrPull`, GCP Artifact Registry `roles/artifactregistry.reader`")],
        ], [32, 148]),
        H(L("2.6 Yerinde / VDI analiz (WB-50: Yerinde / VDI)", "2.6 On-site / VDI analysis (WB-50: On-site / VDI)")),
        P(L("Analiz ortamınızda yapılacaksa, analiz başlamadan önce şunları hazırlayınız: kaynak koda ve "
            "dosyalara erişimi olan bir makine/VDI; Python 3.10 veya üzeri; tarafımızca sağlanacak analiz "
            "aracının ve çevrimdışı zafiyet veritabanının kurulabilmesi için dosya aktarım izni. Ortamda internet "
            "erişimi gerekmez.",
            "If the analysis is to be performed in your environment, prepare the following before it starts: a "
            "machine/VDI with access to the source code and files; Python 3.10 or later; permission to transfer "
            "files so that our analysis tool and the offline vulnerability database can be installed. No internet "
            "access is required in the environment.")),
    ]},
    {"title": L("3. Whitebox — Kaynak Kod ve Sürüm (WB-01 – WB-04)",
                "3. Whitebox — Source Code and Version (WB-01 – WB-04)"), "blocks": [
        H(L("WB-01 · Kaynak kodun tamamı", "WB-01 · Complete source code")),
        P(L("Canlıdaki commit'ten arşiv oluşturunuz (`<commit>` yerine WB-02'deki değeri yazınız):",
            "Create an archive from the production commit (replace `<commit>` with the value from WB-02):")),
        C("git archive --format=tar.gz -o 01_kaynak_kod/kaynak_kod.tar.gz <commit>"),
        P(L("`git archive` **submodule** içeriğini ve **Git LFS** dosyalarını içermez. Bunlardan birini "
            "kullanıyorsanız aşağıdaki yöntemi kullanınız:",
            "`git archive` does not include **submodule** contents or **Git LFS** files. If you use either, use "
            "the method below instead:")),
        C("git clone --recurse-submodules <repo-url> src\n"
          "cd src\n"
          "git checkout <commit>\n"
          "git submodule update --init --recursive\n"
          "git lfs pull                       # L:yalnızca Git LFS kullanılıyorsa|only if Git LFS is used\n"
          "cd ..\n"
          "tar --exclude=.git -czf 01_kaynak_kod/kaynak_kod.tar.gz src"),
        P(L("Birden fazla depo varsa her biri için ayrı arşiv oluşturunuz ve `00_BILGI.txt` dosyasında depo adı – "
            "commit eşleşmesini belirtiniz.",
            "If there are multiple repositories, create a separate archive for each and list the repository name – "
            "commit mapping in `00_BILGI.txt`.")),
        H(L("WB-02 · Canlıdaki sürümün commit hash / tag bilgisi", "WB-02 · Commit hash / tag of the production version")),
        P(L("Aşağıdaki yöntemlerden biriyle belirleyiniz ve `00_BILGI.txt` dosyasına yazınız:",
            "Determine it using one of the methods below and write it into `00_BILGI.txt`:")),
        B(L("CI/CD sisteminizde canlıya yapılan son başarılı dağıtımın (deployment) kaydındaki commit.",
            "The commit recorded in the last successful production deployment in your CI/CD system."),
          L("Canlıya çıkılan sürüm etiketi (tag) biliniyorsa: `git rev-list -n 1 <tag>`",
            "If the released tag is known: `git rev-list -n 1 <tag>`"),
          L("Container imajında OCI etiketi tanımlıysa: "
            "`docker inspect --format '{{ index .Config.Labels \"org.opencontainers.image.revision\" }}' <imaj>`",
            "If the container image has the OCI label: "
            "`docker inspect --format '{{ index .Config.Labels \"org.opencontainers.image.revision\" }}' <image>`")),
        H(L("WB-03 · Monorepo kapsam listesi", "WB-03 · Monorepo scope list")),
        P(L("`00_BILGI.txt` içinde kapsamdaki her dizini depo köküne göre göreli yol olarak, satır başına bir "
            "tane yazınız (ör. `services/payment-api`).",
            "In `00_BILGI.txt`, list each in-scope directory as a path relative to the repository root, one per line "
            "(e.g. `services/payment-api`).")),
        H(L("WB-04 · Git geçmişi", "WB-04 · Git history")),
        P(L("Tüm geçmişi tek dosyada iletmek için `git bundle` kullanınız:",
            "Use `git bundle` to deliver the full history in a single file:")),
        C("git bundle create 01_kaynak_kod/repo.bundle --all\n"
          "git bundle verify 01_kaynak_kod/repo.bundle      # L:kontrol|verify"),
    ]},
    {"title": L("4. Whitebox — Bağımlılık Dosyaları (Bölüm 3.2, WB-05)",
                "4. Whitebox — Dependency Files (Section 3.2, WB-05)"), "blocks": [
        P(L("Lock dosyaları depoda commit'liyse ve kaynak kodu (WB-01) sağladıysanız **ek işlem gerekmez**; "
            "formda \"Manifest + lock\" seçeneğini işaretleyiniz. Lock dosyası depoda yoksa (ör. `.gitignore` "
            "ile dışlanmışsa) veya hiç kullanılmıyorsa, ilgili teknolojinin komutunu **canlıya çıkan sürümün "
            "build ortamında** (CI ajanı veya build container'ı) çalıştırarak çıktıyı `02_bagimlilik_ciktilari/` "
            "klasörüne koyunuz ve formda \"Komut çıktısı\" seçeneğini işaretleyiniz.",
            "If lock files are committed to the repository and you provided the source code (WB-01), **no further "
            "action is needed**; select \"Manifest + lock\" in the form. If a lock file is not in the repository "
            "(e.g. excluded via `.gitignore`) or not used at all, run the relevant command **in the build "
            "environment of the production release** (CI agent or build container), put the output into "
            "`02_bagimlilik_ciktilari/` and select \"Command output\" in the form.")),
        N(L("Uyarı: Lock dosyası yokken `npm install`, `pip install` gibi komutlarla bugün yeniden kurulum yapıp "
            "çıktı almayınız. Bu, canlıdakinden farklı (daha yeni) sürümleri çözer ve analiz canlı ortamı "
            "yansıtmaz. Çıktıyı canlıya çıkan build'in ortamından veya çalışan sistemin kendisinden alınız.",
            "Warning: when no lock file exists, do not perform a fresh install today with commands like "
            "`npm install` or `pip install` and take output from that. It resolves different (newer) versions than "
            "production and the analysis will not reflect production. Take the output from the environment of the "
            "build that was released, or from the running system itself.")),
        H(L("Mevcut bağımlılık dosyalarını bulma", "Finding existing dependency files")),
        C("find . \\( -name node_modules -o -name .git \\) -prune -o -type f \\( \\\n"
          "  -name 'package*.json' -o -name '*.lock' -o -name 'pnpm-lock.yaml' \\\n"
          "  -o -name 'requirements*.txt' -o -name 'pyproject.toml' -o -name 'Pipfile' \\\n"
          "  -o -name 'pom.xml' -o -name '*.gradle' -o -name '*.gradle.kts' \\\n"
          "  -o -name 'gradle.lockfile' -o -name 'libs.versions.toml' \\\n"
          "  -o -name '*.csproj' -o -name 'packages.config' -o -name 'Directory.Packages.props' \\\n"
          "  -o -name 'composer.json' -o -name 'go.mod' -o -name 'go.sum' -o -name 'Gemfile' \\\n"
          "  -o -name 'Cargo.toml' -o -name 'pubspec.yaml' -o -name 'Podfile' \\\n"
          "  -o -name 'Package.swift' -o -name 'Package.resolved' -o -name 'Cartfile*' \\\n"
          "  -o -name 'conanfile.*' -o -name 'vcpkg.json' \\) -print > 00_bagimlilik_dosyalari.txt"),
        P(L("Bu liste, sağlanan dosyaların eksiksiz olduğunu doğrulamamız için kullanılır; `00_BILGI.txt` ile "
            "birlikte iletiniz.",
            "We use this list to verify that the files provided are complete; deliver it together with "
            "`00_BILGI.txt`.")),
        H("JavaScript / TypeScript"),
        C("npm ci && npm ls --all --json > npm-deps.json                     # npm\n"
          "yarn install --frozen-lockfile && yarn list --json > yarn-deps.json  # yarn v1\n"
          "pnpm install --frozen-lockfile\n"
          "pnpm list --recursive --depth Infinity --json > pnpm-deps.json      # pnpm"),
        P(L("`npm ls` yalnızca kurulu `node_modules` üzerinden çalışır; bu nedenle build ortamında, kurulum "
            "adımından sonra çalıştırılmalıdır.",
            "`npm ls` only works on an installed `node_modules`; therefore it must be run in the build "
            "environment, after the install step.")),
        H("Python"),
        C("# L:Canlı sunucuda / container içinde, uygulamanın kullandığı Python ile|On the production server / inside the container, with the Python the application uses\n"
          "python -m pip freeze --all > python-deps.txt\n"
          "docker exec <container> python -m pip freeze --all > python-deps.txt\n"
          "conda list --export > conda-deps.txt                # L:Conda ortamları|Conda environments"),
        H("Java — Maven"),
        C("mvn -B dependency:tree -DoutputType=text -DappendOutput=true \\\n"
          "    -DoutputFile=\"$(pwd)/maven-dependency-tree.txt\"\n"
          "mvn -B help:effective-pom -Doutput=effective-pom.xml"),
        P(L("Kurum içi bir parent POM veya BOM kullanılıyorsa, ilgili POM dosyalarını da ekleyiniz ya da paket "
            "deposuna erişim veriniz (WB-30).",
            "If an internal parent POM or BOM is used, include those POM files as well or grant access to the "
            "package repository (WB-30).")),
        H(L("Java / Kotlin — Gradle (Android dahil)", "Java / Kotlin — Gradle (including Android)")),
        C("./gradlew -q projects                                   # L:modül listesi|list of modules\n"
          "./gradlew -q :<modul>:dependencies --configuration runtimeClasspath > gradle-<modul>.txt\n"
          "./gradlew -q :app:dependencies --configuration releaseRuntimeClasspath > android-app.txt\n"
          "./gradlew -q buildEnvironment > gradle-plugins.txt      # L:build eklentileri|build plugins"),
        P(L("Komutu her modül için tekrarlayınız. Windows'ta `./gradlew` yerine `gradlew.bat` kullanınız.",
            "Repeat the command for each module. On Windows use `gradlew.bat` instead of `./gradlew`.")),
        H(".NET / C#"),
        C("dotnet restore <cozum>.sln\n"
          "dotnet list <cozum>.sln package --include-transitive > dotnet-deps.txt"),
        P(L("`packages.config` kullanan eski projelerde bu dosyalar zaten tüm paketleri içerir; dosyaları "
            "sağlamanız yeterlidir. `obj/project.assets.json` dosyaları (restore sonrası oluşur) da kabul edilir.",
            "In older projects using `packages.config`, these files already list all packages; providing them is "
            "sufficient. `obj/project.assets.json` files (created after restore) are also accepted.")),
        H("PHP"),
        C("composer show --tree > composer-tree.txt"),
        P(L("`composer.lock` yoksa, canlı sunucudaki `vendor/composer/installed.json` dosyası kurulu tüm "
            "paketleri kesin sürümleriyle içerir; bu dosyayı iletiniz.",
            "If `composer.lock` is missing, the file `vendor/composer/installed.json` on the production server "
            "contains every installed package with its exact version; please provide that file.")),
        H("Go"),
        C("go list -m all > go-modules.txt\n"
          "go version -m <derlenmis-binary> > go-binary-modules.txt   # L:canlıdaki binary için|for the production binary"),
        H("Ruby / Rust / Dart-Flutter"),
        C("bundle list > ruby-deps.txt\n"
          "cargo tree > cargo-tree.txt\n"
          "flutter pub deps > flutter-deps.txt"),
        H(L("iOS — Swift / Objective-C", "iOS — Swift / Objective-C")),
        B(L("CocoaPods: `Podfile` ve `Podfile.lock`.", "CocoaPods: `Podfile` and `Podfile.lock`."),
          L("Swift Package Manager: `Package.resolved` dosyası; Xcode projelerinde konumu "
            "`<Proje>.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved` veya "
            "`<Calisma>.xcworkspace/xcshareddata/swiftpm/Package.resolved`.",
            "Swift Package Manager: the `Package.resolved` file; in Xcode projects it is located at "
            "`<Project>.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved` or "
            "`<Workspace>.xcworkspace/xcshareddata/swiftpm/Package.resolved`."),
          L("Carthage: `Cartfile` ve `Cartfile.resolved`.", "Carthage: `Cartfile` and `Cartfile.resolved`."),
          L("Projeye elle eklenen `.framework` / `.xcframework` dosyaları: WB-32 tablosuna ad ve sürüm olarak "
            "yazınız.",
            "`.framework` / `.xcframework` files added manually: list them by name and version in the WB-32 table.")),
        H("C / C++"),
        C("conan graph info . --format=json > conan-graph.json     # Conan 2\n"
          "vcpkg list > vcpkg-list.txt                             # L:vcpkg klasik mod|vcpkg classic mode"),
        P(L("Paket yöneticisi kullanılmıyorsa, kullanılan her kütüphane için WB-32'deki tablo formatında ad, "
            "sürüm, kaynak (URL) ve bağlama şekli (statik / dinamik / kaynak kopyası) bilgisini veriniz.",
            "If no package manager is used, provide the name, version, source (URL) and linking method (static / "
            "dynamic / source copy) for every library, using the table format in WB-32.")),
        H(L("WB-05 · Diğer teknolojiler", "WB-05 · Other technologies")),
        P(L("Listede olmayan bir teknoloji kullanıyorsanız, manifest ve lock dosyalarını sağlayınız ve paket "
            "yöneticisinin \"kurulu tüm paketleri sürümleriyle listele\" komutunun çıktısını ekleyiniz. Emin "
            "değilseniz bizimle iletişime geçiniz.",
            "If you use a technology that is not listed, provide its manifest and lock files and add the output of "
            "the package manager's \"list all installed packages with versions\" command. Contact us if unsure.")),
    ]},
    {"title": L("5. Whitebox — Container ve Artefaktlar (WB-10 – WB-12)",
                "5. Whitebox — Containers and Artefacts (WB-10 – WB-12)"), "blocks": [
        H(L("WB-10 · Container imajları", "WB-10 · Container images")),
        P(L("**1. Canlıda çalışan imajların listesi (digest dahil).** Kubernetes kullanılıyorsa:",
            "**1. List of images running in production (including digests).** If Kubernetes is used:")),
        C("COLS='NS:.metadata.namespace,POD:.metadata.name'\n"
          "COLS=\"$COLS,IMAGES:.status.containerStatuses[*].imageID\"\n"
          "COLS=\"$COLS,INIT:.status.initContainerStatuses[*].imageID\"\n"
          "kubectl get pods -A -o custom-columns=\"$COLS\" > 03_container/k8s-images.txt"),
        P(L("Kapsam belirli namespace'lerle sınırlıysa `-A` yerine `-n <namespace>` kullanınız. Docker "
            "sunucularında:",
            "If the scope is limited to specific namespaces, use `-n <namespace>` instead of `-A`. On Docker hosts:")),
        C("docker ps --format '{{.Image}}' | sort -u > 03_container/docker-images.txt\n"
          "docker inspect --format '{{index .RepoDigests 0}}' <registry>/<imaj>:<etiket>"),
        P(L("**2. İmajların kendisi.** Registry'ye yalnızca *pull* yetkili erişim veriniz (bkz. 2.5) veya "
            "imajları dosya olarak dışa aktarınız:",
            "**2. The images themselves.** Grant pull-only registry access (see 2.5) or export the images as files:")),
        C("docker pull <registry>/<imaj>:<etiket>\n"
          "docker save <registry>/<imaj>:<etiket> | gzip > 03_container/<imaj>_<etiket>.tar.gz\n"
          "\n"
          "# L:Docker yoksa (skopeo ile, doğrudan digest üzerinden)|Without Docker (using skopeo, directly by digest)\n"
          "skopeo copy docker://<registry>/<imaj>@sha256:<digest> oci-archive:03_container/<imaj>.tar"),
        P(L("Podman kullanıyorsanız `docker` yerine `podman` yazınız; komutlar aynıdır.",
            "If you use Podman, write `podman` instead of `docker`; the commands are the same.")),
        H(L("WB-11 · Canlıya dağıtılan paketler", "WB-11 · Packages deployed to production")),
        P(L("Dosyaları yeniden derlemeyiniz; canlı sunucudan veya sürüm pipeline'ının ürettiği artefakt "
            "deposundan alınız.",
            "Do not rebuild the files; take them from the production server or from the artefact store produced "
            "by the release pipeline.")),
        T([L("Teknoloji", "Technology"), L("Alınacak dosya", "File to collect")], [
            [L("Java", "Java"), L("Uygulama sunucusundaki `*.war` / `*.ear` / `*.jar` (ör. Tomcat `webapps/`)",
                                  "`*.war` / `*.ear` / `*.jar` on the application server (e.g. Tomcat `webapps/`)")],
            [".NET", L("Yayın (publish) dizininin tamamı (tüm `*.dll` dosyaları ve `*.deps.json`)",
                       "The entire publish directory (all `*.dll` files and `*.deps.json`)")],
            ["Node.js", L("Dağıtılan uygulama dizini (`package.json` ve lock dosyası dahil)",
                          "The deployed application directory (including `package.json` and the lock file)")],
            [L("Go / Rust / C / C++", "Go / Rust / C / C++"), L("Canlıdaki derlenmiş binary dosyaları",
                                                                "The compiled binaries running in production")],
            [L("Web ön yüz", "Web front-end"), L("Sunucuya dağıtılan derlenmiş statik dosyalar (`dist/`, `build/`)",
                                                 "Compiled static files deployed to the server (`dist/`, `build/`)")],
        ], [36, 144]),
        H(L("WB-12 · Mobil uygulama build dosyaları", "WB-12 · Mobile application builds")),
        B(L("**Android:** Mağazaya yüklenen sürümün AAB veya APK dosyasını sürüm pipeline'ından alınız. Cihazdan "
            "almak gerekirse: `adb shell pm path <paket.adi>` komutunun listelediği **tüm** `.apk` yollarını "
            "`adb pull <yol>` ile çekiniz (split APK'lar dahil).",
            "**Android:** take the AAB or APK of the version uploaded to the store from the release pipeline. If it "
            "must be taken from a device: pull **all** `.apk` paths listed by `adb shell pm path <package.name>` "
            "using `adb pull <path>` (including split APKs)."),
          L("**iOS:** Sürüm pipeline'ının ürettiği IPA dosyasını (`xcodebuild -exportArchive` çıktısı) veya "
            "`.xcarchive` dizinini iletiniz. App Store'dan indirilen IPA'lar şifreli olduğundan analiz için "
            "uygun değildir.",
            "**iOS:** provide the IPA produced by the release pipeline (`xcodebuild -exportArchive` output) or the "
            "`.xcarchive` directory. IPAs downloaded from the App Store are encrypted and are not suitable for "
            "analysis.")),
    ]},
    {"title": L("6. Whitebox — Build ve Dağıtım Ortamı (WB-20 – WB-23)",
                "6. Whitebox — Build and Deployment Environment (WB-20 – WB-23)"), "blocks": [
        H(L("WB-20 · Dockerfile ve docker-compose", "WB-20 · Dockerfiles and docker-compose")),
        P(L("Kaynak kodda yer alıyorsa ek işlem gerekmez. Ayrı bir depoda tutuluyorsa `Dockerfile*`, "
            "`docker-compose*.yml` ve `.dockerignore` dosyalarını `05_build_deploy/` klasörüne ekleyiniz.",
            "If they are part of the source code, no further action is needed. If kept in a separate repository, "
            "add `Dockerfile*`, `docker-compose*.yml` and `.dockerignore` files to `05_build_deploy/`.")),
        H(L("WB-21 · Kubernetes / Helm", "WB-21 · Kubernetes / Helm")),
        C("helm list -A\n"
          "helm get values <release> -n <namespace> --all > 05_build_deploy/<release>-values.yaml\n"
          "kubectl get deploy,sts,ds,cronjob,job -n <namespace> -o yaml > 05_build_deploy/workloads.yaml"),
        N(L("Dikkat: Helm values ve workload tanımlarında ortam değişkeni olarak düz metin parola bulunabilir. "
            "Dosyaları göndermeden önce bu değerleri `***` ile maskeleyiniz. `kubectl get secret` çıktısı veya "
            "`helm get manifest` (Secret nesnelerini içerebilir) göndermeyiniz.",
            "Caution: Helm values and workload definitions may contain plain-text passwords as environment "
            "variables. Mask these values with `***` before sending. Do not send `kubectl get secret` output or "
            "`helm get manifest` output (it may contain Secret objects).")),
        H(L("WB-22 · CI/CD pipeline tanımları", "WB-22 · CI/CD pipeline definitions")),
        T([L("Sistem", "System"), L("Dosyalar", "Files")], [
            ["Jenkins", L("`Jenkinsfile`, kullanılan shared library depoları, kurulu eklenti listesi "
                          "(*Manage Jenkins → Plugins → Installed* ekranından ad ve sürüm)",
                          "`Jenkinsfile`, shared library repositories used, installed plugin list "
                          "(name and version from *Manage Jenkins → Plugins → Installed*)")],
            ["GitLab CI", L("`.gitlab-ci.yml` ve `include:` ile çağrılan tüm şablonlar",
                            "`.gitlab-ci.yml` and all templates referenced via `include:`")],
            ["GitHub Actions", L("`.github/workflows/*.yml` ve kurum içi action depoları",
                                 "`.github/workflows/*.yml` and internal action repositories")],
            ["Azure Pipelines", L("`azure-pipelines.yml` ve kullanılan template dosyaları",
                                  "`azure-pipelines.yml` and template files used")],
            [L("Diğer", "Other"), L("Pipeline tanım dosyaları (ör. `bitbucket-pipelines.yml`, `.circleci/config.yml`)",
                                    "Pipeline definition files (e.g. `bitbucket-pipelines.yml`, `.circleci/config.yml`)")],
        ], [36, 144]),
        H(L("WB-23 · Runtime ve sunucu bilgisi", "WB-23 · Runtime and server information")),
        P(L("Container kullanılmayan canlı sunucularda aşağıdaki komutların çıktılarını tek bir metin dosyasında "
            "toplayınız (yalnızca kullanılanlar):",
            "On production servers that do not use containers, collect the output of the following commands in a "
            "single text file (only those that apply):")),
        C("cat /etc/os-release; uname -r                           # L:işletim sistemi|operating system\n"
          "java -version; node -v; python3 --version; dotnet --info\n"
          "nginx -v; httpd -v; apache2 -v                          # L:web sunucusu|web server\n"
          "$CATALINA_HOME/bin/version.sh                           # Tomcat\n"
          "\n"
          "# L:Kurulu işletim sistemi paketleri|Installed operating system packages\n"
          "dpkg-query -W -f='${Package}\\t${Version}\\t${source:Package}\\t${source:Version}\\n' \\\n    > os-packages.txt                                               # Debian / Ubuntu\n"
          "rpm -qa --qf '%{NAME}\\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\\t%{SOURCERPM}\\n' \\\n    > os-packages.txt                                               # RHEL / CentOS / Rocky / Alma\n"
          "apk info -v > os-packages.txt                                     # Alpine"),
        P(L("Windows sunucular (PowerShell):", "Windows servers (PowerShell):")),
        C("Get-ComputerInfo -Property OsName, OsVersion, OsBuildNumber\n"
          "Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\InetStp\\ | Select-Object VersionString  # IIS\n"
          "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,\n"
          "  HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* |\n"
          "  Select-Object DisplayName, DisplayVersion, Publisher |\n"
          "  Export-Csv installed-software.csv -NoTypeInformation"),
    ]},
    {"title": L("7. Whitebox — Kurum İçi ve Üçüncü Taraf Bileşenler (WB-30 – WB-33)",
                "7. Whitebox — Internal and Third-Party Components (WB-30 – WB-33)"), "blocks": [
        H(L("WB-30 · Kurum içi paket deposu", "WB-30 · Internal package repository")),
        P(L("Depo adreslerini içeren yapılandırma dosyalarını **parola/token satırlarını silerek** iletiniz: "
            "`.npmrc`, `pip.conf` / `pip.ini`, Maven `settings.xml`, `nuget.config`, Gradle `init.gradle` / "
            "`gradle.properties`. Erişim verilecekse yalnızca okuma yetkili bir hesap oluşturunuz (Nexus: ilgili "
            "depolar için `nx-repository-view-*-*-read` ve `browse`; Artifactory: *Read* izni; Azure Artifacts: "
            "feed üzerinde *Reader*; GitHub Packages: `read:packages`).",
            "Provide the configuration files containing the repository URLs **with password/token lines removed**: "
            "`.npmrc`, `pip.conf` / `pip.ini`, Maven `settings.xml`, `nuget.config`, Gradle `init.gradle` / "
            "`gradle.properties`. If access is to be granted, create a read-only account (Nexus: "
            "`nx-repository-view-*-*-read` and `browse` for the relevant repositories; Artifactory: *Read* "
            "permission; Azure Artifacts: *Reader* on the feed; GitHub Packages: `read:packages`).")),
        H(L("WB-31 · Kurum içi paket isimleri", "WB-31 · Internal package names")),
        P(L("Aşağıdaki sütunlarla bir CSV/Excel dosyası hazırlayınız:",
            "Prepare a CSV/Excel file with the following columns:")),
        C("ekosistem;paket_adi;scope_veya_groupId;kurum_ici_depo\n"
          "npm;odeme-sdk;@firma;https://nexus.firma.local/repository/npm-internal/\n"
          "maven;core-utils;com.firma.core;https://nexus.firma.local/repository/maven-releases/"),
        H(L("WB-32 · Gömülü (vendored) kütüphaneler", "WB-32 · Vendored libraries")),
        P(L("Kaynak kodda paket yöneticisi dışında bulunan ikili ve kopyalanmış dosyaları listeleyiniz:",
            "List binary and copied files present in the source code outside of package managers:")),
        C("find . \\( -name node_modules -o -name .git \\) -prune -o -type f \\( \\\n"
          "  -name '*.jar' -o -name '*.dll' -o -name '*.so' -o -name '*.so.*' -o -name '*.a' \\\n"
          "  -o -name '*.lib' -o -name '*.min.js' -o -name '*.aar' -o -name '*.xcframework' \\) \\\n"
          "  -print > 06_ucuncu_taraf/vendored-files.txt\n"
          "\n"
          "# Windows (PowerShell)\n"
          "Get-ChildItem -Recurse -File -Include *.jar,*.dll,*.so,*.a,*.lib,*.min.js,*.aar |\n"
          "  Where-Object { $_.FullName -notmatch '\\\\(node_modules|\\.git)\\\\' } |\n"
          "  Select-Object -ExpandProperty FullName > 06_ucuncu_taraf\\vendored-files.txt"),
        P(L("Sürümünü bildiğiniz kütüphaneler için ayrıca şu tabloyu doldurunuz (WB-32 ve WB-33 için ortak):",
            "For libraries whose version you know, also fill in the following table (shared by WB-32 and WB-33):")),
        C("bilesen;surum;uretici_kaynak_url;lisans;kullanildigi_yer;baglama_sekli\n"
          "jquery;3.4.1;https://jquery.com;MIT;web/static/js;kaynak kopyasi\n"
          "<odeme-sdk>;2.8.0;<uretici>;ticari;android/app/libs;statik"),
        H(L("WB-33 · Ticari / lisanslı SDK'lar", "WB-33 · Commercial / licensed SDKs")),
        P(L("Yukarıdaki tabloya ekleyiniz. Satın alma/lisans belgesindeki ürün adı ve sürümü yeterlidir; lisans "
            "anahtarlarını göndermeyiniz.",
            "Add them to the table above. The product name and version on the purchase/license document are "
            "sufficient; do not send license keys.")),
    ]},
    {"title": L("8. Whitebox — Politika ve Kapsam (WB-40 – WB-43)",
                "8. Whitebox — Policy and Scope (WB-40 – WB-43)"), "blocks": [
        H(L("WB-40 · Lisans politikası", "WB-40 · License policy")),
        P(L("İzin verilen ve yasaklanan lisansları **SPDX kimlikleriyle** listeleyiniz "
            "(https://spdx.org/licenses):",
            "List allowed and prohibited licenses using **SPDX identifiers** (https://spdx.org/licenses):")),
        C("izinli:     MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC\n"
          "onayli:     LGPL-2.1-only, MPL-2.0        # L:onayla kullanılabilir|allowed with approval\n"
          "yasakli:    AGPL-3.0-only, GPL-3.0-only, SSPL-1.0"),
        H(L("WB-41 / WB-42 · Kapsam tercihleri", "WB-41 / WB-42 · Scope preferences")),
        P(L("WB-41 formda işaretlenir. WB-42 için kapsam dışı dizinleri depo köküne göre göreli yol olarak "
            "satır başına bir tane yazınız (ör. `tools/`, `samples/`, `test/fixtures/`).",
            "WB-41 is marked in the form. For WB-42, write the excluded directories as paths relative to the "
            "repository root, one per line (e.g. `tools/`, `samples/`, `test/fixtures/`).")),
        H(L("WB-43 · Önceki raporlar ve kabul edilmiş riskler", "WB-43 · Previous reports and accepted risks")),
        P(L("Önceki SCA aracınızın (Dependency-Track, Snyk, Black Duck, Mend, OWASP Dependency-Check vb.) dışa "
            "aktarımını herhangi bir formatta (PDF, CSV, JSON, SBOM) iletebilirsiniz. Kabul edilmiş riskler için:",
            "You may provide the export of your previous SCA tool (Dependency-Track, Snyk, Black Duck, Mend, OWASP "
            "Dependency-Check, etc.) in any format (PDF, CSV, JSON, SBOM). For accepted risks:")),
        C("zafiyet_id;bilesen;surum;kabul_gerekcesi;onaylayan;gecerlilik_tarihi\n"
          "CVE-2024-XXXXX;<bilesen>;<surum>;<gerekce>;<ad soyad>;2027-06-30"),
    ]},
    {"title": L("9. Blackbox — Hedefler ve Yetkilendirme (BB-01 – BB-14)",
                "9. Blackbox — Targets and Authorization (BB-01 – BB-14)"), "blocks": [
        H(L("BB-01 – BB-05 · Hedef ve kapsam dışı listeleri", "BB-01 – BB-05 · Target and exclusion lists")),
        P(L("Formdaki alanlar yetersizse listeleri ayrı bir metin dosyası olarak iletebilirsiniz. Her satıra bir "
            "hedef yazınız:",
            "If the fields in the form are not sufficient, you may provide the lists as a separate text file. "
            "Write one target per line:")),
        C("# BB-01 Web\n"
          "https://www.firma.com.tr\n"
          "https://portal.firma.com.tr\n"
          "*.firma.com.tr            # L:tüm alt alan adları kapsamdaysa açıkça belirtiniz|state explicitly if all subdomains are in scope\n"
          "# BB-02 API\n"
          "https://api.firma.com.tr/v1/\n"
          "# BB-03 Mobil\n"
          "android: com.firma.mobil   (https://play.google.com/store/apps/details?id=com.firma.mobil)\n"
          "ios:     com.firma.mobil   (https://apps.apple.com/tr/app/<ad>/id<numara>)\n"
          "# BB-04 Altyapi\n"
          "203.0.113.10\n"
          "198.51.100.0/28\n"
          "# BB-05 Kapsam disi\n"
          "https://www.firma.com.tr/odeme/   # L:ör. üçüncü taraf ödeme sayfası|e.g. third-party payment page"),
        B(L("**API dokümantasyonu (BB-02, opsiyonel):** Swagger/OpenAPI dosyası (`openapi.json` / `swagger.yaml`) "
            "veya Postman koleksiyonu (*Collection → Export → Collection v2.1*). Postman ortam (environment) "
            "dosyalarındaki token ve parolaları silerek gönderiniz.",
            "**API documentation (BB-02, optional):** Swagger/OpenAPI file (`openapi.json` / `swagger.yaml`) or a "
            "Postman collection (*Collection → Export → Collection v2.1*). Remove tokens and passwords from Postman "
            "environment files before sending."),
          L("**Mobil paket adı (BB-03):** Android paket adı Google Play bağlantısındaki `id=` değeridir. iOS bundle "
            "ID, App Store Connect'te *Uygulama Bilgileri* sayfasında yer alır.",
            "**Mobile package name (BB-03):** the Android package name is the `id=` value in the Google Play link. "
            "The iOS bundle ID is shown on the *App Information* page in App Store Connect."),
          L("Hedeflerin yalnızca firmanıza ait veya yönetiminizde olan sistemler olduğundan emin olunuz. Üçüncü "
            "taraf sistemleri BB-05'e ekleyiniz.",
            "Make sure the targets are only systems owned or managed by your organization. Add third-party systems "
            "to BB-05.")),
        H(L("BB-10 · Yazılı test izni", "BB-10 · Written test authorization")),
        P(L("Yetkilendirme yazısı, firmanızı temsile yetkili bir kişi tarafından imzalanmalı ve en az şunları "
            "içermelidir:",
            "The authorization letter must be signed by a person authorized to represent your organization and "
            "must contain at least the following:")),
        B(L("Taraflar (firmanız ve hizmet sağlayıcı) ve yetkilendirilen test türü: \"Blackbox SCA – pasif analiz\" "
            "ve seçildiyse \"aktif doğrulama\", \"port/servis taraması\".",
            "The parties (your organization and the service provider) and the authorized test type: \"Blackbox SCA – "
            "passive analysis\" and, if selected, \"active verification\", \"port/service scanning\"."),
          L("Hedef listesi (BB-01 – BB-04) ve kapsam dışı liste (BB-05).",
            "The target list (BB-01 – BB-04) and the exclusion list (BB-05)."),
          L("Test tarih aralığı ve saatleri (BB-13).", "The test date range and hours (BB-13)."),
          L("Test kaynak IP adreslerimiz (tarafımızca bildirilir).", "Our test source IP addresses (provided by us)."),
          L("Acil durum irtibat kişileri ve testi durdurma talebinin nasıl iletileceği.",
            "Emergency contacts and how a request to stop testing will be communicated."),
          L("İmzalayanın adı, unvanı, tarih ve kaşe.", "Signatory's name, title, date and company stamp.")),
        P(L("İsteğiniz halinde bu bilgileri içeren bir yetkilendirme yazısı taslağını tarafımızca hazırlayıp "
            "imzanıza sunabiliriz.",
            "On request, we can prepare a draft authorization letter containing this information for your signature.")),
        H(L("BB-11 · Barındırma sağlayıcısı", "BB-11 · Hosting provider")),
        P(L("Hedeflerin barındırıldığı sağlayıcıyı (AWS, Azure, GCP, Cloudflare, Akamai, hosting firması vb.) "
            "belirtiniz. Sağlayıcıların sızma testi politikaları farklıdır: büyük bulut sağlayıcıları birçok "
            "hizmet için ön onay istemez ancak kendi kurallarına uyulmasını şart koşar; paylaşımlı hosting ve bazı "
            "CDN sağlayıcıları ise önceden bildirim veya onay isteyebilir. Sağlayıcınızın güncel politikasını "
            "kontrol ediniz; onay gerekiyorsa alınmasının sorumluluğu sistem sahibine aittir.",
            "Specify the provider hosting the targets (AWS, Azure, GCP, Cloudflare, Akamai, hosting company, etc.). "
            "Providers' penetration testing policies differ: major cloud providers do not require prior approval "
            "for many services but require compliance with their rules; shared hosting and some CDN providers may "
            "require prior notice or approval. Check your provider's current policy; obtaining approval, where "
            "required, is the system owner's responsibility.")),
        H(L("BB-12 · WAF / IPS koordinasyonu", "BB-12 · WAF / IPS coordination")),
        B(L("**Beyaz liste:** WAF/IPS'te yalnızca test kaynak IP adreslerimiz ve kapsamdaki hedefler için, test "
            "tarihleriyle sınırlı bir izin kuralı tanımlayınız. Kuralı loglama açık olacak şekilde oluşturunuz ve "
            "test bitiminde kaldırınız.",
            "**Whitelist:** on the WAF/IPS, define an allow rule restricted to our test source IP addresses and the "
            "in-scope targets, limited to the test dates. Create the rule with logging enabled and remove it when "
            "testing ends."),
          L("**SOC bilgilendirme:** Güvenlik operasyon ekibinize test tarihlerini, saatlerini ve kaynak IP "
            "adreslerimizi önceden bildiriniz.",
            "**Notify SOC:** inform your security operations team in advance of the test dates, hours and our "
            "source IP addresses.")),
        H(L("BB-13 / BB-14 · Zaman aralığı ve ortam", "BB-13 / BB-14 · Time window and environment")),
        P(L("Zaman aralığını saat dilimiyle belirtiniz (ör. `Pzt–Cum 09:00–18:00 (UTC+3)`). Test/staging ortamı "
            "seçildiyse, ortamın canlıyla aynı sürümü çalıştırdığını ve adresini BB-01 – BB-03 listesine "
            "eklediğinizi teyit ediniz.",
            "Specify the time window with its time zone (e.g. `Mon–Fri 09:00–18:00 (UTC+3)`). If a test/staging "
            "environment is selected, confirm that it runs the same version as production and that its addresses "
            "are included in the BB-01 – BB-03 lists.")),
    ]},
    {"title": L("10. Blackbox — Test Derinliği ve Opsiyonel Bilgiler (BB-20 – BB-31)",
                "10. Blackbox — Testing Depth and Optional Information (BB-20 – BB-31)"), "blocks": [
        H(L("BB-20 / BB-21 / BB-22", "BB-20 / BB-21 / BB-22")),
        P(L("Bu maddeler formda işaretlenir; ek hazırlık gerekmez. İstek hızı sınırı (BB-22) belirtilmezse, "
            "testler normal kullanıcı trafiğini aşmayacak düşük bir hızda yürütülür.",
            "These items are marked in the form; no additional preparation is needed. If no rate limit (BB-22) is "
            "specified, testing is performed at a low rate that does not exceed normal user traffic.")),
        H(L("BB-30 · Test kullanıcı hesabı", "BB-30 · Test user account")),
        B(L("Teste özel, gerçek müşteri verisi içermeyen bir hesap oluşturunuz; tipik bir son kullanıcı ile aynı "
            "yetki seviyesinde olmalıdır.",
            "Create a dedicated account that contains no real customer data; it should have the same permission "
            "level as a typical end user."),
          L("Çok faktörlü doğrulama (MFA) varsa: TOTP için kurulum anahtarını (QR kod / secret) veya OTP'nin "
            "gönderileceği test telefon numarası / e-posta adresini sağlayınız.",
            "If multi-factor authentication (MFA) is used: provide the TOTP setup key (QR code / secret) or the test "
            "phone number / e-mail address to which the OTP will be sent."),
          L("Kullanıcı adı ve parolayı, arşiv parolası gibi ayrı bir kanaldan iletiniz; test bitiminde hesabı "
            "kapatınız.",
            "Send the username and password over a separate channel, like the archive password; disable the account "
            "when testing ends.")),
        H(L("BB-31 · Mobil uygulama dosyası", "BB-31 · Mobile application file")),
        P(L("Uygulama mağazada yayımlanmıyorsa: Android için APK/AAB dosyasını (bkz. WB-12); iOS için TestFlight "
            "daveti veya kurumsal (enterprise) imzalı IPA dosyasını iletiniz.",
            "If the application is not published in a store: for Android provide the APK/AAB file (see WB-12); for "
            "iOS provide a TestFlight invitation or an enterprise-signed IPA file.")),
    ]},
    {"title": L("11. Sık Sorulan Sorular", "11. Frequently Asked Questions"), "blocks": [
        {"type": "faq", "items": [
            (L("Kaynak kodumuzu paylaşamıyoruz. Whitebox yine de yapılabilir mi?",
               "We cannot share our source code. Is whitebox still possible?"),
             L("İki seçenek vardır: (1) Analiz sizin ortamınızda yapılır (WB-50: Yerinde / VDI), kod dışarı çıkmaz. "
               "(2) Yalnızca bağımlılık dosyaları (Bölüm 4) ve container imajları (WB-10) sağlanır. İkinci "
               "seçenekte gömülü kütüphaneler (WB-32) tespit edilemez ve bu durum raporda kapsam kısıtı olarak "
               "belirtilir.",
               "There are two options: (1) the analysis is performed in your environment (WB-50: On-site / VDI) and "
               "the code never leaves it. (2) Only dependency files (Section 4) and container images (WB-10) are "
               "provided. With the second option vendored libraries (WB-32) cannot be detected, and this is stated "
               "in the report as a scope limitation.")),
            (L("Kodumuzda parola veya API anahtarı olabilir. Sorun olur mu?",
               "Our code may contain passwords or API keys. Is that a problem?"),
             L("SCA analizi bileşenleri inceler, gizli bilgilere ihtiyaç duymaz. `.env` ve anahtar dosyalarını "
               "dahil etmeyiniz (bkz. 2.2). Koda gömülü gizli bilgiler, sağlanan tüm veriler gibi gizli tutulur.",
               "SCA analysis examines components and does not need secrets. Do not include `.env` and key files "
               "(see 2.2). Secrets embedded in the code are kept confidential, like all data provided.")),
            (L("`node_modules` klasörünü göndermeli miyiz?", "Should we send the `node_modules` folder?"),
             L("Hayır. Lock dosyası (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`) yeterlidir. Lock dosyası "
               "yoksa `npm ls` çıktısını gönderiniz (bkz. Bölüm 4).",
               "No. The lock file (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`) is sufficient. If there is no "
               "lock file, send the `npm ls` output (see Section 4).")),
            (L("Lock dosyamız yok ve canlıya çıkan build'in ortamına artık erişemiyoruz.",
               "We have no lock file and no longer have access to the environment of the released build."),
             L("Bu durumda en güvenilir kaynak canlıdaki çalışan sistemdir: container imajı (WB-10), dağıtılan "
               "paket (WB-11) veya sunucuda `pip freeze` / `vendor/composer/installed.json` gibi çıktılar. Bunlar "
               "da yoksa analiz manifest dosyası üzerinden yapılır ve bulgular \"tahmini sürüm\" olarak işaretlenir.",
               "In that case the most reliable source is the running production system: the container image "
               "(WB-10), the deployed package (WB-11), or outputs such as `pip freeze` / "
               "`vendor/composer/installed.json` on the server. If none of these are available, the analysis is "
               "based on the manifest and findings are marked as \"estimated version\".")),
            (L("Arşiv çok büyük.", "The archive is too large."),
             L("Bölüm 2.2'deki dizinlerin dışlandığından emin olunuz. Gerekirse arşivi `-v2g` parametresiyle "
               "parçalara bölünüz (bkz. 2.4) veya salt-okunur erişim yöntemini tercih ediniz.",
               "Make sure the directories listed in Section 2.2 are excluded. If necessary, split the archive using "
               "the `-v2g` parameter (see 2.4) or choose the read-only access method.")),
            (L("İstenen maddelerin bir kısmını sağlayamıyoruz.", "We cannot provide some of the requested items."),
             L("Formda ilgili maddeyi \"Yok\" olarak işaretleyiniz. Zorunlu olmayan maddeler eksik olsa da analiz "
               "yapılır; eksik maddeler raporda kapsam kısıtı olarak belirtilir. Zorunlu bir madde eksikse sizinle "
               "birlikte alternatif belirlenir.",
               "Mark the item as \"No\" in the form. The analysis is performed even if non-mandatory items are "
               "missing; missing items are stated in the report as scope limitations. If a mandatory item is "
               "missing, we agree on an alternative together.")),
            (L("Komutlardan biri hata veriyor.", "One of the commands returns an error."),
             L("Hata çıktısını, komutu çalıştırdığınız ortam bilgisiyle (işletim sistemi, araç sürümü) birlikte "
               "teknik irtibat kişimize iletiniz; birlikte çözüm bulunur.",
               "Send the error output together with the environment details (operating system, tool version) to our "
               "technical contact; we will resolve it together.")),
        ]},
    ]},
    {"title": L("12. Teslim Öncesi Son Kontrol", "12. Final Check Before Delivery"), "blocks": [
        {"type": "checklist", "items": [
            L("Form doldurulup imzalandı ve arşive / e-postaya eklendi.",
              "The form has been filled in, signed and attached to the archive / e-mail."),
            L("`00_BILGI.txt` içinde canlıdaki commit hash / tag ve uygulama listesi yazılı.",
              "`00_BILGI.txt` contains the production commit hash / tag and the application list."),
            L("Kullanılan her teknoloji için lock dosyası veya komut çıktısı mevcut.",
              "A lock file or command output exists for each technology used."),
            L("`.env`, anahtar dosyaları, Kubernetes Secret'ları ve gerçek müşteri verisi dahil edilmedi; "
              "yapılandırma dosyalarındaki parolalar maskelendi.",
              "`.env`, key files, Kubernetes Secrets and real customer data are excluded; passwords in "
              "configuration files are masked."),
            L("`SHA256SUMS.txt` oluşturuldu.", "`SHA256SUMS.txt` has been created."),
            L("Arşiv AES-256 ve dosya adı şifreleme ile oluşturuldu; parola ve arşiv özeti ayrı kanaldan iletildi.",
              "The archive was created with AES-256 and file name encryption; the password and archive hash were "
              "sent over a separate channel."),
            L("Blackbox için imzalı yetkilendirme yazısı iletildi ve WAF/SOC koordinasyonu tamamlandı.",
              "For blackbox, the signed authorization letter has been sent and WAF/SOC coordination is complete."),
        ]},
    ]},
]


EN_MAP = [
    ("00_bagimlilik_dosyalari.txt", "00_dependency_files.txt"), ("00_BILGI.txt", "00_INFO.txt"),
    ("01_kaynak_kod", "01_source_code"), ("02_bagimlilik_ciktilari", "02_dependency_outputs"),
    ("04_artefaktlar", "04_artefacts"), ("06_ucuncu_taraf", "06_third_party"), ("07_politika", "07_policy"),
    ("kaynak_kod.tar.gz", "source_code.tar.gz"),
    ("<YYYY-AA-GG>", "<YYYY-MM-DD>"), ("<Firma>", "<Company>"), ("<derlenmis-binary>", "<compiled-binary>"),
    ("<paket.adi>", "<package.name>"), ("<imaj>", "<image>"), ("<etiket>", "<tag>"), ("<modul>", "<module>"),
    ("<cozum>", "<solution>"), ("<bilesen>", "<component>"), ("<surum>", "<version>"), ("<gerekce>", "<reason>"),
    ("<ad soyad>", "<full name>"), ("<odeme-sdk>", "<payment-sdk>"), ("<uretici>", "<vendor>"),
    ("<ad>", "<name>"), ("<numara>", "<number>"), ("<Uygulama>", "<Application>"),
    ("ekosistem;paket_adi;scope_veya_groupId;kurum_ici_depo", "ecosystem;package_name;scope_or_groupId;internal_repository"),
    ("bilesen;surum;uretici_kaynak_url;lisans;kullanildigi_yer;baglama_sekli",
     "component;version;vendor_source_url;license;used_in;linking"),
    ("zafiyet_id;bilesen;surum;kabul_gerekcesi;onaylayan;gecerlilik_tarihi",
     "vulnerability_id;component;version;acceptance_reason;approved_by;valid_until"),
    ("odeme-sdk", "payment-sdk"), ("kaynak kopyasi", "source copy"), (";ticari;", ";commercial;"),
    (";statik", ";static"),
    ("izinli:  ", "allowed: "), ("onayli:  ", "approval:"), ("yasakli: ", "denied:  "),
    ("# BB-03 Mobil", "# BB-03 Mobile"), ("# BB-04 Altyapi", "# BB-04 Infrastructure"),
    ("# BB-05 Kapsam disi", "# BB-05 Out of scope"),
    ("apps.apple.com/tr/app/", "apps.apple.com/app/"), ("firma.com.tr", "example.com"),
    ("firma.local", "example.local"), ("com.firma.mobil", "com.example.mobile"), ("com.firma.", "com.example."),
    ("@firma", "@example"),
]


def localize(obj, lang):
    if lang != "en":
        return obj
    if isinstance(obj, str):
        for a, b in EN_MAP:
            obj = obj.replace(a, b)
        return obj
    if isinstance(obj, dict):
        return {k: localize(v, lang) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return type(obj)(localize(v, lang) for v in obj)
    return obj
