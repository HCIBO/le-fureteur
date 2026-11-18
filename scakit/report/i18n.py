LANGS = ("tr", "en", "fr", "de")

T = {
    "title": ("Yazılım Bileşen Analizi (SCA) Raporu", "Software Composition Analysis (SCA) Report"),
    "client": ("Müşteri", "Client"),
    "engagement": ("Çalışma", "Engagement"),
    "date": ("Rapor tarihi", "Report date"),
    "db_state": ("Zafiyet veritabanı durumu", "Vulnerability database state"),
    "summary": ("Yönetici Özeti", "Executive Summary"),
    "components": ("Bileşen", "Components"),
    "affected": ("Zafiyetli bileşen", "Vulnerable components"),
    "findings": ("Bulgu", "Findings"),
    "kev": ("Aktif istismar edilen (CISA KEV)", "Known exploited (CISA KEV)"),
    "malicious": ("Zararlı paket", "Malicious package"),
    "sev": {"CRITICAL": ("Kritik", "Critical"), "HIGH": ("Yüksek", "High"), "MEDIUM": ("Orta", "Medium"),
            "LOW": ("Düşük", "Low"), "UNKNOWN": ("Belirsiz", "Unknown"), "NONE": ("Yok", "None")},
    "plan": ("Düzeltme Planı (öncelik sırasıyla)", "Remediation Plan (by priority)"),
    "plan_intro": (
        "Her bileşen için, bilinen tüm zafiyetleri kapatan en düşük sürüm önerilmiştir. Sıralama: zararlı paket, "
        "aktif istismar (KEV), şiddet, istismar olasılığı (EPSS).",
        "For each component, the lowest version that fixes all known vulnerabilities is recommended. Ordering: "
        "malicious package, known exploitation (KEV), severity, exploit probability (EPSS)."),
    "component": ("Bileşen", "Component"),
    "current": ("Mevcut sürüm", "Current version"),
    "recommended": ("Önerilen sürüm", "Recommended version"),
    "no_fix": ("Düzeltilmiş sürüm yok", "No fixed version"),
    "vulns": ("Zafiyetler", "Vulnerabilities"),
    "relation": ("İlişki", "Relation"),
    "direct": ("Doğrudan", "Direct"),
    "transitive": ("Dolaylı", "Transitive"),
    "via": ("üzerinden", "via"),
    "details": ("Bulgu Detayları", "Finding Details"),
    "id": ("Kimlik", "ID"),
    "severity": ("Şiddet", "Severity"),
    "fix": ("Düzeltme", "Fix"),
    "confidence": ("Güven", "Confidence"),
    "evidence": ("Kanıt", "Evidence"),
    "conf": {"high": ("Yüksek", "High"), "medium": ("Orta", "Medium"), "low": ("Düşük", "Low")},
    "inventory": ("Bileşen Envanteri", "Component Inventory"),
    "ecosystem": ("Ekosistem", "Ecosystem"),
    "version": ("Sürüm", "Version"),
    "license": ("Lisans", "License"),
    "scope": ("Kapsam ve Yöntem", "Scope and Method"),
    "runs": ("Analiz edilen kaynaklar", "Analysed sources"),
    "kind": {"source": ("Whitebox – kaynak / bağımlılık dosyaları", "Whitebox – source / dependency files"),
             "archive": ("Whitebox – derlenmiş paket", "Whitebox – build artefact"),
             "image": ("Whitebox – container imajı", "Whitebox – container image"),
             "web": ("Blackbox – web uygulaması", "Blackbox – web application"),
             "apk": ("Blackbox – Android uygulaması", "Blackbox – Android application"),
             "ipa": ("Blackbox – iOS uygulaması", "Blackbox – iOS application"),
             "list": ("Whitebox – paket listesi", "Whitebox – package list"),
             "desktop": ("Blackbox – masaüstü uygulaması", "Blackbox – desktop application"),
             "sbom": ("SBOM içe aktarma", "SBOM import"),
             "traffic": ("Tarayıcı / proxy trafiği (HAR, Burp)", "Browser / proxy traffic (HAR, Burp)")},
    "limits": ("Kapsam Kısıtları ve Gözlemler", "Scope Limitations and Observations"),
    "lim_unversioned": ("Sürümü belirlenemeyen bileşenler zafiyet eşleştirmesine dahil edilemedi",
                        "Components without a determinable version could not be matched against vulnerabilities"),
    "lim_estimated": ("Sürümü tahmini / orta-düşük güvenle belirlenen bileşenler",
                      "Components whose version was estimated or determined with medium/low confidence"),
    "lim_nocov": ("Zafiyet veritabanında kapsamı olmayan ekosistemlerdeki bileşenler (yalnızca envantere alındı)",
                  "Components in ecosystems not covered by the vulnerability database (inventory only)"),
    "lim_blackbox": (
        "Blackbox analizde yalnızca dışarıdan gözlemlenebilen bileşenler tespit edilebilir. Sunucu tarafında "
        "çalışan ve yanıtlara iz bırakmayan kütüphaneler bu yöntemle tespit edilemez; bu bölümde bir zafiyetin "
        "raporlanmamış olması, uygulamanın ilgili zafiyetten etkilenmediği anlamına gelmez.",
        "Blackbox analysis can only identify externally observable components. Server-side libraries that leave no "
        "trace in responses cannot be detected this way; the absence of a vulnerability here does not mean the "
        "application is unaffected."),
    "obs": {"missing-lockfile": ("Lock dosyası yok — dolaylı bağımlılıklar ve kesin sürümler eksik olabilir",
                                 "No lock file — transitive dependencies and exact versions may be missing"),
            "dev-excluded": ("Geliştirme / test bağımlılıkları kapsam dışı bırakıldı",
                             "Development / test dependencies were excluded"),
            "missing-sri": ("Harici kaynaktan yüklenen script için Subresource Integrity (SRI) yok",
                            "No Subresource Integrity (SRI) on a script loaded from an external origin"),
            "sourcemap-exposed": ("JavaScript source map dosyası herkese açık",
                                  "JavaScript source map file is publicly accessible"),
            "exposed-file": ("Bağımlılık dosyası web üzerinden erişilebilir",
                             "Dependency file is accessible over the web"),
            "version-header": ("Sunucu yazılım sürümü yanıt başlığında açıklanıyor",
                               "Server software version disclosed in response header"),
            "obfuscated": ("Kod karartma tespit edildi — bazı bileşen sürümleri belirlenemeyebilir",
                           "Code obfuscation detected — some component versions may not be determinable"),
            "unsupported-layer": ("Desteklenmeyen imaj katmanı biçimi atlandı", "Unsupported image layer format skipped"),
            "version-error-page": ("Hata sayfasında sunucu / framework sürümü açıklanıyor",
                                   "Server / framework version disclosed on error page"),
            "version-disclosure": ("Platform sürüm bilgisi erişilebilir (CMS sürüm dosyası / akışı)",
                                   "Platform version information accessible (CMS version file / feed)"),
            "license-manifest": ("Üçüncü taraf lisans manifesti erişilebilir (paket listesi; çoğunlukla sürümsüz)",
                                 "Third-party license manifest accessible (package list; usually without versions)"),
            "private-registry": ("Kurum içi registry'den çözümlenen paket — bağımlılık karışıklığı açısından "
                                 "doğrulanmalı", "Package resolved from an internal registry — verify against "
                                 "dependency confusion"),
            "internal-package": ("Kurum içi paket (WB-31 listesi)", "Internal package (WB-31 list)"),
            "dependency-confusion": ("Bağımlılık karışıklığı riski", "Dependency confusion risk"),
            "stale-package": ("Uzun süredir yeni sürüm yayımlanmamış paket (bakımı durmuş olabilir)",
                              "No new release for a long time (possibly unmaintained)"),
            "deprecated-package": ("Kullanımdan kaldırılmış (deprecated) paket sürümü", "Deprecated package version"),
            "no-osv-coverage": ("Bu bileşen türü için otomatik zafiyet eşleştirmesi yapılmamaktadır",
                                "Automatic vulnerability matching is not performed for this component type")},
    "method_text": (
        "Bileşenler; bağımlılık / lock dosyaları, komut çıktıları, derlenmiş paket meta verileri, container imajı "
        "paket veritabanları ve (blackbox) dışarıdan gözlemlenen izlerden tespit edilmiştir. Zafiyet eşleştirmesi "
        "OSV.dev veritabanının çevrimdışı kopyası ile yapılmış; istismar olasılığı FIRST EPSS, aktif istismar "
        "bilgisi CISA KEV kataloğundan alınmıştır. Analiz sırasında kaynak kod veya envanter üçüncü taraf "
        "çevrimiçi servislere gönderilmemiştir.",
        "Components were identified from dependency / lock files, command outputs, build artefact metadata, "
        "container image package databases and (blackbox) externally observed traces. Vulnerabilities were matched "
        "using an offline copy of the OSV.dev database; exploit probability is from FIRST EPSS and known "
        "exploitation from the CISA KEV catalog. No source code or inventory was sent to third-party online "
        "services during the analysis."),
    "none": ("Bulgu yok.", "No findings."),
    "count_line": ("{n} bileşen için {f} bulgu", "{f} findings across {n} components"),
    "target": ("Hedef", "Target"),
    "source": ("Kaynak", "Source"),
    "time": ("Zaman", "Time"),
    "detections": ("Tespit", "Detections"),
    "more": ("… ve {n} kanıt daha", "… and {n} more evidence"),
    "summary_text": (
        "Analiz kapsamında {n} bileşen tespit edilmiş, bunlardan {a} tanesinde bilinen güvenlik açığı bulunmuştur. "
        "Toplam {f} bulgunun {c} tanesi kritik, {h} tanesi yüksek seviyededir.",
        "{n} components were identified, {a} of which have known vulnerabilities. Of {f} findings in total, {c} are "
        "critical and {h} are high."),
    "kev_text": ("{k} bulgu, CISA tarafından aktif olarak istismar edildiği bilinen zafiyetlerdir ve öncelikle "
                 "giderilmelidir.",
                 "{k} findings are vulnerabilities known by CISA to be actively exploited and should be fixed first."),
    "mal_text": ("{m} bileşen zararlı paket olarak işaretlenmiştir; derhal kaldırılmalı ve sistemler incelenmelidir.",
                 "{m} components are flagged as malicious packages; remove them immediately and investigate systems."),
    "top_actions": ("Öncelikli aksiyonlar", "Priority actions"),
    "usage": {"imported": ("kodda import ediliyor", "imported in code"),
              "not-imported": ("kodda doğrudan import görülmedi", "no direct import seen in code")},
    "reach": {"called": ("Etkilenen fonksiyon çağrılıyor", "Affected function is called"),
              "not-called": ("Etkilenen fonksiyon çağrısı görülmedi", "No call to affected function seen")},
    "usage_title": ("Kullanım Analizi", "Usage Analysis"),
    "usage_text": (
        "Whitebox kaynak kodda paketlerin import edilip edilmediği incelenmiştir (JS/TS, Python, Java/Kotlin, C#, "
        "Go, Ruby). Go bileşenlerinde ayrıca zafiyetten etkilenen fonksiyonların kodda çağrılıp çağrılmadığı "
        "kontrol edilmiştir. Bu analiz tam bir çağrı grafiği değildir: çalışma zamanında dolaylı yüklenen "
        "kütüphaneler (ör. loglama altyapıları, sürücüler, eklentiler) kodda import edilmeden kullanılabilir. "
        "Bu nedenle 'import görülmedi' sonucu, bileşenin kullanılmadığı anlamına gelmez; önceliklendirmede "
        "yardımcı bir sinyal olarak değerlendirilmelidir.",
        "Whitebox source code was analysed for whether packages are imported (JS/TS, Python, Java/Kotlin, C#, Go, "
        "Ruby). For Go components, whether the functions affected by a vulnerability are called was also checked. "
        "This is not a full call graph: libraries loaded indirectly at runtime (e.g. logging backends, drivers, "
        "plugins) can be used without being imported. A 'no import seen' result therefore does not mean the "
        "component is unused; treat it as a supporting prioritisation signal."),
    "usage_stats": ("{i} doğrudan bağımlılık kodda import ediliyor, {n} tanesinde doğrudan import görülmedi.",
                    "{i} direct dependencies are imported in code; no direct import was seen for {n}."),
    "reach_stats": ("Go: {c} bulguda etkilenen fonksiyon çağrılıyor, {n} bulguda çağrı görülmedi.",
                    "Go: the affected function is called in {c} findings; no call was seen in {n}."),
    "nvd_note": (
        "OSV kapsamı dışındaki sunucu yazılımları ve native kütüphaneler (nginx, Apache, PHP, OpenSSL, sqlite vb.) "
        "NVD CPE verisiyle eşleştirilmiştir. Dağıtım paketlerinde (Ubuntu, Debian, RHEL...) güvenlik yamaları "
        "sürüm numarası değişmeden geri taşınabildiğinden, bu bileşenlerdeki NVD bulguları düşük güvenle "
        "raporlanmıştır ve dağıtımın güvenlik duyurularıyla teyit edilmelidir.",
        "Server software and native libraries outside OSV coverage (nginx, Apache, PHP, OpenSSL, sqlite, etc.) were "
        "matched using NVD CPE data. Distribution packages (Ubuntu, Debian, RHEL...) may receive backported "
        "security fixes without a version change; NVD findings on such components are reported with low confidence "
        "and should be confirmed against the distribution's security advisories."),
    "lic_title": ("Lisans Uyumu", "License Compliance"),
    "lic_text": (
        "Uygulama bağımlılıklarının lisansları SPDX kimliklerine normalleştirilmiş ve {pol} göre "
        "değerlendirilmiştir. İşletim sistemi paketleri ve ikili dosyalardan tespit edilen bileşenler bu "
        "değerlendirmeye dahil edilmemiştir. Bu bölüm hukuki görüş değildir; 'inceleme gerekli' ve 'yasaklı' "
        "sonuçları hukuk biriminizce değerlendirilmelidir.",
        "Licenses of application dependencies were normalised to SPDX identifiers and evaluated against {pol}. "
        "Operating system packages and components detected from binaries are excluded. This section is not legal "
        "advice; 'review required' and 'denied' results should be assessed by your legal team."),
    "pol_custom": ("kurumunuzun lisans politikasına", "your organisation's license policy"),
    "pol_default": ("varsayılan politikaya (serbest: uygun; LGPL/MPL/EPL/GPL: inceleme; AGPL/SSPL ve ticari "
                    "kısıtlı lisanslar: yasaklı)",
                    "the default policy (permissive: allowed; LGPL/MPL/EPL/GPL: review; AGPL/SSPL and "
                    "commercially restricted licenses: denied)"),
    "decision": {"allowed": ("Uygun", "Allowed"), "review": ("İnceleme gerekli", "Review required"),
                 "denied": ("Yasaklı / riskli", "Denied / risky"), "unknown": ("Lisans belirlenemedi", "Unknown")},
    "lic_cat": {"permissive": ("Serbest", "Permissive"), "weak-copyleft": ("Zayıf copyleft", "Weak copyleft"),
                "strong-copyleft": ("Güçlü copyleft", "Strong copyleft"),
                "network-copyleft": ("Ağ copyleft", "Network copyleft"), "restrictive": ("Kısıtlayıcı", "Restrictive"),
                "unknown": ("Bilinmiyor", "Unknown")},
    "decision_col": ("Karar", "Decision"),
    "category_col": ("Kategori", "Category"),
    "sc_title": ("Tedarik Zinciri", "Supply Chain"),
    "sc_none": ("Tedarik zinciri riski tespit edilmedi.", "No supply-chain risks were identified."),
    "online_method": (
        "Lisans, bakım durumu ve paket adı kontrolleri için yalnızca paket adları ve sürümleri {svc} servislerine "
        "gönderilmiştir; kaynak kod veya dosya gönderilmemiştir.",
        "For license, maintenance and package-name checks, only package names and versions were sent to {svc}; "
        "no source code or files were sent."),
    "sup_title": ("Kabul Edilen Riskler ve Yanlış Pozitifler", "Accepted Risks and False Positives"),
    "sup_text": ("Aşağıdaki bulgular gerekçesiyle birlikte ana bulgu listesinden ayrılmıştır.",
                 "The following findings were separated from the main list with their justification."),
    "sup_kind": {"accepted-risk": ("Kabul edilen risk", "Accepted risk"),
                 "false-positive": ("Yanlış pozitif", "False positive"),
                 "not-affected": ("Etkilenmiyor", "Not affected")},
    "reason": ("Gerekçe", "Justification"),
    "location": ("Konum / Kanıt", "Location / Evidence"),
    "target_loc": ("Hedef / Konum", "Target / Location"),
    "appendix_c": ("Ek C — Tespit Konumları", "Appendix C — Detection Locations"),
    "appendix_c_text": ("Zafiyetli her bileşenin tespit edildiği tüm konumlar (URL, dosya yolu) ve kanıtları.",
                        "All locations (URL, file path) and evidence where each vulnerable component was detected."),
    "method_col": ("Yöntem", "Method"),
    "method": {"lockfile": ("Lock dosyası", "Lock file"), "manifest": ("Manifest", "Manifest"),
               "command-output": ("Komut çıktısı", "Command output"), "pkgdb": ("Paket veritabanı", "Package database"),
               "jar-meta": ("JAR meta verisi", "JAR metadata"), "installed-package": ("Kurulu paket", "Installed package"),
               "signature": ("JS / CSS imzası", "JS / CSS signature"), "sourcemap": ("Source map", "Source map"),
               "cdn-url": ("CDN adresi", "CDN URL"), "exposed-file": ("Açık dosya", "Exposed file"),
               "header": ("HTTP başlığı", "HTTP header"), "meta-generator": ("Meta generator", "Meta generator"),
               "query-version": ("URL sürüm parametresi", "URL version parameter"),
               "license-manifest": ("Lisans manifesti", "License manifest"),
               "dex-strings": ("DEX string", "DEX string"), "binary-strings": ("İkili dosya string", "Binary string"),
               "properties": ("Sürüm dosyası", "Version file"), "pe-version": ("PE sürüm bilgisi", "PE version info"),
               "image-config": ("İmaj yapılandırması", "Image config"),
               "body-banner": ("Sayfa içeriği", "Page content"), "error-page": ("Hata sayfası", "Error page"),
               "cms-version": ("CMS sürüm noktası", "CMS version endpoint"),
               "platform": ("Platform işareti", "Platform marker"), "sbom": ("SBOM", "SBOM")},
    "upgrade_line": ("{c} → {v} ({n} zafiyet)", "{c} → {v} ({n} vulnerabilities)"),
}


def tr(key, lang, sub=None):
    if lang in ("fr", "de"):
        from .i18n_more import lookup
        hit = lookup(key, lang, sub)
        if hit is not None:
            return hit
    v = T[key]
    if sub is not None:
        v = v[sub]
    return v[0] if lang == "tr" else v[1]
