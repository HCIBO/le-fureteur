import sys
from pathlib import Path

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import PP_ALIGN
from pptx.util import Emu, Pt

NAVY = RGBColor(0x1F, 0x3A, 0x5F)
ORANGE = RGBColor(0xE0, 0x9A, 0x2B)
LIGHT = RGBColor(0xF1, 0xF4, 0xF8)
GREY = RGBColor(0x5B, 0x64, 0x72)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)
DARK = RGBColor(0x1D, 0x24, 0x30)
W, H = Emu(12192000), Emu(6858000)
CM = 360000


def L(tr, en):
    return {"tr": tr, "en": en}


DECK = [
    {"kind": "title",
     "title": L("Yazılım Bileşen Analizi (SCA) Hizmeti", "Software Composition Analysis (SCA) Service"),
     "sub": L("SCA nedir, nasıl test edilir ve scakit ile nasıl fark yaratırız",
              "What SCA is, how it is tested and how scakit makes the difference")},

    {"title": L("SCA nedir?", "What is SCA?"),
     "bullets": L(
         ["Uygulamaların kullandığı açık kaynak ve üçüncü taraf bileşenleri (kütüphane, framework, SDK, "
          "container imajı) tespit eder",
          "Bu bileşenlerdeki bilinen güvenlik açıklarını, lisans risklerini ve tedarik zinciri risklerini raporlar",
          "Çıktısı: bileşen envanteri (SBOM), önceliklendirilmiş zafiyet listesi ve düzeltme planı",
          "Pentest kendi kodumuzdaki hataları arar; SCA başkasının kodundan gelen riski görünür kılar"],
         ["Identifies the open-source and third-party components an application uses (libraries, frameworks, "
          "SDKs, container images)",
          "Reports known vulnerabilities, license risks and supply-chain risks in those components",
          "Output: component inventory (SBOM), prioritised vulnerability list and remediation plan",
          "A pentest looks for flaws in our own code; SCA exposes the risk inherited from other people's code"])},

    {"title": L("Neden şimdi?", "Why now?"),
     "cols": [
         (L("Gerçek olaylar", "Real incidents"),
          L(["Log4Shell (2021) — tek bir loglama kütüphanesi binlerce sistemi etkiledi",
             "event-stream (2018) — popüler npm paketine zararlı kod eklendi",
             "Dependency confusion (2021) — dahili paket adlarıyla public registry üzerinden saldırı",
             "xz-utils (2024) — sıkıştırma kütüphanesine gizlenmiş arka kapı"],
            ["Log4Shell (2021) — one logging library affected thousands of systems",
             "event-stream (2018) — malicious code added to a popular npm package",
             "Dependency confusion (2021) — attacks via internal package names on public registries",
             "xz-utils (2024) — backdoor hidden in a compression library"])),
         (L("Regülasyon ve standartlar", "Regulation and standards"),
          L(["ABD EO 14028 (2021): kamuya satılan yazılımlarda SBOM",
             "AB Cyber Resilience Act: üreticilerden bileşen envanteri ve zafiyet yönetimi",
             "DORA (AB finans): BİT üçüncü taraf risk yönetimi",
             "PCI DSS 4.0 — 6.3.2: üçüncü taraf yazılım bileşenleri envanteri"],
            ["US EO 14028 (2021): SBOM for software sold to government",
             "EU Cyber Resilience Act: component inventory and vulnerability handling for manufacturers",
             "DORA (EU finance): ICT third-party risk management",
             "PCI DSS 4.0 — 6.3.2: inventory of third-party software components"]))]},

    {"title": L("SCA test türleri", "Types of SCA testing"),
     "boxes": [
         (L("Whitebox", "Whitebox"),
          L("Kaynak kod, lock dosyaları, container imajları. Tam envanter, kesin sürümler, lisans analizi, SBOM.",
            "Source code, lock files, container images. Complete inventory, exact versions, license analysis, SBOM.")),
         (L("Blackbox", "Blackbox"),
          L("Yalnızca hedef: URL, APK/IPA, kurulum dosyası. Saldırganın gördüğü yüzey; sunucu tarafı görünmez.",
            "Target only: URL, APK/IPA, installer. The attacker's view; server side is not visible.")),
         (L("Hibrit (önerilen)", "Hybrid (recommended)"),
          L("İkisi birlikte, tek envanterde. Tam envanter + dışarıdan görünen risk.",
            "Both together in one inventory. Complete inventory + externally visible risk."))],
     "foot": L("Analiz seviyeleri: Minimum (yalnızca hedef) · Önerilen (lock dosyaları, kaynak kod gerekmez) · "
               "Tam (kaynak kod dahil)",
               "Analysis levels: Minimum (target only) · Recommended (lock files, no source code) · "
               "Full (including source code)")},

    {"title": L("Ne raporluyoruz?", "What do we report?"),
     "boxes": [
         (L("Zafiyetler", "Vulnerabilities"),
          L("CVE / GHSA, CVSS, aktif istismar (CISA KEV), istismar olasılığı (EPSS), düzeltme sürümü",
            "CVE / GHSA, CVSS, known exploitation (CISA KEV), exploit probability (EPSS), fixed version")),
         (L("Lisans uyumu", "License compliance"),
          L("SPDX normalizasyonu, müşteri politikasına göre uygun / inceleme / yasaklı",
            "SPDX normalisation, allowed / review / denied against the customer policy")),
         (L("Tedarik zinciri", "Supply chain"),
          L("Zararlı paket, dependency confusion, deprecated ve bakımı durmuş paketler",
            "Malicious packages, dependency confusion, deprecated and unmaintained packages")),
         (L("SBOM", "SBOM"),
          L("CycloneDX 1.5 ve SPDX 2.3; müşterinin kendi araçlarına aktarılabilir",
            "CycloneDX 1.5 and SPDX 2.3; importable into the customer's own tools"))]},

    {"title": L("Raporlamadaki kavramlar", "Reporting terminology"),
     "grid": L([("CVE", "Bir zafiyetin dünya genelindeki tekil kimliği (CVE-2021-44228). MITRE / CVE Programı yönetir."),
                ("NVD + CPE", "ABD NIST'in zafiyet veritabanı; CVE'lere CVSS skoru ve etkilenen ürün (CPE) bilgisi ekler."),
                ("OSV + GHSA", "Açık kaynak paketler için zafiyet veritabanı; ekosistem bazında kesin etkilenen sürüm "
                               "aralıkları. GHSA: GitHub danışma kimliği."),
                ("CVSS", "Şiddet puanı (0–10, FIRST). Kritik ≥ 9.0, Yüksek ≥ 7.0. Teknik etkiyi ölçer, olasılığı değil."),
                ("EPSS", "Önümüzdeki 30 günde istismar edilme olasılığı (FIRST); her gün güncellenir."),
                ("KEV", "CISA'nın sahada aktif istismar edildiğini doğruladığı zafiyetler kataloğu — en önce bunlar."),
                ("SBOM", "Yazılım bileşen listesi (Software Bill of Materials): hangi bileşen, hangi sürüm, nereden."),
                ("CycloneDX / SPDX", "İki standart SBOM formatı: CycloneDX (OWASP), SPDX (Linux Foundation, ISO/IEC 5962)."),
                ("PURL / VEX", "PURL: paket kimliği (pkg:npm/lodash@4.17.21). VEX: \"bu zafiyetten etkileniyor muyuz\" "
                               "beyanı.")],
               [("CVE", "Globally unique ID of a vulnerability (CVE-2021-44228). Run by MITRE / the CVE Program."),
                ("NVD + CPE", "US NIST's vulnerability database; adds CVSS scores and affected products (CPE) to CVEs."),
                ("OSV + GHSA", "Vulnerability database for open-source packages with exact affected version ranges per "
                               "ecosystem. GHSA: GitHub advisory ID."),
                ("CVSS", "Severity score (0–10, FIRST). Critical ≥ 9.0, High ≥ 7.0. Measures impact, not likelihood."),
                ("EPSS", "Probability of exploitation in the next 30 days (FIRST); updated daily."),
                ("KEV", "CISA catalogue of vulnerabilities confirmed as exploited in the wild — fix these first."),
                ("SBOM", "Software Bill of Materials: which component, which version, from where."),
                ("CycloneDX / SPDX", "The two standard SBOM formats: CycloneDX (OWASP), SPDX (Linux Foundation, ISO/IEC 5962)."),
                ("PURL / VEX", "PURL: package identifier (pkg:npm/lodash@4.17.21). VEX: \"are we affected by this "
                               "vulnerability\" statement.")]),
     "foot": L("Önceliklendirme mantığımız: zararlı paket → KEV → şiddet (CVSS) → zafiyetli fonksiyon çağrılıyor → "
               "EPSS. CVSS \"ne kadar kötü\", EPSS \"ne kadar olası\", KEV \"şu an istismar ediliyor\" sorusunu cevaplar.",
               "Our prioritisation: malicious package → KEV → severity (CVSS) → vulnerable function called → EPSS. "
               "CVSS answers \"how bad\", EPSS \"how likely\", KEV \"exploited right now\".")},

    {"title": L("Regülasyonlar ve standartlar", "Regulations and standards"),
     "grid": L([("ABD EO 14028 (2021)", "Kamuya satılan yazılımda SBOM; NTIA SBOM asgari unsurları bu kapsamda yayımlandı."),
                ("AB CRA", "Cyber Resilience Act, (AB) 2024/2847: üreticiye SBOM ve zafiyet yönetimi. Zafiyet bildirimi "
                                            "Eylül 2026, ana yükümlülükler Aralık 2027."),
                ("AB NIS2", "Kritik ve önemli kuruluşlarda tedarik zinciri güvenliği risk yönetiminin parçası."),
                ("AB DORA (Ocak 2025)", "Finans kuruluşlarında BİT riski ve üçüncü taraf (tedarikçi) risk yönetimi."),
                ("PCI DSS 4.0", "6.3.2: üçüncü taraf yazılım bileşenleri envanteri. 6.3.3: kritik yamaların bir ay içinde "
                                "uygulanması."),
                ("Türkiye", "BDDK Bilgi Sistemleri Yönetmeliği ve CBDDO Bilgi ve İletişim Güvenliği Rehberi: güvenli "
                            "yazılım ve tedarikçi riski. SCA çıktısı uyum için destekleyici kanıttır.")],
               [("US EO 14028 (2021)", "SBOM for software sold to government; the NTIA SBOM minimum elements followed."),
                ("EU CRA", "Cyber Resilience Act, (EU) 2024/2847: SBOM and vulnerability handling for manufacturers. "
                                            "Vulnerability reporting Sept 2026, main obligations Dec 2027."),
                ("EU NIS2", "Supply-chain security as part of risk management for essential and important entities."),
                ("EU DORA (Jan 2025)", "ICT risk and third-party (supplier) risk management for financial entities."),
                ("PCI DSS 4.0", "6.3.2: inventory of third-party software components. 6.3.3: critical patches within "
                                "one month."),
                ("Türkiye", "BDDK IS Regulation and the DTO Information and Communication Security Guide: secure "
                            "software and supplier risk. SCA output is supporting evidence for compliance.")]),
     "foot": L("Bu slayt hukuki görüş değildir; ilgili maddeler müşterinin uyum ekibiyle birlikte teyit edilmelidir.",
               "This slide is not legal advice; the relevant clauses should be confirmed with the customer's "
               "compliance team.")},

    {"title": L("scakit: nasıl çalışır?", "scakit: how it works"),
     "flow": L(["Girdiler\nkaynak · lock · APK/IPA\nimaj · URL · MSI",
                "Birleşik envanter\nkanıt + güven\nseviyesi",
                "Eşleştirme\nOSV · NVD\n(çevrimdışı)",
                "Önceliklendirme\nKEV · EPSS · CVSS\nkullanım analizi",
                "Rapor\nPDF · Word · HTML\nSBOM · CSV"],
               ["Inputs\nsource · lock · APK/IPA\nimage · URL · MSI",
                "Unified inventory\nevidence +\nconfidence",
                "Matching\nOSV · NVD\n(offline)",
                "Prioritisation\nKEV · EPSS · CVSS\nusage analysis",
                "Report\nPDF · Word · HTML\nSBOM · CSV"]),
     "foot": L("Zafiyet veritabanı yerel kopyadır (470.000+ OSV kaydı, NVD, EPSS, KEV); analiz internetsiz yapılabilir.",
               "The vulnerability database is a local copy (470,000+ OSV records, NVD, EPSS, KEV); analysis can run "
               "fully offline.")},

    {"title": L("Desteklenen hedefler", "Supported targets"),
     "grid": L([("Web", "JS imzaları, CDN, source map, açık dosyalar, sunucu başlıkları"),
                ("API", "Lock dosyaları, komut çıktıları, sunucu başlıkları"),
                ("Android", "APK/AAB: DEX, androidx/Firebase sürümleri, native .so"),
                ("iOS", "IPA: framework'ler, native kütüphaneler, React Native, Flutter"),
                ("Masaüstü", "MSI/EXE/DMG: .NET DLL, Electron, native DLL, gömülü JRE"),
                ("Container / OS", "docker/OCI imajı, Debian, Ubuntu, Alpine, RHEL, Rocky, Alma")],
               [("Web", "JS signatures, CDN, source maps, exposed files, server headers"),
                ("API", "Lock files, command outputs, server headers"),
                ("Android", "APK/AAB: DEX, androidx/Firebase versions, native .so"),
                ("iOS", "IPA: frameworks, native libraries, React Native, Flutter"),
                ("Desktop", "MSI/EXE/DMG: .NET DLLs, Electron, native DLLs, bundled JRE"),
                ("Container / OS", "docker/OCI image, Debian, Ubuntu, Alpine, RHEL, Rocky, Alma")]),
     "foot": L("Ekosistemler: npm, PyPI, Maven/Gradle, Go, NuGet, Composer, Cargo, RubyGems, Pub, CocoaPods, SwiftPM",
               "Ecosystems: npm, PyPI, Maven/Gradle, Go, NuGet, Composer, Cargo, RubyGems, Pub, CocoaPods, SwiftPM")},

    {"title": L("Fark yaratan özellikler", "What makes it different"),
     "bullets": L(
         ["Whitebox ve blackbox tek envanterde, tek raporda",
          "Çevrimdışı: kaynak kod ve envanter dışarı çıkmaz — banka ve kamu ortamlarına uygun",
          "Önceliklendirme: önce aktif istismar edilenler (KEV), sonra şiddet ve istismar olasılığı",
          "Her tespit kanıtı ve güven seviyesiyle; tahmini sürümler açıkça işaretlenir",
          "Kullanım analizi: paket kodda kullanılıyor mu; Go'da zafiyetli fonksiyon çağrılıyor mu",
          "Danışmanlık çıktısı: TR/EN PDF ve düzenlenebilir Word rapor + SBOM"],
         ["Whitebox and blackbox in one inventory, one report",
          "Offline: source code and inventory never leave — fits banking and public sector environments",
          "Prioritisation: known exploited (KEV) first, then severity and exploit probability",
          "Every detection comes with evidence and a confidence level; estimated versions are flagged",
          "Usage analysis: is the package used in code; in Go, is the vulnerable function called",
          "Consultancy output: TR/EN PDF and editable Word report + SBOM"])},

    {"title": L("Kullanım: 4 komut", "Usage: 4 commands"),
     "code": ("scakit init eng --name \"Banka X SCA\" --client \"Banka X\"\n"
              "scakit add eng ./kaynak-kod  app.apk  app.ipa  https://test.bankax.com.tr\n"
              "scakit match eng\n"
              "scakit report eng --lang tr          # pdf, docx, html, cdx, csv"),
     "foot": L("Ayrıca: policy (lisans politikası) · enrich (tedarik zinciri) · suppress (kabul edilen risk / yanlış "
               "pozitif)",
               "Also: policy (license policy) · enrich (supply chain) · suppress (accepted risk / false positive)")},

    {"title": L("Süreç ve doküman seti", "Process and document set"),
     "steps": L(["Satış\n5 soru", "Doküman\nkart / form\n+ kılavuz", "Teslim\nşifreli arşiv\nkontrol",
                 "Analiz\nscakit", "Kalite\nkontrol", "Rapor\nsunum\nimha"],
                ["Sales\n5 questions", "Documents\ncard / form\n+ guide", "Hand-over\nencrypted\narchive check",
                 "Analysis\nscakit", "Quality\ncontrol", "Report\npresentation\ndisposal"]),
     "foot": L("Müşteriye: tek uygulama → senaryo kartı (Web, API, Mobil, Masaüstü, Container); birden fazla → "
               "Ön Gereksinimler Formu; her durumda Veri Hazırlama Kılavuzu",
               "To the customer: single app → scenario card (Web, API, Mobile, Desktop, Container); several → "
               "Prerequisites Form; always the Data Preparation Guide")},

    {"title": L("Satışta ve piyasada avantajımız", "Our advantage in sales and the market"),
     "bullets": L(
         ["Pentest'e doğal ek hizmet: mobil pentestte APK ile hemen SCA, web pentestte aynı hedefle",
          "Kaynak kodunu vermek istemeyen müşteriye \"Önerilen\" seviye: yalnızca lock dosyaları",
          "Regülasyon dilinde çıktı: SBOM (CycloneDX / SPDX), lisans ve tedarik zinciri raporu",
          "Kurum içi / VDI'da internetsiz çalışma — hassas sektörlerde engeli kaldırır",
          "Ürün lisansı satmıyoruz: analiz + yorum + düzeltme planı + sunum (danışmanlık değeri)",
          "Tekrarlanabilir: aynı iş klasörüyle periyodik yeniden analiz → sürekli hizmet geliri"],
         ["Natural add-on to pentests: SCA right away from the APK in mobile tests, same target in web tests",
          "For customers who won't share source code: the \"Recommended\" level — lock files only",
          "Output in regulatory language: SBOM (CycloneDX / SPDX), license and supply-chain report",
          "Runs offline on premises / in VDI — removes the blocker in sensitive sectors",
          "We don't sell a product licence: analysis + interpretation + remediation plan + presentation",
          "Repeatable: periodic re-analysis with the same engagement → recurring service revenue"])},

    {"title": L("Bilinen sınırlar (müşteriye dürüstçe)", "Known limits (be upfront with customers)"),
     "bullets": L(
         ["Blackbox sunucu tarafı kütüphaneleri göremez; bulgu olmaması \"güvenli\" demek değildir",
          "Fonksiyon seviyesi erişilebilirlik yalnızca Go'da; diğer dillerde import seviyesinde",
          "Sunucu yazılımı / native eşleştirme NVD'de seçili ürünlerle sınırlı; dağıtım paketleri düşük güvenli",
          "App Store IPA'sı şifreli: geliştirici IPA'sı gerekir; Flutter sürümleri için pubspec.lock gerekir",
          "Lisans bulguları hukuki görüş değildir"],
         ["Blackbox cannot see server-side libraries; no findings does not mean \"secure\"",
          "Function-level reachability only for Go; import level for other languages",
          "Server / native matching via NVD is limited to selected products; distro packages are low confidence",
          "App Store IPAs are encrypted: a developer IPA is needed; Flutter versions need pubspec.lock",
          "License findings are not legal advice"])},

    {"kind": "end",
     "title": L("Teşekkürler", "Thank you"),
     "sub": L("Kaynaklar: Operasyon ve Kullanım Rehberi · scakit_KOMUTLAR.md · müşteri dokümanları",
              "Resources: Operations and Usage Guide · scakit_KOMUTLAR.md · customer documents")},
]


def text(slide, x, y, w, h, value, size=18, bold=False, color=DARK, align=PP_ALIGN.LEFT, font="Calibri"):
    tb = slide.shapes.add_textbox(x, y, w, h)
    tf = tb.text_frame
    tf.word_wrap = True
    lines = value.split("\n") if isinstance(value, str) else value
    for i, line in enumerate(lines):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.alignment = align
        r = p.add_run()
        r.text = line
        r.font.size, r.font.bold, r.font.color.rgb, r.font.name = Pt(size), bold, color, font
    return tb


def rect(slide, x, y, w, h, fill, shape=MSO_SHAPE.RECTANGLE, line=None):
    s = slide.shapes.add_shape(shape, x, y, w, h)
    s.fill.solid()
    s.fill.fore_color.rgb = fill
    if line:
        s.line.color.rgb = line
    else:
        s.line.fill.background()
    s.shadow.inherit = False
    return s


def header(slide, title, n, total, lang):
    rect(slide, 0, 0, W, Emu(int(0.32 * CM)), NAVY)
    text(slide, Emu(int(1.4 * CM)), Emu(int(0.8 * CM)), W - Emu(int(2.8 * CM)), Emu(int(1.6 * CM)), title, 30, True, NAVY)
    rect(slide, Emu(int(1.4 * CM)), Emu(int(2.45 * CM)), Emu(int(2.2 * CM)), Emu(int(0.12 * CM)), ORANGE)
    text(slide, Emu(int(1.4 * CM)), H - Emu(int(1.0 * CM)), Emu(int(20 * CM)), Emu(int(0.6 * CM)),
         "SCA · scakit", 10, False, GREY)
    text(slide, W - Emu(int(4.4 * CM)), H - Emu(int(1.0 * CM)), Emu(int(3 * CM)), Emu(int(0.6 * CM)),
         f"{n} / {total}", 10, False, GREY, PP_ALIGN.RIGHT)


def bullets(slide, items, x, y, w, h, size=20):
    tb = slide.shapes.add_textbox(x, y, w, h)
    tf = tb.text_frame
    tf.word_wrap = True
    for i, it in enumerate(items):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.space_after = Pt(10)
        r = p.add_run()
        r.text = "▪  "
        r.font.size, r.font.color.rgb, r.font.name = Pt(size), ORANGE, "Calibri"
        r = p.add_run()
        r.text = it
        r.font.size, r.font.color.rgb, r.font.name = Pt(size), DARK, "Calibri"


def foot_note(slide, value):
    y = H - Emu(int(2.9 * CM))
    rect(slide, Emu(int(1.4 * CM)), y, W - Emu(int(2.8 * CM)), Emu(int(1.6 * CM)), LIGHT)
    text(slide, Emu(int(1.8 * CM)), y + Emu(int(0.2 * CM)), W - Emu(int(3.6 * CM)), Emu(int(1.0 * CM)), value, 13, False,
         GREY)


def build(lang: str, out: Path):
    prs = Presentation()
    prs.slide_width, prs.slide_height = W, H
    blank = prs.slide_layouts[6]
    total = len(DECK)
    x0, top = Emu(int(1.4 * CM)), Emu(int(3.2 * CM))
    cw = W - Emu(int(2.8 * CM))
    for n, s in enumerate(DECK, 1):
        sl = prs.slides.add_slide(blank)
        t = s["title"][lang]
        if s.get("kind") in ("title", "end"):
            rect(sl, 0, 0, W, H, NAVY)
            rect(sl, Emu(int(1.6 * CM)), Emu(int(7.6 * CM)), Emu(int(3 * CM)), Emu(int(0.16 * CM)), ORANGE)
            text(sl, Emu(int(1.6 * CM)), Emu(int(4.0 * CM)), Emu(int(28 * CM)), Emu(int(3.4 * CM)), t, 40, True, WHITE)
            text(sl, Emu(int(1.6 * CM)), Emu(int(8.2 * CM)), Emu(int(28 * CM)), Emu(int(2.4 * CM)), s["sub"][lang], 20,
                 False, RGBColor(0xD6, 0xDE, 0xE8))
            if s["kind"] == "title":
                text(sl, Emu(int(1.6 * CM)), H - Emu(int(2.2 * CM)), Emu(int(20 * CM)), Emu(int(0.8 * CM)),
                     "İç eğitim / Internal training" if lang == "tr" else "Internal training", 12, False,
                     RGBColor(0xD6, 0xDE, 0xE8))
            continue
        header(sl, t, n, total, lang)
        if "bullets" in s:
            bullets(sl, s["bullets"][lang], x0, top, cw, H - top - Emu(int(1.6 * CM)))
        if "cols" in s:
            colw = (cw - Emu(int(1.0 * CM))) // 2
            for i, (head, items) in enumerate(s["cols"]):
                x = x0 + i * (colw + Emu(int(1.0 * CM)))
                rect(sl, x, top, colw, Emu(int(1.1 * CM)), NAVY if i == 0 else ORANGE)
                text(sl, x + Emu(int(0.4 * CM)), top + Emu(int(0.15 * CM)), colw, Emu(int(0.8 * CM)), head[lang], 18,
                     True, WHITE)
                bullets(sl, items[lang], x, top + Emu(int(1.5 * CM)), colw, Emu(int(9 * CM)), 16)
        if "boxes" in s:
            k = len(s["boxes"])
            gap = Emu(int(0.6 * CM))
            bw = (cw - gap * (k - 1)) // k
            bh = Emu(int(7.4 * CM)) if "foot" in s else Emu(int(9.4 * CM))
            for i, (head, body) in enumerate(s["boxes"]):
                x = x0 + i * (bw + gap)
                rect(sl, x, top, bw, bh, LIGHT)
                rect(sl, x, top, bw, Emu(int(0.14 * CM)), ORANGE if i == k - 1 and k == 3 else NAVY)
                text(sl, x + Emu(int(0.4 * CM)), top + Emu(int(0.5 * CM)), bw - Emu(int(0.8 * CM)), Emu(int(1.2 * CM)),
                     head[lang], 22 if k <= 3 else 18, True, NAVY)
                text(sl, x + Emu(int(0.4 * CM)), top + Emu(int(2.0 * CM)), bw - Emu(int(0.8 * CM)), bh - Emu(int(2.3 * CM)),
                     body[lang], 16 if k <= 3 else 15, False, DARK)
        if "flow" in s or "steps" in s:
            items = (s.get("flow") or s.get("steps"))[lang]
            k = len(items)
            gap = Emu(int(0.35 * CM))
            bw = (cw - gap * (k - 1)) // k
            y = top + Emu(int(1.4 * CM))
            for i, it in enumerate(items):
                x = x0 + i * (bw + gap)
                shape = MSO_SHAPE.ROUNDED_RECTANGLE
                b = rect(sl, x, y, bw, Emu(int(4.2 * CM)), NAVY if i % 2 == 0 else RGBColor(0x2E, 0x56, 0x86), shape)
                tf = b.text_frame
                tf.word_wrap = True
                for j, line in enumerate(it.split("\n")):
                    p = tf.paragraphs[0] if j == 0 else tf.add_paragraph()
                    p.alignment = PP_ALIGN.CENTER
                    r = p.add_run()
                    r.text = line
                    r.font.size = Pt(15 if j == 0 else 12)
                    r.font.bold = j == 0
                    r.font.color.rgb = WHITE
                    r.font.name = "Calibri"
                if i < k - 1:
                    a = rect(sl, x + bw + Emu(int(0.02 * CM)), y + Emu(int(1.8 * CM)), gap - Emu(int(0.04 * CM)),
                             Emu(int(0.6 * CM)), ORANGE, MSO_SHAPE.RIGHT_ARROW)
                    a.text_frame.text = ""
        if "grid" in s:
            items = s["grid"][lang]
            cols, gap = 3, Emu(int(0.5 * CM))
            bw = (cw - gap * (cols - 1)) // cols
            rows = (len(items) + cols - 1) // cols
            avail = H - top - Emu(int((3.4 if "foot" in s else 1.8) * CM))
            bh = min((avail - gap * (rows - 1)) // rows, Emu(int(5.2 * CM)))
            body_size = 14 if rows < 3 else 13
            for i, (head, body) in enumerate(items):
                x = x0 + (i % cols) * (bw + gap)
                y = top + (i // cols) * (bh + gap)
                rect(sl, x, y, bw, bh, LIGHT)
                rect(sl, x, y, Emu(int(0.14 * CM)), bh, ORANGE)
                text(sl, x + Emu(int(0.5 * CM)), y + Emu(int(0.3 * CM)), bw - Emu(int(0.8 * CM)), Emu(int(0.9 * CM)),
                     head, 20, True, NAVY)
                text(sl, x + Emu(int(0.5 * CM)), y + Emu(int(1.3 * CM)), bw - Emu(int(0.8 * CM)), bh - Emu(int(1.4 * CM)),
                     body, body_size, False, DARK)
        if "code" in s:
            ch = Emu(int(4.6 * CM))
            rect(sl, x0, top + Emu(int(0.6 * CM)), cw, ch, RGBColor(0x1D, 0x24, 0x30))
            code = s["code"] if lang == "tr" else s["code"].replace("kaynak-kod", "source-code")
            text(sl, x0 + Emu(int(0.6 * CM)), top + Emu(int(1.0 * CM)), cw - Emu(int(1.2 * CM)), ch - Emu(int(0.6 * CM)),
                 code, 17, False, RGBColor(0xE6, 0xED, 0xF3), font="Consolas")
        if "foot" in s:
            foot_note(sl, s["foot"][lang])
    prs.core_properties.title = DECK[0]["title"][lang]
    prs.save(str(out))


if __name__ == "__main__":
    outdir = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    outdir.mkdir(parents=True, exist_ok=True)
    for lang, name in (("tr", "SCA_scakit_Tanitim_TR.pptx"), ("en", "SCA_scakit_Introduction_EN.pptx")):
        build(lang, outdir / name)
        print("ok", name)
