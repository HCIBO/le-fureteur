TITLE = "SCA Hizmeti — Operasyon ve Kullanım Rehberi"
SUBTITLE = "Satıştan teslime süreç ve scakit kullanımı"


def H(t):
    return {"type": "sub", "title": t}


def P(t):
    return {"type": "para", "text": t}


def C(code):
    return {"type": "code", "code": code}


def B(*items):
    return {"type": "bullets", "items": list(items)}


def CL(*items):
    return {"type": "checklist", "items": list(items)}


def N(t):
    return {"type": "note", "text": t}


def T(header, rows, widths):
    return {"type": "table", "header": header, "rows": rows, "widths": widths}


FORM = "SCA_Hizmeti_On_Gereksinimler_TR.pdf"
GUIDE = "SCA_Hizmeti_Veri_Hazirlama_Kilavuzu_TR.pdf"

SECTIONS = [
    {"title": "1. Bu Rehber ve Hizmetin Bileşenleri", "blocks": [
        P("Bu rehber, bir SCA (Yazılım Bileşen Analizi) işinin satıştan teslime kadar nasıl yürütüleceğini ve "
          "**scakit** aracının nasıl kullanılacağını anlatır. Hedef kitle: satış ekibi (Bölüm 2–3), proje sorumlusu "
          "(Bölüm 3–6) ve analistler (tüm bölümler)."),
        P("Hizmet iki parçadan oluşur:"),
        B("**Müşteri dokümanları** (Masaüstü / `SCA_Hizmeti_On_Gereksinimler` klasörü): müşterinin ne vermesi "
          "gerektiğini ve nasıl hazırlayacağını anlatan PDF/Word dosyaları.",
          "**scakit aracı** (`~/scakit`): müşteriden gelen dosyaları ve hedefleri analiz edip bileşen envanterini, "
          "zafiyetleri, lisans ve tedarik zinciri risklerini çıkarır; PDF / Word / HTML rapor ve SBOM üretir."),
        T(["Rol", "Sorumluluk"], [
            ["Satış", "İhtiyacı netleştirme (Bölüm 3.1 soruları), paket/seviye seçimi, doğru dokümanın gönderilmesi"],
            ["Proje sorumlusu (PS)", "Açılış toplantısı, teslim alma kontrolü, takvim, müşteri iletişimi, kapanış ve "
                                     "veri imhası"],
            ["Analist", "scakit ile analiz, kalite kontrol (yanlış pozitif / kabul edilen risk), raporun son hali"],
        ], [40, 140]),
    ]},
    {"title": "2. Doküman Seti: Hangi Dosya Ne Zaman Gönderilir?", "blocks": [
        P("Tüm dokümanlar Türkçe ve İngilizce, PDF (doldurulabilir) ve Word olarak hazırdır. Müşteriye her zaman "
          "**bir talep dokümanı** (form veya senaryo kartı) **+ Veri Hazırlama Kılavuzu** gönderilir."),
        T(["Doküman", "Ne zaman", "Amacı"], [
            [f"Ön Gereksinimler Formu (`{FORM}`)",
             "Firma geneli, birden fazla uygulama, karışık kapsam",
             "SCA'yı tanıtır (whitebox / blackbox / hibrit); tüm gereksinimleri madde kodlarıyla (WB-, BB-, GZ-) "
             "toplar; imzalı onay alır"],
            ["Senaryo Kartı: Mobil", "Yalnızca bir mobil uygulama (genelde mobil pentest ile)",
             "\"APK/IPA yeter mi?\" sorusunun cevabı, 3 seviye, MOB- maddeleri, hazırlama komutları"],
            ["Senaryo Kartı: Web", "Yalnızca bir web uygulaması", "Aynı yapı, WEB- maddeleri"],
            ["Senaryo Kartı: API", "Yalnızca bir API / web servisi", "Aynı yapı, API- maddeleri"],
            ["Senaryo Kartı: Masaüstü", "Masaüstü (thick client) uygulaması", "Aynı yapı, DSK- maddeleri"],
            ["Senaryo Kartı: Container / Altyapı", "Container imajları, Kubernetes, sunucular", "Aynı yapı, INF- maddeleri"],
            [f"Veri Hazırlama Kılavuzu (`{GUIDE}`)", "Her işte, talep dokümanıyla birlikte",
             "Her maddenin (WB-xx, BB-xx) nasıl hazırlanıp teslim edileceği: komutlar, klasör yapısı, şifreleme, SSS"],
        ], [52, 50, 78]),
        N("Kural: Tek uygulama → ilgili senaryo kartı. Birden fazla uygulama veya farklı türler (ör. mobil + web) → "
          "her tür için kendi kartı **ya da** tek bir Ön Gereksinimler Formu. Müşteri tek doküman doldurmak isterse "
          "Form tercih edilir; kartlar daha kısa ve anlaşılırdır. Her iki durumda da Kılavuz eklenir."),
        P("Kart ve formdaki madde kodları birbirine ve Kılavuz'a bağlıdır: ör. kartta `MOB-04 … (WB-12)` yazan madde, "
          "Kılavuz'da **WB-12** başlığında adım adım anlatılır. Müşteri sorduğunda bu kodla yönlendirin."),
    ]},
    {"title": "3. Senaryo 1 — Müşteri SCA Paketi Satın Aldı: Süreç Adım Adım", "blocks": [
        H("3.1 Satış: ihtiyacı netleştirme (5 soru)"),
        P("Satış görüşmesinde bu beş sorunun cevabı hangi dokümanın gönderileceğini ve işin seviyesini belirler:"),
        T(["Soru", "Neden önemli"], [
            ["Hangi uygulamalar? Tür: web, API, mobil, masaüstü, container?", "Hangi senaryo kartı(ları) / form"],
            ["Kaynak kod veya bağımlılık dosyası paylaşılabilir mi?",
             "Blackbox (yalnızca hedef) / Önerilen (lock dosyaları) / Tam (kaynak kod) seviyesi"],
            ["Analiz nerede yapılacak: bizde mi, müşteri ortamında (VDI) mı?", "Yerinde iş: araç + veritabanı aktarımı "
                                                                                  "(Bölüm 5.2)"],
            ["Rapor dili, SBOM formatı (CycloneDX / SPDX), bulgu dışa aktarımı?", "Form GN-02 … GN-04"],
            ["Lisans politikası var mı? Paket adları dış servise sorgulanabilir mi?",
             "WB-40 lisans değerlendirmesi; `--online` zenginleştirme için yazılı onay"],
        ], [95, 85]),
        H("3.2 Uçtan uca süreç"),
        T(["#", "Adım", "Sorumlu", "Çıktı"], [
            ["1", "İhtiyaç netleştirme (3.1), paket / seviye teklifi", "Satış", "Teklif"],
            ["2", "Doğru dokümanların gönderilmesi (Bölüm 2 kuralı) + e-posta şablonu (Ek C)", "Satış / PS",
             "Kart(lar) veya Form + Kılavuz"],
            ["3", "Açılış toplantısı: maddelerin üzerinden geçilmesi, teknik irtibat, takvim, teslim yöntemi", "PS",
             "Doldurulmuş kart/form, NDA"],
            ["4", "Blackbox kapsamı varsa: imzalı test izni (BB-10), WAF/SOC koordinasyonu (BB-12)", "PS",
             "Yetki yazısı"],
            ["5", "Müşterinin dosyaları hazırlaması (Kılavuz) ve şifreli teslim", "Müşteri", "Şifreli arşiv / erişim"],
            ["6", "Teslim alma kontrolü (Bölüm 6.1): bütünlük, eksik madde, lock dosyaları", "PS / Analist",
             "Eksik listesi veya onay"],
            ["7", "Analiz: scakit ile ekleme, eşleştirme, zenginleştirme (Bölüm 6)", "Analist", "Envanter + bulgular"],
            ["8", "Kalite kontrol: güven seviyeleri, yanlış pozitif / kabul edilen riskler (Bölüm 7)", "Analist",
             "Gözden geçirilmiş bulgular"],
            ["9", "Rapor üretimi ve son okuma (Bölüm 8)", "Analist / PS", "PDF, Word, SBOM, CSV"],
            ["10", "Teslim, sunum, kapanış, veri imhası (Bölüm 9)", "PS", "Teslim ve imha tutanağı"],
        ], [8, 92, 30, 50]),
        H("3.3 Soru 1: Müşterinin bize iletmesi gerekenler ve hangi PDF'i gönderiyoruz?"),
        P("Gönderilecek PDF'i belirleyen tek şey **kapsam türü**dür. Karar tablosu:"),
        T(["Müşterinin söylediği", "Gönderilecek dosyalar"], [
            ["\"Mobil uygulamamız için SCA\"", "Senaryo Kartı: Mobil + Kılavuz"],
            ["\"Web sitemiz / portalımız için\"", "Senaryo Kartı: Web + Kılavuz"],
            ["\"API'lerimiz için\"", "Senaryo Kartı: API + Kılavuz"],
            ["\"Mobil uygulama ve arkasındaki API\"", "Mobil kartı + API kartı + Kılavuz"],
            ["\"Masaüstü uygulamamız\" / \"thick client\"", "Senaryo Kartı: Masaüstü + Kılavuz"],
            ["\"Container imajlarımız / Kubernetes\"", "Senaryo Kartı: Container / Altyapı + Kılavuz"],
            ["\"Tüm uygulamalarımız\" / birden fazla tür / emin değil", f"Ön Gereksinimler Formu + Kılavuz"],
        ], [80, 100]),
        P("Müşterinin her durumda ileteceği ortak bilgiler (karttaki 5–6. bölümler veya Formun 2, 5, 7. bölümleri): "
          "iletişim ve teknik irtibat, seçilen seviye, dosya teslim yöntemi, NDA, rapor dili, imza. Blackbox kapsamda "
          "ek olarak imzalı test izni, hedef listesi ve test zaman aralığı."),
    ]},
    {"title": "4. Senaryo 2 — \"Mobil ve Web için Whitebox SCA\"", "blocks": [
        H("4.1 Gönderilecek dosyalar"),
        B("`Senaryo_Kartlari/SCA_Senaryo_Karti_Mobil_TR.pdf`",
          "`Senaryo_Kartlari/SCA_Senaryo_Karti_Web_TR.pdf`",
          f"`{GUIDE}` (yol haritası buradan çıkar — 4.3)",
          "Mobil uygulamanın bağlandığı API de kapsamdaysa: `SCA_Senaryo_Karti_API_TR.pdf`"),
        P("Alternatif: müşteri tek doküman isterse Ön Gereksinimler Formu gönderilir; doldurulacak bölümler 2, 3 "
          "(whitebox), 5 ve 7'dir. Formda Bölüm 3.2 teknoloji tablosunda mobil ve web teknolojilerinin her biri "
          "işaretlenir."),
        N("Whitebox iki seviyedir: Kartlarda \"whitebox\" talebi **Tam** seviyeye karşılık gelir (kaynak kod "
          "dahil). Müşteri kaynak kodu paylaşamıyorsa **Önerilen** seviye (yalnızca lock dosyaları / komut "
          "çıktıları) neredeyse aynı bağımlılık sonucunu verir; yalnızca koda gömülü kütüphaneler ve kullanım analizi "
          "eksik kalır. Bunu satış aşamasında netleştirin."),
        H("4.2 Müşterinin iletmesi gerekenler (Tam seviye)"),
        T(["Kod", "Ne", "Seviye", "Nasıl hazırlanır (Kılavuz)"], [
            ["MOB-01..03", "Platform, teknoloji (Native / Flutter / React Native), mağaza bağlantısı ve sürüm no",
             "Minimum", "Karta yazılır"],
            ["MOB-04", "Android APK / AAB (mağazadaki sürüm)", "Minimum", "WB-12 (Bölüm 5)"],
            ["MOB-05", "iOS: geliştirme ekibinin ürettiği IPA (App Store'dan indirilen değil)", "Minimum",
             "WB-12 (Bölüm 5)"],
            ["MOB-10", "Android bağımlılık listesi (Gradle release çıktısı + build.gradle)", "Önerilen",
             "Kart Bölüm 4, Kılavuz Bölüm 4"],
            ["MOB-11", "iOS: Podfile.lock / Package.resolved", "Önerilen", "Kılavuz Bölüm 4 (iOS)"],
            ["MOB-12", "Flutter: pubspec.lock; React Native: package-lock / yarn.lock", "Önerilen", "Kılavuz Bölüm 4"],
            ["MOB-13", "Elle eklenen kütüphaneler (.aar, .jar, .framework)", "Önerilen", "WB-32 (Bölüm 7)"],
            ["MOB-20", "Mobil kaynak kod + mağazadaki sürümün commit / tag'i", "Tam", "WB-01, WB-02 (Bölüm 3)"],
            ["WEB-01..04", "Web adresleri / ortam, ön yüz ve sunucu teknolojisi (whitebox'ta URL bilgi amaçlı)",
             "Minimum", "Karta yazılır"],
            ["WEB-10", "Ön yüz: package.json + lock dosyası", "Önerilen", "Kılavuz Bölüm 4"],
            ["WEB-11", "Sunucu tarafı lock dosyaları / komut çıktısı (Maven, Gradle, .NET, PHP, Python...)", "Önerilen",
             "Kılavuz Bölüm 4"],
            ["WEB-12", "Sunucu yazılımı ve runtime sürümleri (OS paketleri dahil)", "Önerilen", "WB-23 (Bölüm 6)"],
            ["WEB-20", "Web kaynak kod + canlı sürümün commit / tag'i", "Tam", "WB-01, WB-02 (Bölüm 3)"],
            ["WEB-21", "Container imajı veya dağıtılan paket (WAR, publish dizini)", "Tam", "WB-10, WB-11 (Bölüm 5)"],
            ["MOB/WEB-90..92", "Teslim yöntemi, NDA, rapor dili", "Hepsi", "Kılavuz Bölüm 2"],
        ], [24, 84, 20, 52]),
        H("4.3 Yol haritası: müşteri hangi dosyadan plan çıkarır?"),
        P(f"Müşterinin teknik ekibi planını **Veri Hazırlama Kılavuzu**'ndan (`{GUIDE}`) çıkarır. Kılavuz, kartın "
          "her maddesini bir bölüme bağlar; aşağıdaki sıra önerilir:"),
        T(["Sıra", "Kılavuz bölümü", "İş", "Kim (müşteri tarafı)"], [
            ["1", "Bölüm 2 — Paketleme", "Klasör yapısını oluştur (`SCA_<Firma>_<tarih>/`)", "Proje sorumlusu"],
            ["2", "Bölüm 3 — WB-02", "Mağaza ve canlı web sürümünün commit / tag'ini tespit et", "Mobil + web ekip lideri"],
            ["3", "Bölüm 3 — WB-01", "Kaynak kod arşivleri (submodule / LFS dikkat)", "Geliştiriciler"],
            ["4", "Bölüm 4", "Lock dosyaları; yoksa build ortamında komut çıktıları", "Geliştiriciler / DevOps"],
            ["5", "Bölüm 5 — WB-10..12", "APK / IPA / container imajı / dağıtılan paket", "Mobil ekip / DevOps"],
            ["6", "Bölüm 6 — WB-23", "Sunucu ve runtime sürüm bilgisi", "Sistem ekibi"],
            ["7", "Bölüm 7 — WB-30..33", "Dahili paket listesi (dependency confusion için), elle eklenen kütüphaneler",
             "Mimari / DevOps"],
            ["8", "Bölüm 8 — WB-40", "Lisans politikası (varsa)", "Hukuk / mimari"],
            ["9", "Bölüm 2.3–2.4 + Bölüm 12", "SHA256SUMS, AES-256 şifreli arşiv, son kontrol listesi, teslim",
             "Proje sorumlusu"],
        ], [12, 40, 88, 40]),
        P("Örnek takvim (planlama amaçlı; işin büyüklüğüne göre değişir): müşteri hazırlığı genelde birkaç iş "
          "günü sürer; teslim alma kontrolü aynı gün yapılır; analiz ve kalite kontrol kapsamın büyüklüğüne bağlıdır; "
          "rapor son okuması ve sunum ayrı bir gün olarak planlanır."),
    ]},
    {"title": "5. scakit Kurulumu ve Veritabanı", "blocks": [
        H("5.1 Kurulum (analist makinesi)"),
        C("cd ~/scakit\n"
          "pip install -e \".[report]\"        # reportlab + python-docx (PDF / Word rapor)\n"
          "scakit db update                  # OSV + EPSS + KEV + NVD seçili ürünler (ilk kurulum ~10 dk)\n"
          "scakit db status                  # kayıt sayıları ve son güncelleme tarihleri\n"
          "python3 -m unittest discover -s tests -t .   # araç sağlık kontrolü"),
        B("Gereksinimler: Python 3.10+, ~3 GB disk, `7z` (masaüstü kurulum dosyaları için).",
          "NVD indirmesi API anahtarı olmadan yavaştır; `export NVD_API_KEY=...` ile hızlanır.",
          "Ubuntu tabanlı imajlar için: `scakit db update --ecosystems npm,PyPI,...,Ubuntu` (Ubuntu verisi ~750 MB).",
          "Her işe başlamadan önce `scakit db update` çalıştırın; raporun kapağında veritabanı tarihi yazar."),
        H("5.2 İnternetsiz (müşteri ortamı / VDI) çalışma"),
        C("# internetli makinede\n"
          "scakit db download ./vulndb-paket\n"
          "# klasörü + ~/scakit kaynak kodunu müşteri ortamına aktarın, orada:\n"
          "pip install -e \".[report]\"         # gerekirse wheel dosyalarıyla çevrimdışı kurulum\n"
          "scakit db update --from-dir ./vulndb-paket\n"
          "# alternatif: hazır SQLite dosyasını kopyalayın\n"
          "export SCAKIT_DB=/yol/vulndb.sqlite"),
        N("Gizlilik: Varsayılan çalışma tamamen çevrimdışıdır; kod veya envanter dışarı gönderilmez. Tek istisna "
          "`scakit enrich --online` komutudur (paket adı / sürümü deps.dev, npm, PyPI'ye gider). Bu komutu yalnızca "
          "müşterinin yazılı onayı ile çalıştırın; kullanıldığında rapor bunu otomatik olarak belirtir."),
    ]},
    {"title": "6. Analiz: Senaryo 2 Üzerinden Adım Adım", "blocks": [
        H("6.1 Teslim alma kontrolü"),
        C("mkdir -p ~/isler/2026-11-BANKAX-SCA && cd ~/isler/2026-11-BANKAX-SCA\n"
          "7z x SCA_BankaX_2026-11-03.7z                    # parola ayrı kanaldan (SMS / telefon)\n"
          "sha256sum SCA_BankaX_2026-11-03.7z               # müşterinin ilettiği özetle karşılaştırın\n"
          "cd SCA_BankaX_2026-11-03 && sha256sum -c SHA256SUMS.txt | grep -v ': OK'   # bozuk/eksik dosya"),
        CL("Doldurulmuş ve imzalı kart / form, `00_BILGI.txt` (commit / tag, uygulama listesi) var",
           "Kullanılan her teknoloji için lock dosyası veya komut çıktısı var (MOB-10..12, WEB-10..11)",
           "APK ve IPA mağazadaki sürümle aynı; IPA geliştirici IPA'sı (FairPlay şifreli değil)",
           "Kaynak kod commit'i canlı / mağaza sürümüyle eşleşiyor (WB-02)",
           "`.env`, anahtar dosyaları, gerçek müşteri verisi gönderilmemiş; gönderildiyse müşteriye bildirin"),
        P("Eksik varsa müşteriye madde koduyla dönün: \"MOB-10 eksik — Kart Bölüm 4'teki Gradle komutunun çıktısı\"."),
        H("6.2 Engagement oluşturma ve politika"),
        C("scakit init ~/isler/2026-11-BANKAX-SCA/eng --name \"Banka X Mobil+Web SCA\" \\\n"
          "    --client \"Banka X A.Ş.\" --lang tr\n"
          "scakit policy eng --allowed MIT,Apache-2.0,BSD-3-Clause --denied AGPL-3.0-only   # WB-40 verildiyse"),
        H("6.3 Girdileri ekleme (her girdiye anlamlı bir --target verin)"),
        C("T=SCA_BankaX_2026-11-03\n"
          "scakit add eng $T/01_kaynak_kod/mobil   --target \"Mobil (kaynak)\"\n"
          "scakit add eng $T/01_kaynak_kod/web-ui  --target \"Web ön yüz\"\n"
          "scakit add eng $T/01_kaynak_kod/web-api --target \"Web API\"\n"
          "scakit add eng $T/02_bagimlilik_ciktilari --target \"Bağımlılık çıktıları\"\n"
          "scakit add eng $T/04_artefaktlar/app-release.aab --target \"Mobil (Android)\"\n"
          "scakit add eng $T/04_artefaktlar/BankaX.ipa      --target \"Mobil (iOS)\"\n"
          "scakit add eng $T/03_container/web-api_1.4.tar.gz --target \"Web API imajı\"\n"
          "scakit add eng $T/05_build_deploy/os-packages.txt --os Debian:12 --target \"Web sunucusu\""),
        B("Girdi türü otomatik algılanır: klasör / .zip / .tar.gz kaynak; .apk/.aab/.ipa mobil; `docker save` / OCI "
          "arşivi imaj; .msi/.exe masaüstü; http(s) adresi web. Gerekirse `--type` ile zorlayın.",
          "Kaynak klasör taranırken kullanım analizi (import) otomatik yapılır; içindeki APK / imaj / WAR dosyaları "
          "da kuyruğa alınır.",
          "Geliştirme/test bağımlılıkları varsayılan olarak hariçtir; müşteri WB-41'de \"Evet\" dediyse `--dev`.",
          "Aynı bileşen birden çok kaynaktan gelirse tek kayıtta birleşir; kanıtlar ve hedefler korunur.",
          "Whitebox işte ek olarak web blackbox doğrulaması isteniyorsa (yetki yazısı ile): "
          "`scakit add eng https://test.bankax.com.tr --delay 1 --max-pages 30`"),
        H("6.4 Tedarik zinciri ve eşleştirme"),
        C("scakit enrich eng --internal $T/06_ucuncu_taraf/dahili-paketler.csv            # çevrimdışı\n"
          "scakit enrich eng --internal $T/06_ucuncu_taraf/dahili-paketler.csv --online   # YAZILI ONAY ile\n"
          "scakit match eng"),
        P("`match` sonunda bileşen ve bulgu sayıları, KEV sayısı ve veritabanında kapsamı olmayan ekosistemler "
          "yazılır (CocoaPods için kapsam yoktur; bu normaldir)."),
    ]},
    {"title": "7. Kalite Kontrol: Bulguları Gözden Geçirme", "blocks": [
        P("Rapor müşteriye gitmeden önce analist şu kontrolleri yapar. Ara kontrol için hızlı rapor:"),
        C("scakit report eng --formats html,csv        # tarayıcıda HTML, Excel'de CSV ile inceleyin"),
        CL("Envanter sayısı makul mü? (ör. package-lock'taki paket sayısı ile karşılaştırın; çok düşükse eksik girdi)",
           "\"Kapsam Kısıtları\": lock dosyası olmayan projeler, sürümsüz bileşenler → müşteriden komut çıktısı isteyin",
           "Güveni \"Orta/Düşük\" bulgular: blackbox tahmini sürümler kanıt dosyasından (evidence/) doğrulandı mı?",
           "NVD bulgularında \"(Ubuntu)\" vb. dağıtım işareti → dağıtımın güvenlik duyurusundan teyit edin",
           "KEV işaretli bulgular tek tek kontrol edildi mi? (yönetici özetinde öne çıkar)",
           "Karartılmış APK notu varsa ve MOB-10 yoksa: sürümleri kesinleştirmek için Gradle çıktısı isteyin",
           "Lisans: \"Yasaklı / İnceleme\" listesi politika ile tutarlı mı? \"Belirlenemedi\" listesi makul mü?",
           "Tedarik zinciri: dahili registry paketleri ve bağımlılık karışıklığı bulguları müşteriyle paylaşıldı mı?"),
        H("7.1 Yanlış pozitif ve kabul edilen risk kaydı (WB-43)"),
        C("scakit suppress eng --id CVE-2021-44228 --component org.apache.logging.log4j:log4j-core \\\n"
          "    --kind accepted-risk --reason \"JNDI lookup kapalı; 2026-12 yükseltme planlı\" --by \"Müşteri: A. Kaya\"\n"
          "scakit suppress eng --id GHSA-xxxx-xxxx-xxxx --component jquery@3.3.1 \\\n"
          "    --kind false-positive --reason \"Dosya yalnızca /docs altında, uygulamada yüklenmiyor\"\n"
          "scakit suppress eng --list\n"
          "scakit match eng                              # kurallar eşleştirmede uygulanır"),
        B("Türler: `accepted-risk` (müşteri riski kabul etti), `false-positive` (tespit hatalı), `not-affected` "
          "(bileşen var ama zafiyetli kod yolu kullanılmıyor).",
          "Ayrılan bulgular silinmez; raporda \"Kabul Edilen Riskler ve Yanlış Pozitifler\" bölümünde gerekçesiyle "
          "listelenir.",
          "Gerekçesiz kayıt eklenmez; `--by` ile onaylayanı yazın. Kullanım analizi sonucu (\"import görülmedi\", "
          "\"fonksiyon çağrısı görülmedi\") tek başına bastırma gerekçesi değildir."),
    ]},
    {"title": "8. Raporlama ve Raporun Okunması", "blocks": [
        C("scakit report eng --lang tr                                    # html, pdf, docx, cdx, csv\n"
          "scakit report eng --lang en --formats pdf,docx                 # GN-02 \"İkisi\" ise\n"
          "scakit report eng --formats spdx                               # GN-03 SPDX seçildiyse\n"
          "ls eng/reports/"),
        T(["Dosya", "Kime / ne için"], [
            ["`*_TR.pdf` / `*_EN.pdf`", "Resmî teslim raporu"],
            ["`*_TR.docx`", "Analistin son düzenlemesi (logo, ek yorum); düzenlendiyse PDF'i Word'den yeniden alın"],
            ["`*.cdx.json` / `*.spdx.json`", "SBOM (GN-03): müşterinin envanter / zafiyet yönetim araçları"],
            ["`*_findings.csv`", "Bulgu takibi (GN-04 Excel/CSV)"],
            ["`*.html`", "İç inceleme; istenirse müşteriye de verilebilir"],
        ], [55, 125]),
        H("8.1 Rapor bölümleri ve yorumlanması"),
        T(["Bölüm", "Nasıl okunur"], [
            ["Yönetici özeti", "Bileşen / zafiyetli bileşen sayısı, şiddet dağılımı, KEV, öncelikli 7 aksiyon"],
            ["Düzeltme planı", "Bileşen başına tüm bilinen zafiyetleri kapatan en düşük sürüm. Sıralama: zararlı paket > "
                               "KEV > şiddet > zafiyetli fonksiyon çağrılıyor > EPSS > CVSS"],
            ["Bulgu detayları", "Kritik / Yüksek / KEV ana bölümde; Orta / Düşük Ek A'da. Kimlik, CVE, CVSS, EPSS, "
                                "kanıt, düzeltme sürümü, güven, kaynak (OSV / NVD)"],
            ["Kullanım analizi", "Doğrudan bağımlılık kodda import ediliyor mu; Go'da etkilenen fonksiyon çağrılıyor mu"],
            ["Lisans uyumu", "Politikaya göre uygun / inceleme / yasaklı / belirlenemedi"],
            ["Tedarik zinciri", "Zararlı paket, bağımlılık karışıklığı, dahili registry, deprecated, bakımı durmuş"],
            ["Kabul edilen riskler", "`scakit suppress` kayıtları ve gerekçeleri"],
            ["Kapsam kısıtları", "Lock eksikliği, sürümsüz bileşenler, blackbox ve NVD uyarıları — müşteriye mutlaka "
                                 "anlatılır"],
            ["Ekler", "Ek A: diğer bulgular; Ek B: tam bileşen envanteri"],
        ], [40, 140]),
        T(["Terim", "Anlamı"], [
            ["Güven: Yüksek", "Sürüm dosyadan okundu (lock, paket veritabanı, pom.properties)"],
            ["Güven: Orta", "Güçlü imza / banner / ikili string; veya groupId tahmini; veya NVD AND-yapılandırması"],
            ["Güven: Düşük", "Sürüm çıkarımı zayıf veya dağıtım paketi (yamalar geri taşınmış olabilir)"],
            ["KEV", "CISA'nın aktif olarak istismar edildiğini bildirdiği zafiyet — en önce giderilmeli"],
            ["EPSS", "Önümüzdeki 30 günde istismar edilme olasılığı (FIRST)"],
            ["\"Düzeltilmiş sürüm yok\"", "Bu sürüm hattı için yama yayımlanmamış (EOL); desteklenen hatta geçiş gerekir"],
            ["\"> 1.2.12\"", "NVD yalnızca son etkilenen sürümü veriyor; bu sürümden yeni bir sürüme geçilmeli"],
        ], [40, 140]),
    ]},
    {"title": "9. Teslim ve Kapanış", "blocks": [
        CL("Rapor son okuması yapıldı (müşteri adı, kapsam, tarih, dil)",
           "Teslim paketi: PDF (+ istenirse EN), SBOM, CSV; Word yalnızca talep edilirse",
           "Sunum toplantısı: yönetici özeti, KEV'ler, düzeltme planının ilk 10 satırı, kapsam kısıtları",
           "Kabul edilen riskler müşteriyle teyit edildi, `suppressions.json` güncel",
           "GZ-02 talep edildiyse: teslim alınan dosyalar ve `eng/evidence/` silindi, imha tutanağı verildi",
           "Engagement klasörü (rapor, envanter, bulgular) şirket politikasına göre şifreli arşivlendi"),
        P("Tekrar analiz (ör. müşteri yükseltme yaptı): aynı engagement'a yeni girdileri ekleyip `match` ve `report` "
          "çalıştırmak yeterlidir; eski bulgular yeniden hesaplanır."),
    ]},
    {"title": "10. Sorun Giderme", "blocks": [
        {"type": "faq", "items": [
            ("`match` çok az bulgu verdi / envanter küçük.",
             "Kapsam kısıtlarında \"Lock dosyası yok\" ve sürümsüz bileşenlere bakın; müşteriden Kılavuz Bölüm 4'teki "
             "komut çıktısını isteyin. Dev bağımlılıkları hariç tutulduğunu unutmayın (`--dev`)."),
            ("APK'da sürümlerin çoğu bulunamadı.",
             "Release build karartılmış (rapor gözleminde yazar). MOB-10 Gradle çıktısını isteyin; kaynak kod gerekmez."),
            ("IPA'da \"FairPlay şifrelemesi\" uyarısı.",
             "App Store'dan alınmış IPA. Geliştirme ekibinin ürettiği IPA'yı veya `.xcarchive` dizinini isteyin (WB-12)."),
            ("Masaüstü kurulum dosyası açılmadı.",
             "`7z` kurulu mu? Inno Setup gibi paketleyiciler açılamaz: müşteriden kurulu dizinin arşivini isteyin "
             "(Masaüstü kartı Bölüm 4)."),
            ("Web taraması engellendi / az sonuç.",
             "WAF / IPS engeli olabilir: BB-12 beyaz liste talep edin, `--delay` artırın. Giriş sonrası sayfalar için "
             "test hesabı (BB-30) ile `--header \"Cookie: ...\"`."),
            ("NVD bulgusu dağıtım paketinde.",
             "Dağıtımlar yamaları sürüm değiştirmeden geri taşır; bulgu düşük güvenlidir. Dağıtımın güvenlik "
             "duyurusundan teyit edin; etkilenmiyorsa `suppress --kind not-affected`."),
            ("Bir bileşen için zafiyet eşleşmesi beklerken yok.",
             "Ekosistem veritabanında var mı (`scakit db status`)? Sunucu/native bileşense NVD ürün listesinde mi "
             "(`scakit/vulndb/nvd.py` → CPE_PRODUCTS)? Yeni ürün eklemek için CPE adını NVD'de doğrulayın."),
            ("PDF'te Türkçe karakter bozuk.",
             "Sistemde DejaVu (Linux) veya Arial (Windows/macOS) fontu bulunamadı; fontu kurun veya Word çıktısını "
             "kullanın."),
            ("Müşteri hangi PDF'i dolduracağını sordu.",
             "Bölüm 3.3 karar tablosu. Tek uygulama → kart; birden çok → kartlar veya Form; her durumda Kılavuz."),
        ]},
    ]},
    {"title": "Ek A — Komut Referansı", "blocks": [
        T(["Komut", "Amaç", "Önemli seçenekler"], [
            ["`scakit init <klasör>`", "Yeni engagement", "`--name` `--client` `--lang tr|en`"],
            ["`scakit add <klasör> <girdi>...`", "Girdi tara, envantere ekle",
             "`--target` `--type` `--dev` `--os` `--delay` `--max-pages` `--header` `--no-probe` `--insecure`"],
            ["`scakit policy <klasör>`", "Lisans politikası (WB-40)", "`--allowed` `--review` `--denied` (SPDX)"],
            ["`scakit enrich <klasör>`", "Tedarik zinciri kontrolleri", "`--internal <csv>` `--online` (onay!)"],
            ["`scakit match <klasör>`", "Zafiyet eşleştirme", "`--db`"],
            ["`scakit suppress <klasör>`", "Kabul edilen risk / yanlış pozitif",
             "`--id` `--component ad@sürüm` `--kind` `--reason` `--by` `--expires` `--list`"],
            ["`scakit report <klasör>`", "Rapor üret", "`--lang` `--formats html,md,pdf,docx,cdx,spdx,csv`"],
            ["`scakit db update|download|status`", "Veritabanı", "`--ecosystems` `--from-dir` `--no-nvd`"],
        ], [52, 46, 82]),
        P("Engagement klasörü içeriği: `engagement.json`, `inventory.json`, `findings.json`, `usage.json`, "
          "`license_policy.json`, `suppressions.json`, `evidence/` (blackbox kanıtları), `reports/`."),
    ]},
    {"title": "Ek B — Hızlı Kontrol Listeleri", "blocks": [
        H("Satış / açılış"),
        CL("Kapsam türü ve uygulama listesi netleşti; doğru kart/form + Kılavuz gönderildi",
           "Seviye (Minimum / Önerilen / Tam) ve kaynak kod paylaşımı netleşti",
           "Yerinde mi uzaktan mı; rapor dili; SBOM formatı; `--online` onayı soruldu",
           "NDA imzalandı; blackbox varsa yetki yazısı alındı"),
        H("Analist"),
        CL("`scakit db update` yapıldı (veritabanı tarihi güncel)",
           "Tüm girdiler anlamlı `--target` ile eklendi; kapsam kısıtları incelendi",
           "Kalite kontrol listesi (Bölüm 7) tamamlandı; suppress kayıtları gerekçeli",
           "TR/EN rapor, SBOM, CSV üretildi ve son okuma yapıldı"),
    ]},
    {"title": "Ek C — Müşteriye Gönderilecek E-posta Şablonu (Senaryo 2)", "blocks": [
        C("Konu: SCA Hizmeti – Ön Gereksinimler (Mobil + Web)\n"
          "\n"
          "Merhaba <Ad Soyad>,\n"
          "\n"
          "Mobil ve web uygulamalarınız için whitebox SCA çalışmasına başlayabilmemiz için ekteki\n"
          "dokümanları paylaşıyoruz:\n"
          "\n"
          "  1. Senaryo Kartı – Mobil Uygulama: \"Tam\" seviyeyi işaretleyip MOB- maddelerini doldurunuz.\n"
          "  2. Senaryo Kartı – Web Uygulaması: \"Tam\" seviyeyi işaretleyip WEB- maddelerini doldurunuz.\n"
          "  3. Veri Hazırlama ve Teslim Kılavuzu: her maddenin nasıl hazırlanacağı (madde kodlarıyla).\n"
          "\n"
          "Mobil uygulamanın bağlandığı API de kapsamdaysa API kartını da ekleyebiliriz.\n"
          "Dosyaları Kılavuz Bölüm 2'deki gibi AES-256 şifreli arşiv olarak iletmenizi, parolayı\n"
          "ayrı bir kanaldan (SMS/telefon) paylaşmanızı rica ederiz.\n"
          "\n"
          "<tarih> tarihinde kısa bir açılış toplantısı ile maddelerin üzerinden geçmeyi öneriyoruz.\n"
          "\n"
          "Saygılarımızla,\n"
          "<Ad Soyad> – <Unvan>"),
    ]},
]
