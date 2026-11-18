import { GuideContent } from "./types";

const c: GuideContent = {
  intro:
    "Le Fureteur, yazılımların içindeki üçüncü taraf bileşenleri (açık kaynak kütüphaneler, çerçeveler, işletim sistemi paketleri) bulan, bunları bilinen güvenlik açıklarıyla eşleştiren ve düzeltme planı çıkaran bir Yazılım Bileşen Analizi (SCA) platformudur. Kurumun kendi sunucusuna kurulur; kaynak kod, dosyalar ve bulgular kurum dışına çıkmaz.",
  sections: [
    {
      id: "what",
      title: "Le Fureteur nedir, ne işe yarar?",
      blocks: [
        { p: "Modern bir uygulamanın kodunun büyük kısmı kurumun kendi yazdığı kod değil, dışarıdan alınan bileşenlerdir. Bu bileşenlerden birinde açık çıktığında (ör. Log4Shell) uygulama da etkilenir. Le Fureteur şu soruları yanıtlar:" },
        { ul: [
          "Uygulamada hangi bileşenler, hangi sürümleriyle var? (envanter / SBOM)",
          "Bunlardan hangilerinde bilinen güvenlik açığı var, ne kadar ciddi?",
          "Hangileri şu anda saldırganlarca aktif olarak istismar ediliyor (CISA KEV)?",
          "Hangi sürüme yükseltince açık kapanır? Önce hangisi düzeltilmeli?",
          "Lisanslar kurumun politikasına uygun mu? Tedarik zinciri riski (bağımlılık karışıklığı, bakımı durmuş paket) var mı?",
        ] },
        { p: "Çıktılar: önceliklendirilmiş bulgu listesi, yönetici özeti içeren rapor (HTML / PDF / Word), CSV ve standart SBOM dosyaları (CycloneDX, SPDX)." },
      ],
    },
    {
      id: "how",
      title: "Nasıl çalışır?",
      blocks: [
        { ol: [
          "Toplama: Hedef türüne göre bileşenler bulunur — lock dosyaları, paket veritabanları, derlenmiş paket meta verileri, web yanıtları, mobil uygulama içeriği.",
          "Envanter: Aynı bileşenin farklı yerlerdeki tespitleri birleştirilir; her bileşen için ekosistem, sürüm, güven düzeyi, doğrudan / dolaylı ilişki ve kanıt (dosya yolu / URL) tutulur.",
          "Eşleştirme: Envanter, sunucudaki çevrimdışı zafiyet veritabanıyla (OSV; OSV kapsamı dışındaki sunucu yazılımları için NVD) ekosisteme özgü sürüm karşılaştırmasıyla eşleştirilir.",
          "Zenginleştirme: Her bulguya CVSS şiddeti, EPSS istismar olasılığı ve CISA KEV bilgisi eklenir; düzeltilmiş sürüm hesaplanır.",
          "Önceliklendirme: Zararlı paket → aktif istismar (KEV) → şiddet → EPSS sırası.",
          "Raporlama ve takip: Bulgular veritabanına işlenir; yeniden taramalarda yeni / kapanan / yeniden açılan bulgular izlenir.",
        ] },
        { note: "Analiz tamamen sunucuda ve çevrimdışı yapılır. Kaynak kod veya envanter üçüncü taraf servislere gönderilmez. İnternet yalnızca zafiyet veritabanını güncellemek için (isteğe bağlı) kullanılır." },
      ],
    },
    {
      id: "types",
      title: "Analiz türleri ve desteklenen girdiler",
      blocks: [
        { table: { head: ["Tür", "Girdi", "Ne bulunur"], rows: [
          ["Whitebox — kaynak", "Kaynak kod arşivi (zip / tar) veya bağımlılık dosyaları", "npm / yarn / pnpm, PyPI (requirements, Poetry, Pipfile), Maven / Gradle, Go, Composer, NuGet, Cargo, RubyGems, Pub, CocoaPods, SwiftPM; kullanım (import) analizi"],
          ["Whitebox — derlenmiş", "JAR / WAR / EAR", "İç içe JAR'lar ve Maven meta verileri"],
          ["Whitebox — container", "docker save ile alınmış imaj (.tar)", "İşletim sistemi paketleri (Debian / Ubuntu / Alpine / RHEL ailesi) ve imaj içindeki uygulama bağımlılıkları"],
          ["Whitebox — paket listesi", "dpkg / rpm / apk çıktısı", "İşletim sistemi paketleri (dağıtım ve sürüm belirtilmeli, ör. Debian:12)"],
          ["Blackbox — web", "Web adresi", "Tarayıcıya gelen JavaScript / CSS kütüphaneleri, CDN adresleri, source map'ler, lisans manifestleri, sürüm ifşa eden başlıklar ve hata sayfaları, CMS sürümleri"],
          ["Blackbox — mobil", "APK / IPA", "Uygulamaya gömülü kütüphaneler (FairPlay ile şifrelenmiş IPA analiz edilemez)"],
          ["Blackbox — masaüstü", "Kurulum dosyası (.exe / .msi), Electron uygulaması", "Gömülü DLL'ler, .NET derlemeleri, Electron / Node paketleri"],
        ] } },
        { p: "Bulgulardaki güven düzeyi (yüksek / orta / düşük), sürümün ne kadar kesin belirlendiğini gösterir. Blackbox analiz yalnızca dışarıdan görülebilen bileşenleri bulabilir; sunucu tarafındaki kütüphaneler için whitebox analiz gerekir." },
      ],
    },
    {
      id: "webaccess",
      title: "Web taramasında engeller ve çözümleri",
      blocks: [
        {"p": "Web hedefleri dışarıdan taranır; bazı siteler otomatik istekleri engeller. Le Fureteur engelin türünü tespit eder, tarama sayfasında nedenini ve tek tıkla uygulanabilecek çözümleri gösterir. Çoğu durum kendiliğinden çözülür."},
        {"table": {"head": ["Durum", "Ne olur?"], "rows": [["WAF / bot koruması (TLS parmak izi)", "HTTP istemcisi \"Otomatik\" ise tarama engeli görür görmez tarayıcı uyumlu TLS'e (curl_cffi) geçip devam eder."], ["JavaScript doğrulaması / CAPTCHA", "Otomatik geçilmez. Tarayıcı yardımcısı kendi bilgisayarınızda görünür bir tarayıcı açar; doğrulamayı siz geçersiniz, gezinme ve yükleme otomatiktir. Ya da HAR / Burp kaydı yükleyin."], ["Coğrafi engel, IP engeli, zaman aşımı", "Yöneticinin tanımladığı çıkış noktaları (HTTP / SOCKS5 proxy) Otomatik modda sırayla denenir; hedef ayarından biri sabitlenebilir."], ["Giriş sayfasına / SSO'ya yönlendirme", "Hedef sayfasından kimlik doğrulama (form, çerez, Bearer, Basic) tanımlayın veya tarayıcı yardımcısında kendiniz giriş yapın."], ["Hız sınırı (429 / 503)", "Bildirilen süre kadar beklenir, yavaşlanır ve istek bir kez yeniden denenir."], ["TLS sertifika hatası", "Güvenilir iç ortamlarda tek tıkla TLS doğrulaması kapatılıp yeniden taranır."], ["DNS, bağlantı reddi, mTLS, bakım", "Nedeni ve yapılacaklar tarama sayfasında açıklanır."]]}},
        {"ul": ["Sayfaların yüklediği başka alan adındaki JS / CSS dosyaları (CDN) da incelenir; izleme betikleri atlanır, o sunucularda gezinme yapılmaz.", "linkedin.com → www.linkedin.com gibi yönlendirmelerde tarama yeni adresten devam eder.", "Dosya hedeflerinde de bileşen çıkmazsa nedeni (kilit dosyası yok, şifreli IPA, korumalı APK, distroless imaj, desteklenmeyen arşiv) ve çözüm komutları gösterilir."]},
        {"note": "İç ağ koruması her koşulda geçerlidir: proxy veya tarayıcı uyumlu istemci kullanılsa da tarama iç ağ adreslerine bağlanmaz (yönetici açıkça izin vermedikçe)."},
      ],
    },
    {
      id: "glossary",
      title: "Kavramlar sözlüğü",
      blocks: [
        { table: { head: ["Kavram", "Açıklama"], rows: [
          ["SCA", "Software Composition Analysis — yazılımdaki üçüncü taraf bileşenlerin ve risklerinin analizi."],
          ["SBOM", "Software Bill of Materials — yazılımın bileşen listesi. Standartları: CycloneDX ve SPDX."],
          ["CVE", "Bir güvenlik açığının evrensel kimliği (ör. CVE-2021-44228)."],
          ["GHSA / OSV", "GitHub güvenlik duyurusu kimliği / Google'ın açık zafiyet veritabanı; paket ekosistemlerine göre etkilenen sürüm aralıklarını içerir."],
          ["NVD / CPE", "ABD Ulusal Zafiyet Veritabanı / ürün tanımlama biçimi; OSV kapsamı dışındaki sunucu yazılımları için kullanılır."],
          ["CVSS", "Açığın teknik şiddet puanı (0–10)."],
          ["EPSS", "Açığın önümüzdeki 30 günde istismar edilme olasılığı (FIRST)."],
          ["KEV", "CISA'nın gerçek saldırılarda aktif olarak istismar edildiği bilinen açıklar listesi — en yüksek öncelik."],
          ["PURL", "Paket URL'si — bileşenin ekosistem bağımsız kimliği (ör. pkg:npm/lodash@4.17.20)."],
          ["Doğrudan / dolaylı bağımlılık", "Uygulamanın kendisinin eklediği paket / başka bir paket üzerinden gelen paket."],
          ["Bağımlılık karışıklığı", "Kurum içi paket adının genel kayıtta da bulunması; saldırganın sahte paket yüklemesine yol açabilir."],
          ["Copyleft", "Türetilmiş yazılımın da aynı lisansla açılmasını şart koşan lisanslar (GPL, AGPL...)."],
        ] } },
      ],
    },
    {
      id: "roles",
      title: "Roller ve yetkiler",
      blocks: [
        { table: { head: ["Rol", "Yetki"], rows: [
          ["Yönetici", "Her şey: kullanıcılar, organizasyonlar, ayarlar (NVD anahtarı, SMTP, Jira), zafiyet veritabanı, bildirim kanalları, sistem durumu, denetim kaydı."],
          ["Analist", "Tüm organizasyonlarda proje, hedef, tarama ve bulgu yönetimi; sistem durumunu görüntüleme. Ayarları değiştiremez."],
          ["Müşteri", "Yalnızca kendi organizasyonu: proje ve hedef ekler, dosya yükler, tarar, bulgu durumunu yönetir, Jira'ya ekler, rapor indirir. Web hedefi olarak yalnızca organizasyonuna tanımlı alan adlarını ekleyebilir."],
        ] } },
      ],
    },
    {
      id: "start",
      title: "Adım adım kullanım",
      blocks: [
        { ol: [
          "Yönetici: Ayarlar → Veritabanını güncelle (ilk kurulumda zorunlu) ve Sistem durumu sayfasındaki önerileri gözden geçirin.",
          "Organizasyonlar → müşteri kurumu ekleyin; web taraması yapılacaksa izinli alan adlarını girin (ornek.com veya *.ornek.com).",
          "Kullanıcılar → analist ve müşteri hesaplarını oluşturun.",
          "Projeler → yeni proje; proje ayarlarında rapor dili, lisans politikası ve Jira proje anahtarı belirlenebilir.",
          "Hedef ekle → web adresi (blackbox) veya dosya yükleme (kaynak kod, APK, IPA, imaj, kurulum dosyası).",
          "Taramayı başlat → ilerleme ve günlük tarama sayfasında izlenir.",
          "Bulgular → filtreleyin, ayrıntıya bakın, durum atayın, yorum ekleyin, Jira'ya gönderin.",
          "Tarama → Raporlar sekmesinden raporu ve SBOM dosyalarını indirin.",
          "Hedef sayfasından zamanlanmış tarama ekleyerek düzenli yeniden taramayı açın.",
        ] },
        { note: "Yalnızca yazılı izni alınmış sistemleri tarayın. İç ağ adresleri varsayılan olarak engellidir; yönetici ayarlardan açabilir." },
      ],
    },
    {
      id: "findings",
      title: "Bulgular ve yaşam döngüsü",
      blocks: [
        { p: "Bir bulgu = bir hedefte bir bileşen + bir zafiyet. Aynı bulgu taramalar arasında tekildir; ilk ve son görülme zamanı korunur." },
        { table: { head: ["Durum", "Anlamı"], rows: [
          ["Açık", "Yeni bulunmuş, işlem bekliyor."],
          ["Üzerinde çalışılıyor", "Düzeltme süreci başladı."],
          ["Kabul edilen risk", "Bilinçli olarak kabul edildi (gerekçe zorunlu). Raporda ayrı bölümde gösterilir."],
          ["Yanlış pozitif", "Bulgu hatalı (gerekçe zorunlu)."],
          ["Etkilenmiyor", "Bileşen var ama açık bu kullanımda tetiklenemez (gerekçe zorunlu)."],
          ["Düzeltildi", "Otomatik: yeniden taramada bileşen / sürüm artık görülmüyor. Tekrar görülürse bulgu yeniden açılır."],
        ] } },
        { p: "Tarama sayfasındaki Değişiklikler sekmesi, önceki taramaya göre yeni, kapanan ve yeniden açılan bulguları gösterir. Durum değiştirdikten sonra raporu yeniden üretebilirsiniz." },
        {"p": "Bulgular sayfasındaki arama kutusu alan adı, hedef, proje, müşteri, bileşen, sürüm, CVE / GHSA ve açıklamada arar; birden fazla kelime hepsini içerenleri getirir. Ekosistem, düzeltme var / yok, ilk görülme ve hedef türü filtreleri vardır; filtrelenmiş liste CSV olarak indirilebilir. Aranan hedefin bulgusu yoksa eşleşen hedefler bağlantılarıyla gösterilir."},
      ],
    },
    {
      id: "collaboration",
      title: "Takım çalışması: atama, onay, tartışma, mesaj",
      blocks: [
        { p: "Le Fureteur, bulguların kim tarafından, hangi sürede ve hangi kararla kapatılacağını ekip içinde yönetmek için iş birliği araçları içerir." },
        { ul: [
          "Takımlar: her takımda yönetici, sorumlular ve onlara bağlı üyeler bulunur. Takım detay sayfasında organizasyon şeması, kişi başı iş yükü, iş kuyruğu ve son 30 günde teslim edilenler görünür.",
          "Atama: bulgu bir kişiye son tarihle atanır; atanan kişi bildirim alır. Toplu atama Bulgular ekranından yapılır.",
          "Onay süreci: risk kabulü, yanlış pozitif ve \"etkilenmiyor\" kararları, kararı veren kişinin sorumlusuna / takım yöneticisine onaya gider. Onaylananlar ve reddedilenler Onaylar → Karar verdiklerim sekmesinde saklanır.",
          "Tartışma odası: bir bulgu hakkında görüş ayrılığı varsa bulgudan tartışma açılır, ilgili kişiler eklenir. Uzlaşılamazsa tartışma yöneticiye taşınır; yönetici karar verir veya yetkili birine vekâlet verir. Karar bulgu geçmişine işlenir.",
          "Mesajlar: kişilere veya bir takımın tamamına yazılır. Tek tik gönderildi, çift gri tik iletildi, çift mavi tik okundu anlamına gelir. Okumayanlara saatte bir hatırlatma gönderilebilir.",
          "Hatırlatıcılar: kendinize zamanlı not bırakın; bulgu veya mesajdan da kurulabilir. Zamanı gelince bildirim kutusuna düşer.",
        ] },
        { note: "Müşteri kullanıcıları yalnızca kendi organizasyonlarındaki kişileri ve danışmanlık ekibini görür; başka organizasyonun bulgusu, tartışması veya mesajı hiçbir koşulda görünmez." },
      ],
    },
    {
      id: "reports",
      title: "Raporlar ve çıktılar",
      blocks: [
        { table: { head: ["Dosya", "İçerik"], rows: [
          ["rapor.html / .pdf / .docx", "Yönetici özeti, düzeltme planı, bulgu ayrıntıları, kullanım analizi, lisans uyumu, tedarik zinciri, kapsam kısıtları, ekler (envanter, tespit konumları)."],
          ["bulgular.csv", "Tablo programları ve başka araçlar için bulgu listesi."],
          ["sbom.cdx.json", "CycloneDX 1.5 SBOM."],
          ["sbom.spdx.json", "SPDX 2.3 SBOM."],
        ] } },
        { p: "Rapor dili proje ayarlarından seçilir: Türkçe, İngilizce, Fransızca, Almanca." },
      ],
    },
    {
      id: "automation",
      title: "Zamanlama, bildirimler ve Jira",
      blocks: [
        { ul: [
          "Sürekli / zamanlanmış tarama: hedef sayfasından veya proje → Eğilim ve sürekli tarama sekmesinden tüm hedeflere; sihirbazla (günler, saat aralığı, sıklık) ya da cron ifadesiyle. En sık saatte bir. Aynı anda başlayan taramalar proje kuyruk kuralına göre sıralanır.",
          "Zamanlanmış veritabanı güncellemesi: Ayarlar sayfasından (yönetici); önerilen her gün bir kez.",
          "Bildirimler (yönetici): Slack, Microsoft Teams, e-posta veya genel webhook. Olaylar: tarama tamamlandı / başarısız, eşik üstü yeni bulgu, yeni KEV bulgusu, veritabanı güncellemesi başarısız. Kanal tek bir organizasyonla sınırlandırılabilir. Webhook gövdesi isteğe bağlı olarak HMAC-SHA256 ile imzalanır (X-Scakit-Signature).",
          "Jira (Cloud ve Server / Data Center): birden fazla Jira bağlantısı eklenebilir; yönetici her birini kimlerin (rol, kullanıcı) ve hangi müşterilerin bulguları için kullanabileceğini belirler. \"Jira'ya ekle\" denince yetkili birden fazla bağlantı varsa hangisi olduğu sorulur; projeye varsayılan Jira atanırsa sorulmaz. Aynı bulgu için ikinci kayıt açılmaz; isteğe bağlı otomatik kayıt ve düzelince / yeniden açılınca yorum.",
        ] },
      ],
    },
    {
      id: "queue",
      title: "Tarama kuyruğu, sürekli tarama ve eğilim",
      blocks: [
        {"ul": ["Kuyruk paneli (Taramalar sayfası): çalışan ve sıradaki taramalar; yönetici ve analist sırayı değiştirebilir (en öne al, bir yukarı / aşağı, sona at).", "Proje kuyruk kuralı: her projenin taramaları (elle, toplu, zamanlanmış) kendi aralarında sırayla, aynı anda en fazla N veya serbest çalışır; aralarında bekleme süresi verilebilir. Diğer projeler etkilenmez.", "Hedef eklerken \"Kuyruk (bu taramalar için)\" kartından yalnızca o taramalara özel kural seçilebilir veya projenin varsayılanı yapılabilir. Hedef sayfasındaki başlat menüsü: kuyruğun önüne al / normal / sona ekle.", "Sunucu geneli kurallar (yönetici, Ayarlar → Tarama kuyruğu): worker başına aynı anda kaç tarama ve taramalar arası bekleme — proje kurallarının üst sınırıdır.", "Sürekli tarama: proje → Eğilim ve sürekli tarama sekmesinden günler, saat aralığı ve sıklık seçilip tüm hedeflere tek seferde uygulanır (ör. hafta içi 09–18 arası 3 saatte bir, haftada 2 kez).", "Eğilim: pano, proje ve hedef sayfalarında saat / gün / hafta bazında açık bulgu, yeni ve kapanan bulgular ve önceki döneme göre fark; Küçük / Orta / Büyük boyut ve tablo görünümü."]},
      ],
    },
    {
      id: "vulndb",
      title: "Zafiyet veritabanı",
      blocks: [
        { p: "Eşleştirme sunucudaki yerel veritabanıyla yapılır. Kaynaklar: OSV (paket ekosistemleri ve Linux dağıtımları), EPSS, CISA KEV ve isteğe bağlı NVD (API anahtarı önerilir)." },
        { ul: [
          "Güncelleme: Ayarlar → Veritabanını güncelle, ya da zamanlanmış güncelleme.",
          "İnternetsiz kurulum: başka bir makinede `scakit db download klasör` ile indirip klasörü sunucuya kopyalayın; Ayarlar'da klasör yolunu verin.",
          "Güncellik: Sistem durumu sayfasında her kaynağın yaşı gösterilir; eski veri uyarı üretir.",
          "Veritabanı güncellenirken taramalar beklemeden çalışır (son kaydedilmiş veriyle). Bozuk inen bir arşiv atlanır ve sonraki güncellemede yeniden indirilir.",
          "Kapalı ağ için adım adım anlatım ve indirme: Komut satırı (scakit) sayfası.",
        ] },
      ],
    },
    {
      id: "system",
      title: "Sistem durumu ve öz tarama",
      blocks: [
        { p: "Sistem durumu sayfası (yönetici / analist) uygulamanın kendi sağlığını gösterir: worker'lar, iş kuyruğu, disk, veritabanı, zafiyet verisinin güncelliği, harici araçlar ve yapılandırma kontrolleri — her biri için yapılacak işlem önerisiyle." },
        { ul: [
          "Öz tarama: Le Fureteur, kendi Python, arayüz ve işletim sistemi paketlerini kendi zafiyet veritabanıyla tarar ve güncelleme önerisi verir (çevrimdışı).",
          "Güncel sürüm kontrolü (yönetici, isteğe bağlı): yalnızca Le Fureteur'ün kendi açık kaynak bağımlılıklarının adları PyPI ve npm kayıtlarına sorulur; müşteri verisi gönderilmez.",
        ] },
      ],
    },
    {
      id: "security",
      title: "Güvenlik ve gizlilik",
      blocks: [
        { ul: [
          "Kurum içi kurulum: kod, dosyalar, bulgular ve raporlar kurumun sunucusunda kalır.",
          "Parolalar Argon2 ile saklanır; oturum çerezi httpOnly + SameSite=Strict; tüm değiştirici isteklerde CSRF koruması; giriş denemesi sınırı.",
          "Gizli ayarlar (NVD anahtarı, SMTP parolası, Jira token'ı, webhook adresleri) veritabanında şifreli saklanır ve arayüze geri gönderilmez.",
          "Hedef koruması: yalnızca http / https; müşteriler yalnızca izinli alan adlarını tarayabilir; iç ağ ve bulut metadata adresleri varsayılan olarak engellidir; kontrol tarama anında tekrarlanır.",
          "Organizasyon yalıtımı: müşteri kullanıcıları başka organizasyonun hiçbir verisini göremez.",
          "Denetim kaydı: giriş, ayar, hedef, tarama, durum değişikliği, Jira ve rapor indirme işlemleri kayıt altındadır.",
          "Üretimde HTTPS arkasında çalıştırın (SCAKIT_COOKIE_SECURE=1).",
        ] },
      ],
    },
    {
      id: "toolset",
      title: "Araç seti",
      blocks: [
        { p: "Günlük işler için küçük, güvenli araçlar: HTTP istemcisi, kodlayıcı / çözücü (Base64, URL, HTML, Hex, Unicode, JWT, SHA), TCP ping ve kişisel not defteri." },
        { ul: [
          "HTTP istemcisi ve ping iç ağ adreslerine (127.0.0.1, 10.x, 169.254.169.254 vb.) hiçbir koşulda bağlanmaz; yönlendirmeler de denetlenir.",
          "Oturum çereziniz hedefe gönderilmez; yalnızca sizin eklediğiniz başlıklar gider. Her istek denetim kaydına yazılır ve dakikalık sınıra tabidir.",
          "Kodlayıcı tamamen tarayıcıda çalışır. Not defteri yalnızca size görünür.",
          "Müşteri kullanıcıları için ağ araçları varsayılan olarak kapalıdır; açılırsa yalnızca izinli alan adlarına istek atabilirler (Ayarlar → Araç seti).",
        ] },
      ],
    },
    {
      id: "admin",
      title: "Yönetim: bakım modu, oturumlar, denetim",
      blocks: [
        { ul: [
          "Bakım modu (Sistem durumu → Bakım): açıkken yalnızca yöneticiler giriş yapabilir; diğer kullanıcılar ve API token'ları bakım ekranı görür, zamanlanmış taramalar başlamaz.",
          "Giriş ve API sınırları (Ayarlar → Güvenlik ve erişim): başarısız giriş sayısı, kilit süresi ve kullanıcı başına dakikalık API isteği.",
          "Kullanıcı detayı: giriş geçmişi (başarılı / başarısız, IP, cihaz), etkin oturumlar ve son işlemler. Şüpheli durumda tüm oturumlar tek tıkla sonlandırılır. Herkes kendi oturumlarını Hesabım sayfasından görür.",
          "Denetim kaydı: kullanıcı, işlem, nesne türü, IP ve zaman aralığına göre süzülür; CSV olarak dışa aktarılır.",
          "Yedekleme: `scakit server backup dosya --encrypt` ile şifreli yedek alınır; geri yükleme yalnızca boş kuruluma yapılır.",
        ] },
      ],
    },
    {
      id: "cli",
      title: "Komut satırı (CLI)",
      blocks: [
        { p: "Aynı analiz motoru danışmanlık çalışmaları için komut satırından da kullanılabilir:" },
        { code: "scakit init ~/isler/musteri --name \"Portal 2026\" --client \"Müşteri\" --lang tr\nscakit add ~/isler/musteri ./kaynak-kod.zip app.apk https://ornek.com\nscakit db update\nscakit match ~/isler/musteri\nscakit report ~/isler/musteri --formats html,pdf,docx,cdx,spdx\n\n# web sunucusu\nscakit server init --email admin@firma.com\nscakit server run --port 8800\nscakit server worker" },
        {"note": "scakit'in ne olduğu, kurulumu, tüm komutları ve kapalı ağda veritabanı hazırlama adımları için menüdeki Komut satırı (scakit) sayfasına bakın; yönetici ve analistler paketi oradan indirebilir."},
      ],
    },
    {
      id: "faq",
      title: "Sık sorulan sorular",
      blocks: [
        { table: { head: ["Soru", "Yanıt"], rows: [
          ["Bulgu yok — uygulama güvenli mi?", "Hayır, yalnızca bilinen açığı olan bileşen bulunmadığı anlamına gelir. Blackbox analizde sunucu tarafı bileşenler görünmez; kapsam kısıtları raporda belirtilir."],
          ["Neden bir bulgunun güveni düşük?", "Sürüm tahmin edildi ya da dağıtım paketlerinde yamalar sürüm numarası değişmeden geri taşınmış olabilir. Kanıt bölümünü inceleyin."],
          ["Yükseltme önerisi neden ana sürüm atlıyor?", "Bazı açıklar yalnızca yeni ana sürümde düzeltilmiştir; öneri tüm bilinen açıkları kapatan en düşük sürümdür."],
          ["Tarama başarısız oldu.", "Tarama sayfasındaki Günlük sekmesine bakın; Sistem durumu sayfasında worker ve veritabanı durumunu kontrol edin."],
        ] } },
      ],
    },
  ],
  api: {
    title: "API",
    groupsHead: ["Yol", "Rol", "Açıklama"],
    groups: [
      ["/api/auth/*", "herkes", "Giriş, çıkış, oturumdaki kullanıcı, dil, parola değişikliği"],
      ["/api/orgs", "yönetici (yazma)", "Organizasyonlar ve izinli alan adları"],
      ["/api/users", "yönetici", "Kullanıcı yönetimi"],
      ["/api/projects", "tümü (kapsamlı)", "Projeler, rapor dili, lisans politikası, Jira anahtarı"],
      ["/api/projects/{id}/targets, /api/targets/*", "tümü (kapsamlı)", "Hedefler, dosya yükleme / silme, tarama başlatma"],
      ["/api/scans/*", "tümü (kapsamlı)", "Taramalar, günlük, iptal, bileşenler, değişiklikler, raporlar"],
      ["/api/findings/*", "tümü (kapsamlı)", "Bulgu listesi / ayrıntı, durum, yorum, Jira kaydı"],
      ["/api/schedules/*", "tümü (veritabanı: yönetici)", "Zamanlamalar ve cron önizlemesi"],
      ["/api/notifications/*", "yönetici", "Bildirim kanalları ve test gönderimi"],
      ["/api/settings, /api/vulndb/*", "yönetici", "Ayarlar, zafiyet veritabanı durumu ve güncelleme"],
      ["/api/system/*", "yönetici / analist", "Sistem durumu, öz tarama, güncel sürüm kontrolü"],
      ["/api/jira/*", "yönetici / tümü", "Jira bağlantı testi ve durumu"],
      ["/api/dashboard, /api/audit", "tümü / yönetici", "Pano özeti, denetim kaydı"],
    ],
    fullListTitle: "Tüm uç noktalar (canlı şema)",
    fullListNote: "API oturum çereziyle çalışır: önce /api/auth/login ile giriş yapın; POST / PUT / PATCH / DELETE isteklerinde scakit_csrf çerezinin değerini X-CSRF-Token başlığında gönderin. Makineden makineye kullanım (CI/CD) için API token desteği yol haritasındadır.",
  },
};
export default c;
