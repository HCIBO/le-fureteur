import { IconApps, IconBrandAndroid, IconBrowserCheck, IconBrandDocker, IconCode, IconDeviceDesktop, IconFileCertificate, IconListDetails, IconWorldWww } from "@tabler/icons-react";
import { t } from "../i18n";

export type TargetType = {
  id: string; kind: "web" | "upload"; icon: any; color: string; title: string; desc: string;
  formats: string[]; accept?: string; how?: { label: string; code: string }[]; tips?: string[];
};

export const TARGET_TYPES: TargetType[] = [
  { id: "web", kind: "web", icon: IconWorldWww, color: "indigo", title: t("Web sitesi / web uygulaması"),
    desc: t("Canlı adres dışarıdan (blackbox) taranır: JS kütüphaneleri, CDN dosyaları, sürüm ifşaları, CMS eklentileri."),
    formats: ["https://"], tips: [t("Birden fazla adresi alt alta yazın; her biri ayrı hedef olur."), t("Yalnızca yazılı izni alınmış adresleri tarayın.")] },
  { id: "traffic", kind: "upload", icon: IconBrowserCheck, color: "orange", title: t("Tarayıcı / Burp trafiği"),
    desc: t("Siteyi kendi tarayıcınızda veya Burp üzerinden gezin, kaydı yükleyin: HTML, JS ve CSS yanıtları hedefe hiç istek atılmadan incelenir. Cloudflare / WAF arkasındaki ve IP izin listeli hedefler için önerilen yol."),
    formats: [".har", "Burp XML"], accept: ".har,.json,.xml",
    how: [{ label: "Chrome / Edge / Firefox", code: "1. F12 → Network (Ağ) sekmesi → \"Preserve log\" işaretli\n2. Siteyi normal şekilde gezin (WAF doğrulaması çıkarsa siz geçin)\n3. İstek listesinde sağ tık → \"Save all as HAR with content\"" },
          { label: "Burp Suite", code: "1. Proxy → HTTP history → hedefin isteklerini seçin\n2. Sağ tık → \"Save items\" → \"Base64-encode requests and responses\" işaretli\n3. Oluşan .xml dosyasını yükleyin" }],
    tips: [t("Çerezler, yetki başlıkları, istek gövdeleri ve Set-Cookie yanıtları dosya sunucuya yazılmadan önce otomatik silinir."), t("Ne kadar çok sayfa gezerseniz o kadar çok bileşen bulunur; yalnızca kaydedilen yanıtlar incelenir.")] },
  { id: "source", kind: "upload", icon: IconCode, color: "teal", title: t("Kaynak kod"),
    desc: t("Depo arşivi veya lock dosyaları: npm, PyPI, Maven/Gradle, Go, NuGet, Composer, Cargo, RubyGems, Pub."),
    formats: [".zip", ".tar.gz", ".tar.xz", "package-lock.json", "requirements.txt", "pom.xml", "go.sum", "…"], accept: ".zip,.tar,.tgz,.gz,.bz2,.xz,.txz,.tbz2,.json,.lock,.txt,.xml,.toml,.sum,.mod,.gradle,.kts,.csproj,.yaml,.yml",
    how: [{ label: "git", code: "git archive --format=zip -o kaynak.zip HEAD" }],
    tips: [t("node_modules / vendor klasörlerini eklemenize gerek yok; lock dosyaları yeterli."), t("Arşivler güvenli biçimde açılır (zip bombası, sembolik bağ ve yol aşımı engellenir).")] },
  { id: "mobile", kind: "upload", icon: IconBrandAndroid, color: "green", title: t("Mobil uygulama"),
    desc: t("Android (APK, AAB, XAPK) ve iOS (IPA) paketlerindeki SDK'lar, native kütüphaneler ve Flutter / React Native bileşenleri."),
    formats: [".apk", ".aab", ".xapk", ".ipa"], accept: ".apk,.aab,.xapk,.apks,.ipa,.zip",
    how: [{ label: "adb", code: "adb shell pm path com.ornek.uygulama\nadb pull /data/app/.../base.apk" }],
    tips: [t("Uygulama mağazası sürümüyle aynı paketi yükleyin; şifrelenmiş IPA'lar kısmen analiz edilebilir.")] },
  { id: "image", kind: "upload", icon: IconBrandDocker, color: "blue", title: t("Konteyner imajı"),
    desc: t("Docker / OCI imajındaki işletim sistemi paketleri ve uygulama bağımlılıkları."),
    formats: [".tar", ".tar.gz"], accept: ".tar,.gz,.tgz",
    how: [{ label: "docker", code: "docker save ornek/uygulama:1.4 -o imaj.tar" }, { label: "podman", code: "podman save -o imaj.tar ornek/uygulama:1.4" }] },
  { id: "desktop", kind: "upload", icon: IconDeviceDesktop, color: "grape", title: t("Masaüstü / sunucu yazılımı"),
    desc: t("Kurulum dosyaları ve paketler: gömülü kütüphaneler, DLL / SO sürüm bilgileri, Electron uygulamaları."),
    formats: [".exe", ".msi", ".dmg", ".deb", ".rpm", ".zip", ".jar", ".war"], accept: ".exe,.msi,.dmg,.pkg,.deb,.rpm,.zip,.jar,.war,.ear,.appimage,.msix,.appx,.cab" },
  { id: "sbom", kind: "upload", icon: IconFileCertificate, color: "orange", title: t("SBOM dosyası"),
    desc: t("Başka bir araçla üretilmiş yazılım malzeme listesi; bileşenler doğrudan zafiyet veritabanıyla eşleştirilir."),
    formats: ["CycloneDX JSON / XML", "SPDX JSON / tag-value"], accept: ".json,.xml,.cdx,.spdx,.tv,.txt",
    how: [{ label: "syft", code: "syft dir:. -o cyclonedx-json > sbom.cdx.json" }, { label: "cdxgen", code: "cdxgen -o sbom.cdx.json" }] },
  { id: "packages", kind: "upload", icon: IconListDetails, color: "cyan", title: t("Sunucu paket listesi"),
    desc: t("Bir sunucudaki kurulu işletim sistemi paketleri; dağıtıma özgü güvenlik bültenleriyle eşleştirilir."),
    formats: ["dpkg", "rpm", "apk"], accept: ".txt,.list,.log",
    how: [{ label: "Debian / Ubuntu", code: "dpkg-query -W -f='${Package} ${Version}\\n' > paketler.txt" }, { label: "RHEL / Rocky", code: "rpm -qa --qf '%{NAME} %{EPOCH}:%{VERSION}-%{RELEASE}\\n' > paketler.txt" }, { label: "Alpine", code: "apk info -v > paketler.txt" }] },
];

export const typeOf = (tg: { kind: string; options?: any }) =>
  TARGET_TYPES.find((x) => x.id === (tg.kind === "web" ? "web" : tg.options?.type)) ?? { ...TARGET_TYPES[1], id: "other", icon: IconApps, color: "gray", title: t("Dosya") };
