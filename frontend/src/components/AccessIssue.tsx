import { Alert, Anchor, Badge, Button, Card, Group, List, Select, Stack, Text, ThemeIcon } from "@mantine/core";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { IconAlertTriangle, IconCertificate, IconFileAlert, IconLock, IconMapPinOff, IconPlugConnectedX, IconRefresh, IconRouteAltLeft, IconTool, IconWorldOff } from "@tabler/icons-react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../api";
import { fail } from "./ui";
import { CaptureAssist } from "./CaptureAssist";
import { CodeBlock } from "./CodeBlock";
import { t } from "../i18n";

type Info = { title: string; why: string; icon: any; color: string; steps: string[]; egress?: boolean; capture?: boolean; tls?: boolean; auth?: boolean; retry?: boolean };

const ISSUES = (): Record<string, Info> => ({
  dns: { title: t("Alan adı çözümlenemedi"), why: t("Le Fureteur sunucusu bu adın IP adresini bulamadı."), icon: IconWorldOff, color: "gray",
    steps: [t("Adresin yazımını kontrol edin."), t("Yalnızca şirket içi DNS'te tanımlı bir adsa, tarama sunucusunun o DNS'i kullanması ve yöneticinin iç ağ taramasına izin vermesi gerekir.")], retry: true },
  timeout: { title: t("Sunucu yanıt vermedi (zaman aşımı)"), why: t("Bağlantı kurulamadı. Çoğu zaman hedef yalnızca belirli IP adreslerine veya ülkelere açıktır (izin listesi)."), icon: IconPlugConnectedX, color: "orange",
    steps: [t("Sistem sahibinden tarama sunucusunun çıkış IP adresini izin listesine eklemesini isteyin."), t("İzinli bir ülkede / ağda çıkış noktası (proxy) tanımlıysa onu seçip yeniden tarayın."), t("Ya da tarayıcı yardımcısını izinli ağdaki bilgisayarınızda çalıştırın.")], egress: true, capture: true, retry: true },
  refused: { title: t("Bağlantı reddedildi"), why: t("Sunucu bu portta bağlantı kabul etmiyor ya da güvenlik duvarı reddediyor."), icon: IconPlugConnectedX, color: "orange",
    steps: [t("Adresteki port ve http / https doğru mu kontrol edin."), t("Erişim yalnızca belirli ağlara açıksa çıkış noktası veya tarayıcı yardımcısı kullanın.")], egress: true, capture: true, retry: true },
  reset: { title: t("Bağlantı kesildi"), why: t("Sunucu ya da aradaki güvenlik cihazı bağlantıyı kapattı; IP / ülke filtrelemesinde sık görülür."), icon: IconPlugConnectedX, color: "orange",
    steps: [t("Başka bir çıkış noktasıyla deneyin."), t("Tarayıcı yardımcısını izinli ağdan çalıştırın.")], egress: true, capture: true, retry: true },
  tls_error: { title: t("TLS sertifikası doğrulanamadı"), why: t("Sertifika kendinden imzalı, süresi dolmuş veya ad uyuşmuyor (iç ortamlarda yaygın)."), icon: IconCertificate, color: "yellow",
    steps: [t("Ortam güvenilirse TLS doğrulamasını bu hedef için kapatıp yeniden tarayın.")], tls: true },
  mtls: { title: t("Sunucu istemci sertifikası istiyor (mTLS)"), why: t("Erişim için kullanıcıya / cihaza verilmiş bir istemci sertifikası gerekiyor."), icon: IconCertificate, color: "grape",
    steps: [t("Sertifika tarayıcınızda yüklüyse tarayıcı yardımcısıyla kaydı kendi bilgisayarınızda alın."), t("Ya da sitenin trafiğini Burp / tarayıcıdan HAR olarak kaydedip yükleyin.")], capture: true },
  internal_blocked: { title: t("İç ağ adresi engellendi"), why: t("Adres özel / ayrılmış bir IP'ye çıkıyor; güvenlik için iç ağ taraması varsayılan olarak kapalıdır."), icon: IconLock, color: "red",
    steps: [t("İç ağ hedefi bilerek taranıyorsa yönetici Ayarlar → Tarama → İç ağ taramasına izin ver seçeneğini açmalıdır.")] },
  http_auth: { title: t("Sunucu HTTP kimlik doğrulaması istiyor"), why: t("Sayfalar kullanıcı adı / parola (Basic, Digest veya NTLM) olmadan açılmıyor."), icon: IconLock, color: "blue",
    steps: [t("Hedef sayfasında Kimlik doğrulama → Basic seçip test hesabını girin ve yeniden tarayın.")], auth: true },
  login_required: { title: t("Site giriş sayfasına yönlendiriyor"), why: t("İçerik oturum açmadan görünmüyor; tarama yalnızca giriş sayfasını görebildi."), icon: IconLock, color: "blue",
    steps: [t("Hedef sayfasında Kimlik doğrulama → Form ile giriş, Çerez veya Bearer token tanımlayın."), t("SSO / çok adımlı girişte: tarayıcı yardımcısını başlatın, açılan pencerede kendiniz giriş yapın; yardımcı oturum açık şekilde gezer.")], auth: true, capture: true },
  geo_block: { title: t("Coğrafi engel"), why: t("Site, tarama sunucusunun bulunduğu ülkeden erişime izin vermiyor."), icon: IconMapPinOff, color: "orange",
    steps: [t("İzinli ülkedeki bir çıkış noktasını (proxy) seçip yeniden tarayın; Otomatik modda tanımlı çıkış noktaları sırayla denenir."), t("Ya da tarayıcı yardımcısını o ülkedeki bir bilgisayarda çalıştırın.")], egress: true, capture: true },
  ip_block: { title: t("IP adresi engellendi"), why: t("Güvenlik duvarı tarama sunucusunun IP adresini engelliyor."), icon: IconMapPinOff, color: "red",
    steps: [t("Sistem sahibinden tarama IP'sini izin listesine eklemesini isteyin."), t("Başka bir çıkış noktasıyla deneyin veya tarayıcı yardımcısını kullanın.")], egress: true, capture: true },
  captcha: { title: t("CAPTCHA doğrulaması"), why: t("Site insan doğrulaması (CAPTCHA) istiyor; bu adım otomatik geçilmez."), icon: IconAlertTriangle, color: "orange",
    steps: [t("Tarayıcı yardımcısını başlatın: doğrulamayı açılan pencerede siz geçersiniz, gerisi otomatik devam eder."), t("Sistem sahibi tarama IP'sini veya tarama başlığını doğrulamadan muaf tutabilir.")], capture: true },
  unavailable: { title: t("Site geçici olarak kapalı / bakımda"), why: t("Sunucu bakım veya geçici hata sayfası döndürdü."), icon: IconAlertTriangle, color: "gray",
    steps: [t("Bir süre sonra yeniden tarayın veya sürekli tarama zamanlaması ekleyin.")], retry: true },
});

const EMPTY_HINTS = (): Record<string, { text: string; code?: { label: string; code: string }[] }> => ({
  source: { text: t("Arşivde tanınan bağımlılık dosyası yok. Kilit dosyalarının (package-lock.json, poetry.lock, go.sum, pom.xml / gradle.lockfile…) arşivde olduğundan emin olun ya da bir SBOM üretip yükleyin."),
    code: [{ label: "syft", code: "syft dir:. -o cyclonedx-json > sbom.cdx.json" }, { label: "cdxgen", code: "cdxgen -o sbom.cdx.json" }] },
  mobile: { text: t("Uygulamada tanınan kütüphane bulunamadı. App Store'dan alınan IPA şifrelidir; geliştirici / ad-hoc derlemesini yükleyin. Korumalı (paketlenmiş) APK'larda koruma öncesi derleme gerekir.") },
  image: { text: t("İmajda paket veritabanı bulunamadı (scratch / distroless olabilir). İmajdan SBOM üretip yükleyin."), code: [{ label: "syft", code: "syft <imaj>:<etiket> -o cyclonedx-json > sbom.cdx.json" }] },
  sbom: { text: t("SBOM'da bileşen yok veya bileşenlerin PURL'i eksik. Üreten aracın çıktısını kontrol edin.") },
  packages: { text: t("Paket listesi tanınamadı. dpkg -l, rpm -qa veya apk info -v çıktısını yükleyin ve işletim sistemini (ör. Debian:12) belirtin.") },
  desktop: { text: t("Kurulum paketinden bileşen çıkarılamadı. Kurulu uygulama klasörünü ZIP olarak yükleyin.") },
  "": { text: t("Yüklenen dosyalarda bileşen bulunamadı. Doğru hedef türünü seçtiğinizden emin olun.") },
});

export function AccessIssueCard({ access, targetId, projectId, targetOptions }: { access: any; targetId: number; projectId?: number; targetOptions?: any }) {
  const nav = useNavigate();
  const meta = useQuery<any>({ queryKey: ["meta"], queryFn: () => api("/meta") });
  const [egress, setEgress] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function rescan(patch?: any) {
    setBusy(true);
    try {
      if (patch) await api(`/targets/${targetId}`, { method: "PATCH", body: { options: { ...(targetOptions ?? {}), ...patch } } });
      const s = await api(`/targets/${targetId}/scans`, { method: "POST" });
      nav(`/scans/${s.id}`);
    } catch (e) { fail(e); } finally { setBusy(false); }
  }
  if (access.issue === "empty_input") {
    const h = EMPTY_HINTS()[access.type ?? ""] ?? EMPTY_HINTS()[""];
    return (
      <Card withBorder mb="lg" style={{ borderLeft: "4px solid var(--mantine-color-orange-6)" }}>
        <Group gap="sm" align="flex-start" wrap="nowrap">
          <ThemeIcon size={40} radius="md" color="orange" variant="light"><IconFileAlert size={22} /></ThemeIcon>
          <Stack gap={6} style={{ flex: 1 }}>
            <Text fw={800}>{t("Yüklenen dosyalarda bileşen bulunamadı")}</Text>
            {access.detail && <Text size="xs" c="dimmed">{access.detail}</Text>}
            <Text size="sm">{h.text}</Text>
            {h.code?.map((c) => <CodeBlock key={c.label} code={c.code} filename={c.label} lang="bash" />)}
          </Stack>
        </Group>
      </Card>
    );
  }
  const info = ISSUES()[access.issue];
  if (!info) return null;
  const names: string[] = meta.data?.egress ?? [];
  const Icon = info.icon;
  return (
    <Card withBorder mb="lg" style={{ borderLeft: `4px solid var(--mantine-color-${info.color}-6)` }}>
      <Group gap="sm" align="flex-start" wrap="nowrap">
        <ThemeIcon size={44} radius="md" color={info.color} variant="light"><Icon size={24} /></ThemeIcon>
        <div style={{ flex: 1 }}>
          <Group gap="xs"><Text fw={800}>{info.title}</Text>{access.detail && <Badge variant="light" color={info.color} tt="none">{String(access.detail).slice(0, 60)}</Badge>}</Group>
          <Text size="sm" mt={4}>{info.why}</Text>
          {access.egress_tried?.length > 0 && <Text size="xs" c="dimmed" mt={4}>{t("Denenen çıkış noktaları: {n}", { n: access.egress_tried.join(", ") })}</Text>}
          <List size="sm" mt="xs" spacing={2}>{info.steps.map((s) => <List.Item key={s}>{s}</List.Item>)}</List>
        </div>
      </Group>
      <Stack gap="sm" mt="md">
        <Group gap="xs" wrap="wrap">
          {info.retry && <Button size="xs" variant="light" leftSection={<IconRefresh size={14} />} loading={busy} onClick={() => rescan()}>{t("Yeniden tara")}</Button>}
          {info.tls && <Button size="xs" leftSection={<IconRefresh size={14} />} loading={busy} onClick={() => rescan({ verify_tls: false })}>{t("TLS doğrulamasını kapatıp yeniden tara")}</Button>}
          {info.auth && <Button size="xs" variant="light" leftSection={<IconLock size={14} />} component={Link} to={`/targets/${targetId}#auth`}>{t("Kimlik doğrulamayı ayarla")}</Button>}
        </Group>
        {info.egress && (names.length ? (
          <Group gap="xs" align="flex-end" wrap="wrap">
            <Select size="xs" label={t("Çıkış noktası")} w={220} data={names} value={egress} onChange={setEgress} placeholder={t("Seçin")} leftSection={<IconRouteAltLeft size={14} />} />
            <Button size="xs" disabled={!egress} loading={busy} onClick={() => rescan({ egress })}>{t("Bu çıkış noktasıyla yeniden tara")}</Button>
          </Group>
        ) : (
          <Alert variant="light" color="gray" icon={<IconTool size={16} />}>
            <Text size="xs">{t("Tanımlı çıkış noktası (proxy) yok. Yönetici Ayarlar → Çıkış noktaları bölümünden izinli ülkelerde / ağlarda proxy ekleyebilir; Otomatik modda engelde sırayla denenir.")}</Text>
            {meta.data && <Anchor component={Link} to="/settings?group=egress" size="xs">{t("Çıkış noktalarını ayarla →")}</Anchor>}
          </Alert>
        ))}
        {info.capture && <CaptureAssist targetId={targetId} />}
        {info.capture && projectId && <Anchor component={Link} to={`/projects/${projectId}/targets/new?type=traffic`} size="xs">{t("Ya da HAR / Burp kaydı yükleyin →")}</Anchor>}
      </Stack>
    </Card>
  );
}

const NOTE_INFO = (): Record<string, { title: string; text: string }> => ({
  "missing-lockfile": { title: t("Kilit dosyası yok"), text: t("Yalnızca manifest bulundu; sürümler aralık olarak yazıldığından eşleştirme eksik kalabilir. Kilit dosyasını da ekleyin.") },
  obfuscated: { title: t("Gizlenmiş / şifreli kod"), text: t("Sınıf adları kısaltılmış veya ikili şifreli; bu bölümden tespit sınırlı. Geliştirici derlemesi veya kaynak kod daha eksiksiz sonuç verir.") },
  packed: { title: t("Uygulama koruması (paketleyici)"), text: t("Gerçek kod çalışma anında açılıyor; DEX'ten kütüphane tespiti eksik kalır. Koruma uygulanmadan önceki derlemeyi yükleyin; native kütüphaneler ve varlıklar yine tarandı.") },
  "no-osv-coverage": { title: t("Zafiyet verisi kapsamı yok"), text: t("Bu bileşenler için açık zafiyet veritabanında ekosistem kaydı yok; envantere yazıldı ama eşleştirilemedi.") },
  "unsupported-layer": { title: t("İşlenemeyen imaj katmanı"), text: t("Bazı katmanlar açılamadı; o katmanlardaki paketler eksik olabilir.") },
});

const LOCK_CMD: Record<string, string> = {
  npm: "npm install --package-lock-only", PyPI: "pip freeze > requirements.txt  # veya: poetry lock / uv lock", Go: "go mod tidy",
  Packagist: "composer update --lock", RubyGems: "bundle lock", "crates.io": "cargo generate-lockfile", NuGet: "dotnet restore --use-lock-file", Pub: "flutter pub get",
};

export function InputNotesCard({ notes }: { notes: any[] }) {
  const groups = Object.entries(notes.reduce((m: Record<string, any[]>, n) => { (m[n.kind] ||= []).push(n); return m; }, {}));
  const info = NOTE_INFO();
  return (
    <Card withBorder mb="lg">
      <Text fw={600} mb="xs">{t("Girdi uyarıları")}</Text>
      <Stack gap="sm">
        {groups.map(([kind, items]) => (
          <div key={kind}>
            <Group gap="xs"><Badge variant="light" color="orange" tt="none">{info[kind]?.title ?? kind}</Badge><Text size="xs" c="dimmed">{t("{n} yer", { n: items.length })}</Text></Group>
            <Text size="sm" mt={4}>{info[kind]?.text}</Text>
            <List size="xs" mt={4} spacing={0}>{items.slice(0, 5).map((n, i) => <List.Item key={i}><Text span size="xs" ff="monospace">{n.location}</Text>{n.detail && kind !== "missing-lockfile" ? ` — ${n.detail}` : ""}</List.Item>)}</List>
            {kind === "missing-lockfile" && [...new Set(items.map((n) => n.detail))].filter((e) => LOCK_CMD[e]).map((e) => (
              <CodeBlock key={e} code={LOCK_CMD[e]} filename={e} lang="bash" />
            ))}
          </div>
        ))}
      </Stack>
    </Card>
  );
}
