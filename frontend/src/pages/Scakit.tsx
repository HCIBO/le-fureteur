import { Alert, Anchor, Badge, Button, Card, Group, List, SimpleGrid, Table, Tabs, Text, ThemeIcon, Timeline, Title } from "@mantine/core";
import { useQuery } from "@tanstack/react-query";
import { IconAffiliate, IconBrandApple, IconBrandUbuntu, IconBrandWindows, IconCloudOff, IconDatabase, IconDownload, IconGitBranch, IconInfoCircle, IconShieldLock, IconTerminal2, IconUsb, IconWorld } from "@tabler/icons-react";
import { Link } from "react-router-dom";
import { api, User } from "../api";
import { PageHeader } from "../components/ui";
import { CodeBlock } from "../components/CodeBlock";
import { t } from "../i18n";

export default function Scakit({ user }: { user: User }) {
  const meta = useQuery<any>({ queryKey: ["meta"], queryFn: () => api("/meta") });
  const staff = user.role === "admin" || user.role === "analyst";
  const origin = (meta.data?.public_url || window.location.origin).replace(/\/$/, "");
  const ver = meta.data?.version ?? "0.1.0";
  const uses = [
    { icon: IconCloudOff, color: "grape", title: t("Kapalı ağ (internetsiz) kurulum"), text: t("Sunucu internete çıkamıyorsa zafiyet veritabanı internetli başka bir makinede scakit ile indirilir, USB / dosya paylaşımıyla sunucuya taşınır.") },
    { icon: IconGitBranch, color: "blue", title: t("CI/CD hattında tarama"), text: t("Derleme sırasında kaynak kodu Le Fureteur'e yükler, sonucu bekler ve politika kapısına göre derlemeyi durdurur (scakit ci).") },
    { icon: IconShieldLock, color: "orange", title: t("WAF arkasındaki siteler"), text: t("Görünür bir tarayıcı açar, doğrulamayı siz geçersiniz, trafik kaydedilip Le Fureteur'e yüklenir (scakit capture).") },
    { icon: IconTerminal2, color: "teal", title: t("Sunucusuz yerinde tarama"), text: t("Müşteri ortamında, Le Fureteur sunucusu olmadan tarama yapıp raporu (HTML, PDF, Word, SBOM) yerinde üretir.") },
  ];
  const cmds: [string, string, string][] = [
    ["scakit db download <klasör>", t("Zafiyet verisini (OSV, EPSS, KEV, NVD) bir klasöre indirir; kapalı ağa taşımak için."), "scakit db download ./vulndb-paket --no-nvd"],
    ["scakit db update [--from-dir <klasör>]", t("Yerel zafiyet veritabanını internetten veya indirilmiş klasörden günceller."), "scakit db update --from-dir /mnt/usb/vulndb-paket"],
    ["scakit db status", t("Veritabanındaki kayıt sayılarını ve son güncelleme zamanlarını gösterir."), "scakit db status"],
    ["scakit init <klasör> --name <ad>", t("Yeni bir iş (engagement) klasörü oluşturur; tüm girdiler ve raporlar burada tutulur."), "scakit init ./acme --name \"Acme portal\" --client Acme --lang tr"],
    ["scakit add <klasör> <girdi>…", t("Kaynak kod, arşiv, APK / IPA, konteyner imajı, SBOM, paket listesi veya web adresini tarayıp envantere ekler."), "scakit add ./acme ./kaynak.zip https://portal.acme.com --type auto"],
    ["scakit match <klasör>", t("Envanteri zafiyet veritabanıyla eşleştirir; bulgular oluşur."), "scakit match ./acme"],
    ["scakit report <klasör>", t("Raporları üretir: HTML, Markdown, PDF, Word, CycloneDX, SPDX, CSV."), "scakit report ./acme --lang en --formats html,pdf,cdx"],
    ["scakit suppress <klasör>", t("Kabul edilen risk / yanlış pozitif / etkilenmiyor kaydı ekler (gerekçe ve geçerlilik tarihiyle)."), "scakit suppress ./acme --id CVE-2021-23337 --kind not-affected --reason \"kullanılmıyor\""],
    ["scakit policy <klasör>", t("Lisans politikasını belirler: izinli, incelenecek, yasak SPDX kimlikleri."), "scakit policy ./acme --denied GPL-3.0-only,AGPL-3.0-only"],
    ["scakit enrich <klasör>", t("Tedarik zinciri kontrolleri (iç paket adı çakışması vb.). Varsayılan çevrimdışıdır; --online yalnızca müşteri onayıyla."), "scakit enrich ./acme --internal ic-paketler.csv"],
    ["scakit ci", t("CI'da: dosyaları Le Fureteur'e yükler, taramayı bekler, politika kapısına göre çıkış kodu verir; SARIF üretebilir."), `scakit ci --url ${origin} --project 3 --fail-on HIGH --sarif sonuc.sarif`],
    ["scakit capture", t("WAF / bot korumalı site için görünür tarayıcıyla kayıt alıp yükler (bilet tarama sayfasından alınır)."), `scakit capture --server ${origin} --ticket lfc_…`],
    ["scakit server init | run | worker", t("Le Fureteur sunucusunu kurar ve çalıştırır (yalnızca sunucu yöneticileri için)."), "scakit server run --host 0.0.0.0 --port 8000"],
  ];
  return (
    <>
      <PageHeader title={t("scakit — komut satırı aracı")} sub={t("Le Fureteur'ün tarama motoru; sunucusuz, kapalı ağda ve CI'da kullanmak için")}
        right={staff ? <Button component="a" href="/api/cli/scakit.tar.gz" leftSection={<IconDownload size={16} />}>{t("scakit {v} indir", { v: ver })}</Button> : undefined} />

      <Card withBorder mb="lg">
        <Group gap="sm" align="flex-start" wrap="nowrap">
          <ThemeIcon size={44} radius="md" variant="light"><IconTerminal2 size={24} /></ThemeIcon>
          <div>
            <Title order={4}>{t("scakit nedir?")}</Title>
            <Text size="sm" mt={4}>{t("Le Fureteur'ün arka planında taramaları yapan yazılımın komut satırı hâlidir. Web arayüzündeki taramalar, eşleştirme ve raporlar bu motorla üretilir; scakit aynı motoru doğrudan terminalden kullanmanızı sağlar. Arayüzü kullanan çoğu kullanıcının scakit'e ihtiyacı yoktur.")}</Text>
            <Text size="sm" mt={6}>{t("Sunucuda zaten kuruludur; kendi bilgisayarınıza yalnızca aşağıdaki durumlardan birinde kurmanız gerekir.")}</Text>
          </div>
        </Group>
      </Card>

      <Text fw={700} mb="xs">{t("Ne zaman gerekir?")}</Text>
      <SimpleGrid cols={{ base: 1, sm: 2, lg: 4 }} mb="lg">
        {uses.map((u) => (
          <Card key={u.title} withBorder>
            <ThemeIcon size={36} radius="md" variant="light" color={u.color} mb="xs"><u.icon size={20} /></ThemeIcon>
            <Text fw={700} size="sm">{u.title}</Text>
            <Text size="xs" c="dimmed" mt={4}>{u.text}</Text>
          </Card>
        ))}
      </SimpleGrid>

      <Card withBorder mb="lg">
        <Group gap="xs" mb="xs"><IconDownload size={18} /><Text fw={700}>{t("Kurulum")}</Text><Badge variant="light">Python 3.10+</Badge></Group>
        {staff ? (
          <Text size="sm" mb="sm">{t("Paketi bu sayfanın üstündeki düğmeyle indirin (sunucunun çalıştırdığı sürümün aynısıdır) ve bir sanal ortama kurun:")}</Text>
        ) : (
          <Alert variant="light" color="blue" icon={<IconInfoCircle size={16} />} mb="sm">{t("Tam paket yalnızca yönetici ve analistlere açıktır. CI ve WAF arkasındaki siteler için scakit gerekmez: API & CI/CD sayfasındaki tek dosyalık CI istemcisini ve tarama sayfasındaki tarayıcı yardımcısını kullanın.")}
            <Group gap="md" mt={6}><Anchor component={Link} to="/api-ci" size="sm">{t("API & CI/CD →")}</Anchor></Group></Alert>
        )}
        <Tabs defaultValue="linux">
          <Tabs.List mb="sm">
            <Tabs.Tab value="linux" leftSection={<IconBrandUbuntu size={14} />}>Linux</Tabs.Tab>
            <Tabs.Tab value="mac" leftSection={<IconBrandApple size={14} />}>macOS</Tabs.Tab>
            <Tabs.Tab value="win" leftSection={<IconBrandWindows size={14} />}>Windows</Tabs.Tab>
          </Tabs.List>
          <Tabs.Panel value="linux"><CodeBlock lang="bash" filename={t("Terminal")} code={`python3 -m venv ~/.scakit\n~/.scakit/bin/pip install ./scakit-${ver}.tar.gz\n# PDF / Word raporları da gerekiyorsa:  ~/.scakit/bin/pip install "scakit[report] @ file://$PWD/scakit-${ver}.tar.gz"\nsudo ln -sf ~/.scakit/bin/scakit /usr/local/bin/scakit\nscakit --version`} /></Tabs.Panel>
          <Tabs.Panel value="mac"><CodeBlock lang="bash" filename={t("Terminal")} code={`python3 -m venv ~/.scakit\n~/.scakit/bin/pip install ./scakit-${ver}.tar.gz\necho 'export PATH="$HOME/.scakit/bin:$PATH"' >> ~/.zshrc && source ~/.zshrc\nscakit --version`} /></Tabs.Panel>
          <Tabs.Panel value="win"><CodeBlock lang="powershell" filename="PowerShell" code={`py -m venv $HOME\\.scakit\n$HOME\\.scakit\\Scripts\\pip install .\\scakit-${ver}.tar.gz\n$HOME\\.scakit\\Scripts\\scakit --version`} /></Tabs.Panel>
        </Tabs>
        <List size="xs" c="dimmed" mt="sm" spacing={2}>
          <List.Item>{t("İsteğe bağlı ekler: [report] PDF / Word raporları, [browser-tls] tarayıcı uyumlu TLS istemcisi. scakit capture için ayrıca: pip install playwright && python -m playwright install chromium")}</List.Item>
          <List.Item>{t("Ubuntu 24.04 gibi sistemlerde pip doğrudan kuruluma izin vermez (externally-managed); yukarıdaki sanal ortam (venv) yöntemi bu yüzden kullanılır.")}</List.Item>
        </List>
      </Card>

      <Card withBorder mb="lg">
        <Group gap="xs" mb="xs"><IconDatabase size={18} /><Text fw={700}>{t("Kapalı ağda zafiyet veritabanını güncelleme")}</Text></Group>
        <Text size="sm" mb="md">{t("Le Fureteur sunucusu internete çıkamıyorsa veriler internetli başka bir makinede indirilir ve sunucuya taşınır. Bütün veri yaklaşık 450 MB'tır; içinde müşteri bilgisi yoktur, yalnızca herkese açık zafiyet kayıtları vardır.")}</Text>
        <Timeline bulletSize={28} lineWidth={2}>
          <Timeline.Item bullet={<IconWorld size={14} />} title={t("1. İnternetli makinede indirin")}>
            <Text size="xs" c="dimmed" mb={6}>{t("scakit'i yukarıdaki gibi kurun ve verileri bir klasöre indirin. Bağlantı koparsa komutu tekrar çalıştırın; inen dosyalar atlanır.")}</Text>
            <CodeBlock lang="bash" filename={t("İnternetli makine")} code={`scakit db download ./vulndb-paket          # NVD için hızlandırma: export NVD_API_KEY=...\n# yalnızca bazı ekosistemler: --ecosystems npm,PyPI,Maven   ·   NVD'siz: --no-nvd`} />
          </Timeline.Item>
          <Timeline.Item bullet={<IconUsb size={14} />} title={t("2. Klasörü sunucuya taşıyın")}>
            <Text size="xs" c="dimmed" mb={6}>{t("USB bellek, dosya paylaşımı veya scp ile vulndb-paket klasörünün tamamını sunucuya kopyalayın.")}</Text>
            <CodeBlock lang="bash" filename={t("Örnek")} code={"scp -r ./vulndb-paket kullanici@fureteur-sunucusu:/srv/vulndb-paket"} />
          </Timeline.Item>
          <Timeline.Item bullet={<IconDatabase size={14} />} title={t("3. Le Fureteur'de içe aktarın")}>
            <Text size="xs" c="dimmed" mb={6}>{t("Ayarlar → Zafiyet veritabanı bölümünde klasör yolunu yazıp \"Klasörden içe aktar\"a basın. Sunucu yöneticisiyseniz komutla da yapabilirsiniz:")}</Text>
            <CodeBlock lang="bash" filename={t("Sunucu")} code={"scakit db update --from-dir /srv/vulndb-paket\nscakit db status"} />
            {staff && <Anchor component={Link} to="/settings" size="xs">{t("Ayarlar → Zafiyet veritabanı →")}</Anchor>}
          </Timeline.Item>
        </Timeline>
      </Card>

      <Card withBorder mb="lg">
        <Group gap="xs" mb="xs"><IconTerminal2 size={18} /><Text fw={700}>{t("Komutlar")}</Text></Group>
        <Text size="xs" c="dimmed" mb="sm">{t("Her komutun ayrıntılı seçenekleri: scakit <komut> --help")}</Text>
        <Table.ScrollContainer minWidth={760}>
          <Table verticalSpacing="sm" striped>
            <Table.Thead><Table.Tr><Table.Th w={260}>{t("Komut")}</Table.Th><Table.Th>{t("Ne yapar?")}</Table.Th><Table.Th>{t("Örnek")}</Table.Th></Table.Tr></Table.Thead>
            <Table.Tbody>
              {cmds.map(([c, d, ex]) => (
                <Table.Tr key={c}><Table.Td><Text size="xs" ff="monospace" fw={600}>{c}</Text></Table.Td><Table.Td><Text size="sm">{d}</Text></Table.Td>
                  <Table.Td><Text size="xs" ff="monospace" c="dimmed" style={{ wordBreak: "break-all" }}>{ex}</Text></Table.Td></Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      </Card>

      <SimpleGrid cols={{ base: 1, md: 2 }} mb="lg">
        <Card withBorder>
          <Group gap="xs" mb="xs"><IconAffiliate size={18} /><Text fw={700}>{t("Sunucusuz uçtan uca örnek")}</Text></Group>
          <CodeBlock lang="bash" filename={t("Terminal")} code={`scakit db update                                   # bir kez (veya --from-dir)\nscakit init ./acme --name "Acme portal" --lang tr\nscakit add ./acme ./kaynak.zip ./app.apk https://portal.acme.com\nscakit match ./acme\nscakit report ./acme --formats html,pdf,docx,cdx\n# raporlar: ./acme/reports/`} />
        </Card>
        <Card withBorder>
          <Group gap="xs" mb="xs"><IconShieldLock size={18} /><Text fw={700}>{t("Güvenlik ve gizlilik")}</Text></Group>
          <List size="sm" spacing={4}>
            <List.Item>{t("Analiz tamamen çevrimdışıdır; kaynak kod ve dosyalar hiçbir dış servise gönderilmez.")}</List.Item>
            <List.Item>{t("İnternete yalnızca veritabanı indirme (herkese açık zafiyet verisi) ve web hedefinin kendisi için çıkılır.")}</List.Item>
            <List.Item>{t("enrich --online paket adlarını deps.dev / npm / PyPI'ye sorar; yalnızca müşterinin yazılı onayıyla kullanın.")}</List.Item>
            <List.Item>{t("capture çerezleri, yetki başlıklarını ve istek gövdelerini yüklemeden önce siler.")}</List.Item>
          </List>
        </Card>
      </SimpleGrid>
    </>
  );
}
