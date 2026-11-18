import { Alert, Anchor, Badge, Button, Card, Group, List, SimpleGrid, Stack, Text, ThemeIcon } from "@mantine/core";
import { useMemo } from "react";
import { IconShieldLock } from "@tabler/icons-react";
import { Link } from "react-router-dom";
import { t } from "../i18n";
import { CodeBlock } from "./CodeBlock";
import { CaptureAssist } from "./CaptureAssist";

export const WAF_NAME: Record<string, string> = {
  cloudflare: "Cloudflare", akamai: "Akamai", imperva: "Imperva / Incapsula", "aws-waf": "AWS WAF / CloudFront", sucuri: "Sucuri",
  "f5-asm": "F5 BIG-IP ASM", perimeterx: "HUMAN / PerimeterX", datadome: "DataDome", "rate-limit": t("Hız sınırı (HTTP 429)"), captcha: t("Doğrulama sayfası (CAPTCHA)"),
};

export function WafCard({ waf, targetId, projectId }: { waf: any; targetId: number; projectId?: number }) {
  const token = useMemo(() => Array.from(crypto.getRandomValues(new Uint8Array(12)), (b) => b.toString(16).padStart(2, "0")).join(""), []);
  const name = WAF_NAME[waf.vendor] ?? waf.vendor;
  const cfRule = `(http.request.headers["x-lefureteur-scan"][0] eq "${token}")`;
  return (
    <Card withBorder mb="lg" style={{ borderLeft: "4px solid var(--mantine-color-orange-6)" }}>
      <Group gap="sm" align="flex-start" wrap="nowrap">
        <ThemeIcon size={44} radius="md" color="orange" variant="light"><IconShieldLock size={24} /></ThemeIcon>
        <div style={{ flex: 1 }}>
          <Group gap="xs"><Text fw={800}>{t("Hedef bir WAF / bot koruması arkasında")}</Text><Badge color="orange">{name}</Badge></Group>
          <Text size="sm" mt={4}>{t("{b} / {r} istek {name} tarafından engellendi veya doğrulama sayfasına yönlendirildi. Tarayıcı sayfa içeriğini göremediği için bulunan bileşenler eksik olabilir{zero}.", { b: waf.blocked, r: waf.requests, name, zero: waf.components === 0 ? t(" (hiç bileşen bulunamadı)") : "" })}</Text>
        </div>
      </Group>
      <Stack gap="sm" mt="md">
        {waf.browser_tls && <Text size="xs" c="dimmed">{t("Tarama otomatik olarak tarayıcı uyumlu TLS'e geçti ancak engel sürdü; bu genellikle JavaScript doğrulamasıdır. Tarayıcı yardımcısıyla tamamlayın.")}</Text>}
        <CaptureAssist targetId={targetId} />
        <Group justify="space-between" wrap="wrap" gap="xs">
          <Text size="sm" c="dimmed">{t("Kaydı kendiniz almak isterseniz (tarayıcı geliştirici araçları veya Burp):")}</Text>
          {projectId && <Button size="xs" variant="default" component={Link} to={`/projects/${projectId}/targets/new?type=traffic`}>{t("HAR / Burp kaydı yükle")}</Button>}
        </Group>
      </Stack>
      <Text size="sm" fw={600} mt="md">{t("Diğer seçenekler (sistem sahibinin işbirliğiyle)")}</Text>
      <SimpleGrid cols={{ base: 1, md: 2 }} mt="xs">
        <Card withBorder padding="sm">
          <Text fw={700} size="sm">1. {t("Gizli tarama başlığını izin listesine ekleyin")}</Text>
          <List size="sm" mt={6} spacing={4}>
            <List.Item>{t("Hedef sayfasında Kimlik doğrulama → \"Özel başlık\" seçin ve aşağıdaki başlığı girin.")}</List.Item>
            <List.Item>{t("Sistem sahibi WAF'ta bu başlığı taşıyan isteklere izin veren bir kural ekler.")}</List.Item>
          </List>
          <CodeBlock code={`X-LeFureteur-Scan: ${token}`} filename={t("Başlık")} lang="bash" />
          {waf.vendor === "cloudflare" && <Stack gap={4} mt="xs"><Text size="xs" c="dimmed">{t("Cloudflare → Security → WAF → Custom rules → Action: Skip (tüm bot / WAF bileşenleri), ifade:")}</Text><CodeBlock code={cfRule} filename="Cloudflare" lang="bash" /></Stack>}
          <Button component={Link} to={`/targets/${targetId}`} size="xs" mt="sm" variant="light">{t("Hedef ayarlarını aç")}</Button>
        </Card>
        <Stack gap="sm">
          <Card withBorder padding="sm">
            <Text fw={700} size="sm">2. {t("Tarama sunucusunun IP adresini izin listesine ekleyin")}</Text>
            <Text size="sm" mt={4}>{t("Le Fureteur'ün internete çıktığı IP adresini sistem sahibi WAF'ta güvenilir olarak tanımlayabilir. Ayrıca istekler arası beklemeyi artırmak hız sınırına takılmayı azaltır.")}</Text>
          </Card>
          <Card withBorder padding="sm">
            <Text fw={700} size="sm">3. {t("İçeriden tarayın")}</Text>
            <Text size="sm" mt={4}>{t("Kaynak kod, konteyner imajı veya SBOM yüklerseniz WAF devreye girmez ve sonuçlar web taramasından daha eksiksiz olur.")}</Text>
            {projectId && <Anchor component={Link} to={`/projects/${projectId}/targets/new`} size="sm">{t("Kaynak kod / SBOM hedefi ekle")} →</Anchor>}
          </Card>
        </Stack>
      </SimpleGrid>
      {waf.samples?.length > 0 && (
        <Alert mt="md" color="gray" variant="light" title={t("Örnek engellenen istekler")}>
          {waf.samples.map((s: any, i: number) => <Text key={i} size="xs" ff="monospace">{s.status} · {s.url}</Text>)}
        </Alert>
      )}
    </Card>
  );
}
