import { Anchor, Button, Card, CopyButton, Grid, Group, List, Stack, Text, ThemeIcon } from "@mantine/core";
import { useQuery } from "@tanstack/react-query";
import { IconBook, IconBrandLinkedin, IconBug, IconCheck, IconCopy, IconExternalLink, IconPresentation, IconServer } from "@tabler/icons-react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { t } from "../i18n";
import { AUTHOR_LINKEDIN, PRODUCT } from "../brand";
import { PageHeader } from "../components/ui";

function Topic({ icon: I, color, title, text }: { icon: any; color: string; title: string; text: string }) {
  return (
    <Group wrap="nowrap" align="flex-start" gap="sm">
      <ThemeIcon size={36} radius="md" variant="light" color={color}><I size={20} /></ThemeIcon>
      <div><Text fw={700} size="sm">{title}</Text><Text size="sm" c="dimmed">{text}</Text></div>
    </Group>
  );
}

export default function Contact() {
  const meta = useQuery<any>({ queryKey: ["meta"], queryFn: () => api("/meta") });
  const info = [`${PRODUCT} ${meta.data?.version ?? ""}`, `${t("Tarayıcı")}: ${navigator.userAgent}`, `${t("Adres")}: ${window.location.origin}`, `${t("Zaman")}: ${new Date().toISOString()}`].join("\n");
  return (
    <>
      <PageHeader title={t("İletişim")} sub={t("Destek, demo, kurulum ve lisans talepleri için")} />
      <Grid>
        <Grid.Col span={{ base: 12, md: 7 }}>
          <Card withBorder p="xl" style={{ background: "linear-gradient(135deg, var(--mantine-primary-color-light) 0%, var(--mantine-color-body) 70%)" }}>
            <Group wrap="nowrap" align="flex-start" gap="lg">
              <ThemeIcon size={64} radius="xl" color="blue" variant="filled"><IconBrandLinkedin size={36} /></ThemeIcon>
              <Stack gap={6}>
                <Text fw={800} size="xl">{PRODUCT}</Text>
                <Text size="sm">{t("Ürünle ilgili sorularınız, kurulum desteği, demo ve iş birliği için LinkedIn üzerinden ulaşabilirsiniz.")}</Text>
                <Text size="xs" c="dimmed" ff="monospace">linkedin.com/in/ciboh</Text>
                <Group mt="sm">
                  <Button component="a" href={AUTHOR_LINKEDIN} target="_blank" rel="noopener noreferrer" leftSection={<IconBrandLinkedin size={18} />} rightSection={<IconExternalLink size={14} />}>{t("LinkedIn'de iletişime geç")}</Button>
                  <Button component={Link} to="/guide" variant="default" leftSection={<IconBook size={16} />}>{t("Rehberi aç")}</Button>
                </Group>
              </Stack>
            </Group>
          </Card>
          <Card withBorder mt="md">
            <Text fw={700} mb="sm">{t("Size nasıl yardımcı olabiliriz?")}</Text>
            <Stack gap="md">
              <Topic icon={IconPresentation} color="indigo" title={t("Demo ve lisans")} text={t("Ekibinize canlı tanıtım, deneme süresi ve kurum içi kurulum için lisans seçenekleri.")} />
              <Topic icon={IconServer} color="teal" title={t("Kurulum desteği")} text={t("Docker / PostgreSQL kurulumu, kapalı ağda zafiyet verisi aktarımı, SSO ve CI/CD entegrasyonu.")} />
              <Topic icon={IconBug} color="red" title={t("Hata bildirimi")} text={t("Beklenmedik bir davranış mı gördünüz? Aşağıdaki sistem bilgisini ve ilgili taramanın günlüğünü ekleyin.")} />
            </Stack>
          </Card>
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 5 }}>
          <Card withBorder>
            <Text fw={700}>{t("Hata bildirirken")}</Text>
            <List size="sm" mt="xs" spacing={4}>
              <List.Item>{t("Ne yapmak istediğinizi ve ne olduğunu kısaca yazın.")}</List.Item>
              <List.Item>{t("Tarama numarasını ve Günlük sekmesindeki adımları ekleyin.")}</List.Item>
              <List.Item>{t("Müşteri verisi, parola veya token paylaşmayın.")}</List.Item>
            </List>
            <Text size="sm" fw={600} mt="md" mb={4}>{t("Sistem bilgisi")}</Text>
            <Card withBorder p="xs" bg="var(--mantine-color-default-hover)"><Text size="xs" ff="monospace" style={{ whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{info}</Text></Card>
            <CopyButton value={info}>{({ copied, copy }) => <Button mt="sm" fullWidth variant="light" color={copied ? "teal" : undefined} leftSection={copied ? <IconCheck size={16} /> : <IconCopy size={16} />} onClick={copy}>{copied ? t("Kopyalandı") : t("Sistem bilgisini kopyala")}</Button>}</CopyButton>
            <Text size="xs" c="dimmed" mt="xs">{t("Ayrıntılı sürüm ve bileşen listesi:")} <Anchor component={Link} to="/system" size="xs">{t("Sistem durumu")}</Anchor></Text>
          </Card>
        </Grid.Col>
      </Grid>
    </>
  );
}
