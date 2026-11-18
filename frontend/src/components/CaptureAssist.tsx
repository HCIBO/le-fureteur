import { Anchor, Badge, Button, Group, List, Loader, Paper, Stack, Tabs, Text, ThemeIcon } from "@mantine/core";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { IconBrowserCheck, IconCircleCheck, IconDownload, IconPlayerPlay } from "@tabler/icons-react";
import { Link } from "react-router-dom";
import { api, fmtDate } from "../api";
import { t } from "../i18n";
import { CodeBlock } from "./CodeBlock";
import { fail } from "./ui";

export function CaptureAssist({ targetId }: { targetId: number }) {
  const [ticket, setTicket] = useState<{ ticket: string; expires_at: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const status = useQuery<any>({ queryKey: ["capture-status", targetId], queryFn: () => api(`/targets/${targetId}/capture-status`), refetchInterval: ticket ? 3000 : false });
  const st = status.data?.ticket;
  const origin = window.location.origin;
  async function start() {
    setBusy(true);
    try { setTicket(await api(`/targets/${targetId}/capture-ticket`, { method: "POST" })); status.refetch(); } catch (e) { fail(e); } finally { setBusy(false); }
  }
  const done = ticket && st?.used_at && st?.result_scan_id;
  return (
    <Paper withBorder p="md" radius="md" style={{ borderColor: "var(--mantine-color-green-5)", background: "var(--mantine-color-green-light)" }}>
      <Group justify="space-between" align="flex-start" wrap="wrap" gap="sm">
        <Group gap="sm" wrap="nowrap" align="flex-start" style={{ flex: "1 1 380px" }}>
          <ThemeIcon size={40} radius="md" color="green"><IconBrowserCheck size={22} /></ThemeIcon>
          <div>
            <Group gap="xs"><Badge color="green">{t("Önerilen")}</Badge><Text fw={800}>{t("Tarayıcı yardımcısıyla otomatik tamamla")}</Text></Group>
            <Text size="sm" mt={4}>{t("Kendi bilgisayarınızda tek komutla görünür bir tarayıcı açılır. Doğrulama çıkarsa siz geçersiniz; yardımcı siteyi kendisi gezer, kaydı temizleyip yükler ve taramayı başlatır.")}</Text>
          </div>
        </Group>
        {!ticket && <Button color="green" leftSection={<IconPlayerPlay size={16} />} onClick={start} loading={busy}>{t("Yardımcıyı başlat")}</Button>}
      </Group>
      {ticket && !done && (
        <Stack gap="xs" mt="md">
          <Tabs defaultValue={/Win/i.test(navigator.platform) ? "win" : "unix"} variant="pills" radius="md">
            <Tabs.List mb="xs">
              <Tabs.Tab value="unix">Linux / macOS</Tabs.Tab>
              <Tabs.Tab value="win">Windows</Tabs.Tab>
              <Tabs.Tab value="cli">{t("scakit kuruluysa")}</Tabs.Tab>
            </Tabs.List>
            <Tabs.Panel value="unix">
              <Stack gap="xs">
                <Text size="sm" fw={700}>1. {t("İlk kullanımda bir kez kurun (scakit gerekmez)")}</Text>
                <CodeBlock code={"python3 -m venv ~/.lf-capture\n~/.lf-capture/bin/pip install playwright\n~/.lf-capture/bin/python -m playwright install --with-deps chromium"} filename={t("Kurulum")} lang="bash" />
                <Text size="sm" fw={700}>2. {t("Yardımcıyı indirip çalıştırın")}</Text>
                <CodeBlock code={`curl -fsSL ${origin}/api/capture/helper.py -o lf_capture.py\n~/.lf-capture/bin/python lf_capture.py --server ${origin} --ticket ${ticket.ticket}`} filename={t("Komut")} lang="bash" />
              </Stack>
            </Tabs.Panel>
            <Tabs.Panel value="win">
              <Stack gap="xs">
                <Text size="sm" fw={700}>1. {t("İlk kullanımda bir kez kurun (scakit gerekmez)")}</Text>
                <Text size="xs" c="dimmed">{t("Python yoksa python.org'dan kurun (\"Add python.exe to PATH\" işaretli). Ardından PowerShell'de:")}</Text>
                <CodeBlock code={"py -m pip install playwright\npy -m playwright install chromium"} filename="PowerShell" lang="bash" />
                <Text size="sm" fw={700}>2. {t("Yardımcıyı indirip çalıştırın")}</Text>
                <CodeBlock code={`Invoke-WebRequest ${origin}/api/capture/helper.py -OutFile lf_capture.py\npy lf_capture.py --server ${origin} --ticket ${ticket.ticket}`} filename="PowerShell" lang="bash" />
              </Stack>
            </Tabs.Panel>
            <Tabs.Panel value="cli">
              <Stack gap="xs">
                <Text size="sm">{t("Le Fureteur komut satırı aracı (scakit) bilgisayarınızda kuruluysa ayrıca dosya indirmeniz gerekmez; yalnızca Playwright'ı bir kez kurun.")}</Text>
                <CodeBlock code={`python3 -m pip install playwright && python3 -m playwright install --with-deps chromium\nscakit capture --server ${origin} --ticket ${ticket.ticket}`} filename={t("Komut")} lang="bash" />
                <Text size="xs" c="dimmed">{t("scakit kurulu değilse Linux / macOS veya Windows sekmesindeki adımları izleyin; yardımcı tek dosyadır ve scakit gerektirmez.")}</Text>
              </Stack>
            </Tabs.Panel>
          </Tabs>
          <Text size="xs" c="dimmed">{t("İpucu: her sayfada görünen kısa doğrulama tarayıcı tarafından kendiliğinden geçilir; yalnızca kutucuk / bulmaca çıkarsa sizin tıklamanız gerekir. Pencereyi kapatırsanız o ana kadarki kayıt yine yüklenir.")} <Anchor href="/api/capture/helper.py" size="xs" download><IconDownload size={12} /> lf_capture.py</Anchor></Text>
          <Group gap="xs"><Loader size="xs" /><Text size="sm">{t("Yardımcının kaydı yüklemesi bekleniyor… Bilet {date} tarihine kadar geçerli ve tek kullanımlık.", { date: fmtDate(ticket.expires_at) })}</Text></Group>
          <List size="xs" c="dimmed" spacing={2}>
            <List.Item>{t("Yardımcı doğrulamayı çözmez, gizlenmez; doğrulamayı siz geçersiniz. Yalnızca test izniniz olan adreslerde kullanın.")}</List.Item>
            <List.Item>{t("Çerezler, yetki başlıkları ve istek gövdeleri kayıttan silinerek yüklenir.")}</List.Item>
          </List>
        </Stack>
      )}
      {done && (
        <Group mt="md" gap="xs">
          <IconCircleCheck size={18} color="var(--mantine-color-green-7)" />
          <Text size="sm" fw={600}>{t("Kayıt alındı ve tarama başladı.")}</Text>
          <Anchor component={Link} to={`/scans/${st.result_scan_id}`} size="sm">{t("Tarama #{n}", { n: st.result_scan_id })} →</Anchor>
        </Group>
      )}
    </Paper>
  );
}
