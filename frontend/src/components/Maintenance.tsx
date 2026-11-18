import { Anchor, Button, Center, Group, Paper, Stack, Switch, Text, Textarea, ThemeIcon } from "@mantine/core";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { IconBarrierBlock, IconLogout, IconTool } from "@tabler/icons-react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { PRODUCT } from "../brand";
import { t } from "../i18n";
import { fail, ok } from "./ui";

export const usePublicStatus = (interval = 60000) =>
  useQuery<{ maintenance: boolean; message: string }>({ queryKey: ["public-status"], queryFn: () => api("/public/status"), refetchInterval: interval });

export function useMaintenanceBlock() {
  const [msg, setMsg] = useState<string | null>(null);
  useEffect(() => {
    const h = (e: Event) => setMsg((e as CustomEvent).detail ?? "");
    window.addEventListener("lf-maintenance", h);
    return () => window.removeEventListener("lf-maintenance", h);
  }, []);
  return msg;
}

export function MaintenanceScreen({ message, onLogout }: { message: string; onLogout: () => void }) {
  return (
    <Center h="100vh" p="md" style={{ background: "radial-gradient(circle at 30% 20%, #312e81 0%, #0f172a 60%)" }}>
      <Paper radius="lg" p="xl" maw={480} w="100%" shadow="xl">
        <Stack align="center" ta="center" gap="sm">
          <ThemeIcon size={64} radius="xl" color="orange" variant="light"><IconBarrierBlock size={34} /></ThemeIcon>
          <Text fw={800} size="xl">{t("Bakım çalışması")}</Text>
          <Text c="dimmed">{t("{p} şu anda bakımda. Bu sürede yalnızca yöneticiler işlem yapabilir; verileriniz güvende.", { p: PRODUCT })}</Text>
          {message && <Paper withBorder p="sm" radius="md" w="100%" bg="var(--mantine-color-orange-light)"><Text size="sm" style={{ whiteSpace: "pre-wrap" }}>{message}</Text></Paper>}
          <Group mt="sm">
            <Button variant="default" onClick={() => window.location.reload()}>{t("Tekrar dene")}</Button>
            <Button variant="subtle" color="gray" leftSection={<IconLogout size={16} />} onClick={onLogout}>{t("Çıkış")}</Button>
          </Group>
        </Stack>
      </Paper>
    </Center>
  );
}

export function AdminMaintenanceBanner() {
  const st = usePublicStatus();
  if (!st.data?.maintenance) return null;
  return (
    <Paper radius={0} px="md" py={6} bg="orange.6" c="white">
      <Group gap="xs" justify="center">
        <IconTool size={16} />
        <Text size="sm" fw={600}>{t("Bakım modu açık: yönetici dışındaki kullanıcılar sisteme erişemiyor.")}</Text>
        <Anchor component={Link} to="/system" size="sm" c="white" fw={700} underline="always">{t("Kapat")}</Anchor>
      </Group>
    </Paper>
  );
}

export function MaintenanceCard() {
  const qc = useQueryClient();
  const st = usePublicStatus(15000);
  const settings = useQuery<any[]>({ queryKey: ["settings"], queryFn: () => api("/settings") });
  const current = settings.data?.find((x: any) => x.key === "maintenance_message")?.value ?? "";
  const [msg, setMsg] = useState<string | null>(null);
  const on = !!st.data?.maintenance;
  async function save(enable: boolean) {
    if (enable && !confirm(t("Bakım modu açılsın mı? Yönetici dışındaki tüm kullanıcılar (API token'ları dahil) hemen engellenir."))) return;
    try {
      await api("/settings", { method: "PUT", body: { maintenance_mode: enable ? "1" : "0", maintenance_message: msg ?? current } });
      ok(enable ? t("Bakım modu açıldı") : t("Bakım modu kapatıldı"));
      qc.invalidateQueries({ queryKey: ["public-status"] }); qc.invalidateQueries({ queryKey: ["settings"] });
    } catch (e) { fail(e); }
  }
  return (
    <Paper withBorder p="md" radius="md" style={{ borderLeft: `4px solid var(--mantine-color-${on ? "orange" : "gray"}-5)` }}>
      <Group justify="space-between" align="flex-start" wrap="nowrap">
        <Group gap="sm" align="flex-start" wrap="nowrap">
          <ThemeIcon size={40} radius="md" variant="light" color={on ? "orange" : "gray"}><IconBarrierBlock size={22} /></ThemeIcon>
          <div>
            <Text fw={700}>{t("Bakım modu")}</Text>
            <Text size="sm" c="dimmed" maw={560}>{t("Güncelleme, geri yükleme veya veritabanı işlemlerinden önce açın. Açıkken yalnızca yöneticiler giriş yapabilir; diğer kullanıcılar ve API token'ları bakım ekranı görür, zamanlanmış taramalar başlamaz. Çalışan taramalar tamamlanır.")}</Text>
          </div>
        </Group>
        <Switch size="lg" checked={on} onChange={(e) => save(e.currentTarget.checked)} onLabel={t("AÇIK")} offLabel={t("KAPALI")} color="orange" />
      </Group>
      <Textarea mt="sm" label={t("Kullanıcılara gösterilecek mesaj")} placeholder={t("ör. Sürüm yükseltmesi nedeniyle 22:00'ye kadar bakımdayız.")} value={msg ?? current} onChange={(e) => setMsg(e.currentTarget.value)} autosize minRows={2} maxLength={500} />
      {msg !== null && msg !== current && <Group justify="flex-end" mt="xs"><Button size="xs" variant="light" onClick={() => save(on)}>{t("Mesajı kaydet")}</Button></Group>}
    </Paper>
  );
}
