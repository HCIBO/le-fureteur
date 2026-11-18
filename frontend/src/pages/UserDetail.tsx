import { Anchor, Avatar, Badge, Button, Card, Code, Group, SimpleGrid, Table, Tabs, Text, ThemeIcon, Tooltip } from "@mantine/core";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { IconAlertTriangle, IconArrowLeft, IconBrowser, IconCircleCheck, IconCircleX, IconDevices, IconHistory, IconKey, IconListCheck, IconLogin, IconLogout, IconUsersGroup } from "@tabler/icons-react";
import { Link, useParams } from "react-router-dom";
import { api, fmtDate, ROLE_LABEL } from "../api";
import { t } from "../i18n";
import { fail, ok } from "../components/ui";
import { TEAM_ROLE } from "../components/OrgChart";

const REASON: Record<string, string> = {
  bad_password: t("Hatalı parola"), no_account: t("Hesap yok"), inactive: t("Hesap devre dışı"),
  throttled: t("Çok fazla deneme (kilitli)"), maintenance: t("Bakım modu"),
};

function Stat({ icon: I, color, label, value }: { icon: any; color: string; label: string; value: any }) {
  return (
    <Card withBorder padding="sm"><Group gap="sm" wrap="nowrap">
      <ThemeIcon size={36} radius="md" variant="light" color={color}><I size={20} /></ThemeIcon>
      <div><Text size="xs" c="dimmed">{label}</Text><Text fw={700} size="lg" lh={1.2}>{value}</Text></div>
    </Group></Card>
  );
}

export default function UserDetail() {
  const { id } = useParams();
  const qc = useQueryClient();
  const q = useQuery<any>({ queryKey: ["user-detail", id], queryFn: () => api(`/users/${id}/detail`) });
  if (!q.data) return null;
  const { user: u, stats, sessions, logins, actions, teams } = q.data;
  async function revoke(sid?: number) {
    if (!confirm(sid ? t("Bu oturum sonlandırılsın mı?") : t("Kullanıcının tüm oturumları sonlandırılsın mı? Yeniden giriş yapması gerekir."))) return;
    try {
      const r = await api(`/users/${u.id}/sessions${sid ? `?session_id=${sid}` : ""}`, { method: "DELETE" });
      ok(t("{n} oturum sonlandırıldı", { n: r.revoked })); qc.invalidateQueries({ queryKey: ["user-detail", id] });
    } catch (e) { fail(e); }
  }
  return (
    <>
      <Anchor component={Link} to="/users" size="sm"><Group gap={4}><IconArrowLeft size={14} />{t("Kullanıcılar")}</Group></Anchor>
      <Card withBorder mt="xs" mb="md">
        <Group justify="space-between" wrap="wrap">
          <Group gap="md" wrap="nowrap">
            <Avatar size={64} radius="xl" color={u.role === "admin" ? "red" : u.role === "analyst" ? "indigo" : "teal"}>{(u.name || u.email)[0].toUpperCase()}</Avatar>
            <div>
              <Group gap="xs"><Text fw={800} size="xl">{u.name || u.email}</Text>
                <Badge variant="light" color={u.role === "admin" ? "red" : u.role === "analyst" ? "indigo" : "teal"}>{ROLE_LABEL[u.role]}</Badge>
                {!u.active && <Badge color="gray">{t("Devre dışı")}</Badge>}</Group>
              <Text size="sm" c="dimmed">{u.email}{u.organization ? ` · ${u.organization}` : ""}</Text>
              <Group gap={6} mt={4}>{teams.map((tm: any) => <Badge key={tm.id} size="sm" variant="outline" tt="none" leftSection={<IconUsersGroup size={11} />}>{tm.name} · {TEAM_ROLE[tm.role]?.label}</Badge>)}</Group>
            </div>
          </Group>
          <Button color="red" variant="light" leftSection={<IconLogout size={16} />} onClick={() => revoke()} disabled={!sessions.length}>{t("Tüm oturumları sonlandır")}</Button>
        </Group>
        <SimpleGrid cols={{ base: 2, md: 4 }} mt="md" spacing="xs">
          <div><Text size="xs" c="dimmed">{t("Oluşturulma")}</Text><Text size="sm">{fmtDate(u.created_at)}</Text></div>
          <div><Text size="xs" c="dimmed">{t("Son giriş")}</Text><Text size="sm">{fmtDate(u.last_login)}</Text></div>
          <div><Text size="xs" c="dimmed">{t("Son IP")}</Text><Text size="sm" ff="monospace">{q.data.last_ip ?? "—"}</Text></div>
          <div><Text size="xs" c="dimmed">{t("Son cihaz")}</Text><Tooltip label={q.data.last_user_agent ?? ""} disabled={!q.data.last_user_agent} multiline w={360}><Text size="sm">{q.data.last_device || "—"}</Text></Tooltip></div>
        </SimpleGrid>
      </Card>
      <SimpleGrid cols={{ base: 2, md: 4 }} mb="md">
        <Stat icon={IconDevices} color="indigo" label={t("Etkin oturum")} value={stats.sessions} />
        <Stat icon={IconAlertTriangle} color={stats.failed_logins_30d ? "red" : "gray"} label={t("Başarısız giriş (30 gün)")} value={stats.failed_logins_30d} />
        <Stat icon={IconListCheck} color="teal" label={t("Açık atanmış bulgu")} value={stats.open_assigned} />
        <Stat icon={IconKey} color="grape" label={t("API token")} value={stats.api_tokens} />
      </SimpleGrid>
      <Tabs defaultValue="sessions">
        <Tabs.List mb="md">
          <Tabs.Tab value="sessions" leftSection={<IconDevices size={14} />}>{t("Oturumlar")}</Tabs.Tab>
          <Tabs.Tab value="logins" leftSection={<IconLogin size={14} />}>{t("Giriş geçmişi")}</Tabs.Tab>
          <Tabs.Tab value="actions" leftSection={<IconHistory size={14} />}>{t("Son işlemler")}</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="sessions">
          <Card withBorder p={0}><Table.ScrollContainer minWidth={760}><Table verticalSpacing="sm">
            <Table.Thead><Table.Tr><Table.Th>{t("Cihaz")}</Table.Th><Table.Th>{t("IP")}</Table.Th><Table.Th>{t("Başlangıç")}</Table.Th><Table.Th>{t("Son etkinlik")}</Table.Th><Table.Th>{t("Bitiş")}</Table.Th><Table.Th /></Table.Tr></Table.Thead>
            <Table.Tbody>
              {sessions.map((s: any) => (
                <Table.Tr key={s.id}>
                  <Table.Td><Group gap="xs" wrap="nowrap"><IconBrowser size={16} /><div><Text size="sm">{s.device || t("Bilinmiyor")}</Text><Text size="xs" c="dimmed">{s.method === "sso" ? "SSO" : t("Parola")}</Text></div></Group></Table.Td>
                  <Table.Td><Text size="sm" ff="monospace">{s.ip}</Text>{s.first_ip !== s.ip && <Text size="xs" c="dimmed">{t("ilk")}: {s.first_ip}</Text>}</Table.Td>
                  <Table.Td><Text size="sm">{fmtDate(s.created_at)}</Text></Table.Td>
                  <Table.Td><Text size="sm">{fmtDate(s.last_seen_at)}</Text></Table.Td>
                  <Table.Td><Text size="sm" c="dimmed">{fmtDate(s.expires_at)}</Text></Table.Td>
                  <Table.Td ta="right"><Button size="xs" variant="subtle" color="red" onClick={() => revoke(s.id)}>{t("Sonlandır")}</Button></Table.Td>
                </Table.Tr>
              ))}
              {!sessions.length && <Table.Tr><Table.Td colSpan={6}><Text c="dimmed" ta="center" py="md" size="sm">{t("Etkin oturum yok")}</Text></Table.Td></Table.Tr>}
            </Table.Tbody>
          </Table></Table.ScrollContainer></Card>
        </Tabs.Panel>
        <Tabs.Panel value="logins">
          <Card withBorder p={0}><Table.ScrollContainer minWidth={760}><Table verticalSpacing="xs" striped>
            <Table.Thead><Table.Tr><Table.Th>{t("Zaman")}</Table.Th><Table.Th>{t("Sonuç")}</Table.Th><Table.Th>{t("Yöntem")}</Table.Th><Table.Th>{t("IP")}</Table.Th><Table.Th>{t("Cihaz")}</Table.Th></Table.Tr></Table.Thead>
            <Table.Tbody>
              {logins.map((e: any) => (
                <Table.Tr key={e.id}>
                  <Table.Td><Text size="sm">{fmtDate(e.at)}</Text></Table.Td>
                  <Table.Td>{e.success ? <Badge color="green" variant="light" leftSection={<IconCircleCheck size={12} />}>{t("Başarılı")}</Badge>
                    : <Badge color="red" variant="light" leftSection={<IconCircleX size={12} />}>{REASON[e.reason] ?? t("Başarısız")}</Badge>}</Table.Td>
                  <Table.Td><Text size="sm">{e.method === "sso" ? "SSO" : t("Parola")}</Text></Table.Td>
                  <Table.Td><Text size="sm" ff="monospace">{e.ip}</Text></Table.Td>
                  <Table.Td><Tooltip label={e.user_agent} disabled={!e.user_agent} multiline w={360}><Text size="sm">{e.device || "—"}</Text></Tooltip></Table.Td>
                </Table.Tr>
              ))}
              {!logins.length && <Table.Tr><Table.Td colSpan={5}><Text c="dimmed" ta="center" py="md" size="sm">{t("Kayıt yok")}</Text></Table.Td></Table.Tr>}
            </Table.Tbody>
          </Table></Table.ScrollContainer></Card>
        </Tabs.Panel>
        <Tabs.Panel value="actions">
          <Card withBorder p={0}><Table.ScrollContainer minWidth={760}><Table verticalSpacing="xs" striped>
            <Table.Thead><Table.Tr><Table.Th>{t("Zaman")}</Table.Th><Table.Th>{t("İşlem")}</Table.Th><Table.Th>{t("Nesne")}</Table.Th><Table.Th>{t("Ayrıntı")}</Table.Th><Table.Th>{t("IP")}</Table.Th></Table.Tr></Table.Thead>
            <Table.Tbody>
              {actions.map((a: any) => (
                <Table.Tr key={a.id}>
                  <Table.Td><Text size="sm">{fmtDate(a.at)}</Text></Table.Td><Table.Td><Code>{a.action}</Code></Table.Td>
                  <Table.Td><Text size="xs">{a.object}</Text></Table.Td><Table.Td><Text size="xs" lineClamp={2} maw={380}>{t(a.detail ?? "")}</Text></Table.Td>
                  <Table.Td><Text size="xs" ff="monospace">{a.ip}</Text></Table.Td>
                </Table.Tr>
              ))}
              {!actions.length && <Table.Tr><Table.Td colSpan={5}><Text c="dimmed" ta="center" py="md" size="sm">{t("Kayıt yok")}</Text></Table.Td></Table.Tr>}
            </Table.Tbody>
          </Table></Table.ScrollContainer></Card>
          <Anchor component={Link} to={`/audit?user=${encodeURIComponent(u.email)}`} size="sm" mt="xs" display="block">{t("Denetim kaydında tümünü gör")} →</Anchor>
        </Tabs.Panel>
      </Tabs>
    </>
  );
}
