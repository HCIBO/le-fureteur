import { Anchor, Avatar, Badge, Button, Card, Group, Progress, SimpleGrid, Table, Tabs, Text, ThemeIcon, Tooltip } from "@mantine/core";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { IconAlertTriangle, IconArrowLeft, IconChecks, IconClockExclamation, IconGavel, IconListCheck, IconMail, IconSitemap, IconTrophy } from "@tabler/icons-react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, SEV_COLOR, fmtDay } from "../api";
import { t } from "../i18n";
import { SevBadge, StatusBadge } from "../components/ui";
import { OrgChart, TEAM_ROLE } from "../components/OrgChart";
import { ComposeModal } from "../components/Messaging";

const SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

function Kpi({ icon: I, color, label, value, hint }: { icon: any; color: string; label: string; value: number; hint?: string }) {
  return (
    <Card withBorder padding="md">
      <Group gap="sm" wrap="nowrap">
        <ThemeIcon size={40} radius="md" variant="light" color={color}><I size={22} /></ThemeIcon>
        <div><Text size="xs" c="dimmed">{label}</Text><Text fw={800} size="xl" lh={1.1}>{value}</Text>{hint && <Text size="xs" c="dimmed">{hint}</Text>}</div>
      </Group>
    </Card>
  );
}

function SevBar({ by }: { by: Record<string, number> }) {
  const total = SEVS.reduce((a, s) => a + (by[s] ?? 0), 0);
  if (!total) return <Text size="xs" c="dimmed">—</Text>;
  return (
    <Tooltip label={SEVS.filter((s) => by[s]).map((s) => `${s}: ${by[s]}`).join(" · ")}>
      <Progress.Root size={10} w={140}>
        {SEVS.filter((s) => by[s]).map((s) => <Progress.Section key={s} value={(by[s] / total) * 100} color={SEV_COLOR[s]} />)}
      </Progress.Root>
    </Tooltip>
  );
}

function FindingRows({ rows, delivered }: { rows: any[]; delivered?: boolean }) {
  const nav = useNavigate();
  if (!rows.length) return <Text size="sm" c="dimmed" ta="center" py="lg">{delivered ? t("Son 30 günde kapatılan bulgu yok") : t("Takımın açık işi yok")}</Text>;
  const now = Date.now();
  return (
    <Table.ScrollContainer minWidth={720}>
      <Table highlightOnHover verticalSpacing="xs">
        <Table.Thead><Table.Tr><Table.Th>{t("Şiddet")}</Table.Th><Table.Th>{t("Zafiyet")}</Table.Th><Table.Th>{t("Atanan")}</Table.Th><Table.Th>{delivered ? t("Durum") : t("Son tarih")}</Table.Th></Table.Tr></Table.Thead>
        <Table.Tbody>
          {rows.map((f) => {
            const late = f.due_date && new Date(f.due_date).getTime() < now;
            return (
              <Table.Tr key={f.id} style={{ cursor: "pointer" }} onClick={() => nav(`/findings?open=${f.id}`)}>
                <Table.Td><SevBadge sev={f.severity} /></Table.Td>
                <Table.Td><Text size="sm" fw={600}>{f.cves?.[0] ?? f.vuln_id}</Text><Text size="xs" c="dimmed">{f.component} {f.version}</Text></Table.Td>
                <Table.Td><Group gap={6} wrap="nowrap"><Avatar size="sm" radius="xl" color="indigo">{(f.assignee?.email ?? "?")[0].toUpperCase()}</Avatar><Text size="sm">{f.assignee?.name || f.assignee?.email}</Text></Group></Table.Td>
                <Table.Td>{delivered ? <StatusBadge status={f.status} />
                  : f.due_date ? <Badge variant={late ? "filled" : "light"} color={late ? "red" : "gray"} leftSection={late ? <IconAlertTriangle size={11} /> : null}>{fmtDay(f.due_date)}</Badge>
                  : <Text size="xs" c="dimmed">{t("belirtilmedi")}</Text>}</Table.Td>
              </Table.Tr>
            );
          })}
        </Table.Tbody>
      </Table>
    </Table.ScrollContainer>
  );
}

export default function TeamDetail() {
  const { id } = useParams();
  const nav = useNavigate();
  const q = useQuery<any>({ queryKey: ["team-overview", id], queryFn: () => api(`/teams/${id}/overview`) });
  const [compose, setCompose] = useState<null | { team?: number; users?: number[] }>(null);
  if (!q.data) return null;
  const { team, totals, people, queue, delivered } = q.data;
  const maxOpen = Math.max(1, ...people.map((p: any) => p.open));
  return (
    <>
      <Anchor component={Link} to="/teams" size="sm"><Group gap={4}><IconArrowLeft size={14} />{t("Takımlar")}</Group></Anchor>
      <Group justify="space-between" align="flex-end" mt="xs" mb="lg">
        <div>
          <Text fw={800} size="28px" lh={1.2}>{team.name}</Text>
          <Text c="dimmed" size="sm">{team.organization ?? t("İç takım (danışmanlık)")} · {t("{n} kişi", { n: team.members.length })}{team.description ? ` · ${team.description}` : ""}</Text>
        </div>
        <Button leftSection={<IconMail size={16} />} onClick={() => setCompose({ team: team.id })}>{t("Takıma mesaj")}</Button>
      </Group>

      <SimpleGrid cols={{ base: 2, md: 3, lg: 6 }} mb="lg">
        <Kpi icon={IconListCheck} color="indigo" label={t("Açık iş")} value={totals.open} />
        <Kpi icon={IconAlertTriangle} color="red" label={t("Kritik")} value={totals.critical} />
        <Kpi icon={IconClockExclamation} color="orange" label={t("Gecikmiş")} value={totals.overdue} />
        <Kpi icon={IconTrophy} color="green" label={t("Teslim (30 gün)")} value={totals.delivered_30d} />
        <Kpi icon={IconChecks} color="yellow" label={t("Bekleyen onay")} value={totals.pending_approvals} />
        <Kpi icon={IconGavel} color="grape" label={t("Açık tartışma")} value={totals.open_disputes} />
      </SimpleGrid>

      <Card withBorder mb="lg">
        <Group gap="xs" mb="md"><IconSitemap size={18} /><Text fw={700}>{t("Organizasyon şeması")}</Text></Group>
        <OrgChart members={people} onClick={(m) => nav(`/findings?assignee=${m.user.id}`)} />
        <Text size="xs" c="dimmed" ta="center" mt="xs">{t("Bir kişiye tıklayarak ona atanmış bulguları açın.")}</Text>
      </Card>

      <Tabs defaultValue="people">
        <Tabs.List mb="md">
          <Tabs.Tab value="people">{t("Kişi başı iş yükü")}</Tabs.Tab>
          <Tabs.Tab value="queue" rightSection={<Badge size="xs" variant="light">{queue.length}</Badge>}>{t("İş kuyruğu")}</Tabs.Tab>
          <Tabs.Tab value="delivered" rightSection={<Badge size="xs" variant="light" color="green">{delivered.length}</Badge>}>{t("Teslim edilenler")}</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="people">
          <Card withBorder p={0}>
            <Table.ScrollContainer minWidth={760}>
              <Table verticalSpacing="sm">
                <Table.Thead><Table.Tr><Table.Th>{t("Kişi")}</Table.Th><Table.Th>{t("Açık iş")}</Table.Th><Table.Th>{t("Şiddet dağılımı")}</Table.Th><Table.Th>{t("Gecikmiş")}</Table.Th><Table.Th>{t("Teslim (30 gün)")}</Table.Th><Table.Th /></Table.Tr></Table.Thead>
                <Table.Tbody>
                  {people.map((p: any) => {
                    const R = TEAM_ROLE[p.role];
                    return (
                      <Table.Tr key={p.user.id}>
                        <Table.Td><Group gap="sm" wrap="nowrap"><Avatar radius="xl" color={R.color} variant="light">{(p.user.name || p.user.email)[0].toUpperCase()}</Avatar>
                          <div><Text size="sm" fw={600}>{p.user.name || p.user.email}</Text><Group gap={4}><R.icon size={11} /><Text size="xs" c="dimmed">{R.label}</Text></Group></div></Group></Table.Td>
                        <Table.Td><Group gap="xs" wrap="nowrap"><Progress value={(p.open / maxOpen) * 100} w={80} size="sm" color="indigo" /><Text size="sm" fw={600}>{p.open}</Text></Group></Table.Td>
                        <Table.Td><SevBar by={p.by_severity} /></Table.Td>
                        <Table.Td>{p.overdue ? <Badge color="red" variant="filled">{p.overdue}</Badge> : <Text size="sm" c="dimmed">0</Text>}</Table.Td>
                        <Table.Td><Text size="sm" c={p.delivered_30d ? "green" : "dimmed"} fw={p.delivered_30d ? 600 : 400}>{p.delivered_30d}</Text></Table.Td>
                        <Table.Td ta="right"><Group gap={4} justify="flex-end" wrap="nowrap">
                          <Button size="xs" variant="default" component={Link} to={`/findings?assignee=${p.user.id}`}>{t("Bulguları")}</Button>
                          <Button size="xs" variant="light" leftSection={<IconMail size={13} />} onClick={() => setCompose({ users: [p.user.id] })}>{t("Mesaj")}</Button>
                        </Group></Table.Td>
                      </Table.Tr>
                    );
                  })}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
          </Card>
        </Tabs.Panel>
        <Tabs.Panel value="queue"><Card withBorder p={0}><FindingRows rows={queue} /></Card>
          <Text size="xs" c="dimmed" mt="xs">{t("Sıralama: önce son tarihi yaklaşan / geçen, sonra şiddet.")}</Text></Tabs.Panel>
        <Tabs.Panel value="delivered"><Card withBorder p={0}><FindingRows rows={delivered} delivered /></Card>
          <Text size="xs" c="dimmed" mt="xs">{t("Son 30 günde takım üyelerine atanmış ve kapatılmış (düzeltildi, risk kabulü vb.) bulgular.")}</Text></Tabs.Panel>
      </Tabs>
      <ComposeModal opened={compose !== null} onClose={() => setCompose(null)} teamId={compose?.team} userIds={compose?.users} />
    </>
  );
}
