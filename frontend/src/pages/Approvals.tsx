import { Anchor, Avatar, Badge, Blockquote, Button, Card, Drawer, Group, Modal, SimpleGrid, Stack, Table, Tabs, Text, Textarea, ThemeIcon, Timeline } from "@mantine/core";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { IconArrowRight, IconCheck, IconChecks, IconClock, IconGavel, IconSend, IconX } from "@tabler/icons-react";
import { Link } from "react-router-dom";
import { api, fmtDate, ROLE_LABEL, STATUS_LABEL } from "../api";
import { t } from "../i18n";
import { fail, ok, PageHeader, SevBadge, StatusBadge } from "../components/ui";
import { PageIntro } from "../components/PageIntro";

const STATE: Record<string, { color: string; label: string; icon: any }> = {
  pending: { color: "orange", label: t("Bekliyor"), icon: IconClock },
  approved: { color: "green", label: t("Onaylandı"), icon: IconCheck },
  rejected: { color: "red", label: t("Reddedildi"), icon: IconX },
  canceled: { color: "gray", label: t("Geri çekildi"), icon: IconArrowRight },
};

function StateBadge({ state }: { state: string }) {
  const S = STATE[state];
  return <Badge variant="light" color={S.color} leftSection={<S.icon size={12} />}>{S.label}</Badge>;
}

function PersonCard({ title, u, extra }: { title: string; u: any; extra?: string }) {
  return (
    <Card withBorder padding="sm">
      <Text size="xs" c="dimmed" tt="uppercase" fw={600} mb={6}>{title}</Text>
      {u ? (
        <Group gap="sm" wrap="nowrap">
          <Avatar radius="xl" color="indigo">{u.email[0].toUpperCase()}</Avatar>
          <div style={{ minWidth: 0 }}>
            <Text size="sm" fw={600} truncate>{u.name || u.email}</Text>
            <Text size="xs" c="dimmed" truncate>{u.email} · {ROLE_LABEL[u.role] ?? u.role}</Text>
            {extra && <Text size="xs" c="dimmed">{extra}</Text>}
          </div>
        </Group>
      ) : <Text size="sm" c="dimmed">—</Text>}
    </Card>
  );
}

function Detail({ r, box, onDone }: { r: any; box: string; onDone: () => void }) {
  const [mode, setMode] = useState<"approve" | "reject" | null>(null);
  const [note, setNote] = useState("");
  const f = r.finding;
  async function decide() {
    try {
      await api(`/approvals/${r.id}/decide`, { body: { approve: mode === "approve", note } });
      ok(mode === "approve" ? t("Onaylandı") : t("Reddedildi"));
      setMode(null); onDone();
    } catch (e) { fail(e); }
  }
  async function cancel() {
    try { await api(`/approvals/${r.id}/cancel`, { method: "POST" }); onDone(); } catch (e) { fail(e); }
  }
  return (
    <Stack>
      <Group justify="space-between"><StateBadge state={r.state} /><Text size="xs" c="dimmed">#{r.id}</Text></Group>
      {f && (
        <Card withBorder>
          <Group gap="xs" mb={4}><SevBadge sev={f.severity} />{f.kev && <Badge color="red" variant="outline" size="sm">KEV</Badge>}
            <Anchor component={Link} to={`/findings?open=${r.finding_id}`} fw={700}>{f.cves?.[0] ?? f.vuln_id}</Anchor></Group>
          <Text size="sm">{f.component} <Text span c="dimmed">{f.version}</Text></Text>
          <Text size="xs" c="dimmed" lineClamp={2}>{f.summary}</Text>
          <Group gap="xs" mt="sm"><StatusBadge status={r.from_status} /><IconArrowRight size={14} /><StatusBadge status={r.status} /></Group>
        </Card>
      )}
      <Text fw={600} size="sm">{t("Gerekçe")}</Text>
      <Blockquote color="indigo" p="sm" icon={null}><Text size="sm" style={{ whiteSpace: "pre-wrap" }}>{r.reason || "—"}</Text></Blockquote>
      <SimpleGrid cols={2}>
        <PersonCard title={t("Talep eden")} u={r.requested_by} extra={fmtDate(r.created_at)} />
        {r.decided_by ? <PersonCard title={t("Karar veren")} u={r.decided_by} extra={fmtDate(r.decided_at)} />
          : <Card withBorder padding="sm"><Text size="xs" c="dimmed" tt="uppercase" fw={600} mb={6}>{t("Onaylayıcılar")}</Text>
            <Stack gap={4}>{r.approvers.map((a: any) => <Group key={a.id} gap={6}><Avatar size="xs" radius="xl">{a.email[0].toUpperCase()}</Avatar><Text size="xs">{a.name || a.email}</Text></Group>)}</Stack></Card>}
      </SimpleGrid>
      <Timeline active={r.state === "pending" ? 0 : 1} bulletSize={26} lineWidth={2}>
        <Timeline.Item bullet={<IconSend size={13} />} title={t("Onay istendi")}>
          <Text size="xs" c="dimmed">{r.requested_by?.email} · {fmtDate(r.created_at)}</Text>
        </Timeline.Item>
        <Timeline.Item bullet={(() => { const I = STATE[r.state].icon; return <I size={13} />; })()} color={STATE[r.state].color} title={STATE[r.state].label}>
          {r.decided_at ? <Text size="xs" c="dimmed">{r.decided_by?.email} · {fmtDate(r.decided_at)}</Text> : <Text size="xs" c="dimmed">{t("Karar bekleniyor")}</Text>}
          {r.decision_note && <Blockquote color={STATE[r.state].color} p="xs" mt={6} icon={null}><Text size="sm">{r.decision_note}</Text></Blockquote>}
        </Timeline.Item>
      </Timeline>
      {r.state === "pending" && box === "todo" && (
        <Group grow>
          <Button color="green" leftSection={<IconCheck size={16} />} onClick={() => { setNote(""); setMode("approve"); }}>{t("Onayla")}</Button>
          <Button color="red" variant="light" leftSection={<IconX size={16} />} onClick={() => { setNote(""); setMode("reject"); }}>{t("Reddet")}</Button>
        </Group>
      )}
      {r.state === "pending" && box === "mine" && <Button variant="default" onClick={cancel}>{t("Talebi geri çek")}</Button>}
      <Modal opened={mode !== null} onClose={() => setMode(null)} title={mode === "approve" ? t("Talebi onayla") : t("Talebi reddet")}>
        <Stack>
          <Textarea label={mode === "approve" ? t("Not (isteğe bağlı)") : t("Reddetme gerekçesi (zorunlu)")} value={note} onChange={(e) => setNote(e.currentTarget.value)} autosize minRows={3} />
          <Group justify="flex-end"><Button color={mode === "approve" ? "green" : "red"} onClick={decide} disabled={mode === "reject" && !note.trim()}>{mode === "approve" ? t("Onayla") : t("Reddet")}</Button></Group>
        </Stack>
      </Modal>
    </Stack>
  );
}

function List({ box }: { box: string }) {
  const qc = useQueryClient();
  const q = useQuery<any[]>({ queryKey: ["approvals", box], queryFn: () => api(`/approvals?box=${box}&state=all`) });
  const [sel, setSel] = useState<any | null>(null);
  const done = () => { qc.invalidateQueries({ queryKey: ["approvals"] }); qc.invalidateQueries({ queryKey: ["approvals-count"] }); setSel(null); };
  const empty = { todo: t("Kararınızı bekleyen talep yok"), decided: t("Henüz karar vermediniz"), mine: t("Talebiniz yok") }[box];
  return (
    <>
      {q.data?.length === 0 ? (
        <Card withBorder py={40}><Stack align="center" gap={6}>
          <ThemeIcon size={48} radius="xl" variant="light" color="green"><IconChecks size={24} /></ThemeIcon>
          <Text c="dimmed">{empty}</Text>
        </Stack></Card>
      ) : (
        <Card withBorder p={0}>
          <Table.ScrollContainer minWidth={760}>
            <Table highlightOnHover verticalSpacing="sm">
              <Table.Thead><Table.Tr><Table.Th>{t("Bulgu")}</Table.Th><Table.Th>{t("İstenen karar")}</Table.Th><Table.Th>{box === "mine" ? t("Onaylayıcılar") : t("Talep eden")}</Table.Th><Table.Th>{t("Tarih")}</Table.Th><Table.Th>{t("Durum")}</Table.Th></Table.Tr></Table.Thead>
              <Table.Tbody>
                {(q.data ?? []).map((r) => (
                  <Table.Tr key={r.id} style={{ cursor: "pointer" }} onClick={() => setSel(r)}>
                    <Table.Td><Group gap="xs" wrap="nowrap">{r.finding && <SevBadge sev={r.finding.severity} />}<div><Text size="sm" fw={600}>{r.finding?.cves?.[0] ?? r.finding?.vuln_id}</Text><Text size="xs" c="dimmed">{r.finding?.component} {r.finding?.version}</Text></div></Group></Table.Td>
                    <Table.Td><Text size="sm">{STATUS_LABEL[r.status]}</Text><Text size="xs" c="dimmed" lineClamp={1} maw={260}>{r.reason}</Text></Table.Td>
                    <Table.Td>{box === "mine"
                      ? <Avatar.Group>{r.approvers.slice(0, 4).map((a: any) => <Avatar key={a.id} size="sm" radius="xl">{a.email[0].toUpperCase()}</Avatar>)}</Avatar.Group>
                      : <Group gap={6} wrap="nowrap"><Avatar size="sm" radius="xl" color="indigo">{r.requested_by?.email?.[0]?.toUpperCase()}</Avatar><Text size="sm">{r.requested_by?.name || r.requested_by?.email}</Text></Group>}</Table.Td>
                    <Table.Td><Text size="sm">{fmtDate(r.decided_at || r.created_at)}</Text></Table.Td>
                    <Table.Td><StateBadge state={r.state} /></Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        </Card>
      )}
      <Drawer opened={!!sel} onClose={() => setSel(null)} position="right" size="lg" title={<Group gap="xs"><IconGavel size={18} /><Text fw={600}>{t("Onay talebi")}</Text></Group>}>
        {sel && <Detail r={sel} box={box} onDone={done} />}
      </Drawer>
    </>
  );
}

export default function Approvals() {
  const count = useQuery<{ pending: number }>({ queryKey: ["approvals-count"], queryFn: () => api("/approvals/count") });
  return (
    <>
      <PageHeader title={t("Onaylar")} sub={t("Risk kabulü, yanlış pozitif ve \"etkilenmiyor\" kararlarının onay süreci")} />
      <PageIntro id="approvals" guide="collaboration"
        text={t("Bir kullanıcı bulguyu risk kabulü, yanlış pozitif veya \"etkilenmiyor\" olarak işaretlemek istediğinde karar, bağlı olduğu sorumluya ve takım yöneticisine onaya gider. Onaylanana kadar bulgunun durumu değişmez.")}
        points={[t("Yönetici, analist ve takım yöneticileri kararı doğrudan uygulayabilir."), t("Takımlar ve kimin kime bağlı olduğu Takımlar sayfasında tanımlanır."), t("Onay süreci Ayarlar → Genel bölümünden kapatılabilir.")]} />
      <Tabs defaultValue="todo">
        <Tabs.List mb="md">
          <Tabs.Tab value="todo" rightSection={count.data?.pending ? <Badge size="xs" color="orange" circle>{count.data.pending}</Badge> : null}>{t("Kararımı bekleyenler")}</Tabs.Tab>
          <Tabs.Tab value="decided">{t("Karar verdiklerim")}</Tabs.Tab>
          <Tabs.Tab value="mine">{t("Taleplerim")}</Tabs.Tab>
        </Tabs.List>
        {["todo", "decided", "mine"].map((b) => <Tabs.Panel key={b} value={b}><List box={b} /></Tabs.Panel>)}
      </Tabs>
    </>
  );
}
