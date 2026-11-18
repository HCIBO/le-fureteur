import { Badge, Card, Drawer, Group, Stack, Table, Tabs, Text, ThemeIcon } from "@mantine/core";
import { useQuery } from "@tanstack/react-query";
import { useNavigate, useParams } from "react-router-dom";
import { IconGavel, IconMessages } from "@tabler/icons-react";
import { api, fmtDate } from "../api";
import { t } from "../i18n";
import { PageHeader, SevBadge } from "../components/ui";
import { PageIntro } from "../components/PageIntro";
import { DisputeRoom, DisputeState } from "../components/Dispute";

function List({ box, onOpen }: { box: string; onOpen: (id: number) => void }) {
  const q = useQuery<any[]>({ queryKey: ["disputes", box], queryFn: () => api(`/disputes?box=${box}`) });
  if (q.data?.length === 0) {
    return <Card withBorder py={40}><Stack align="center" gap={6}><ThemeIcon size={48} radius="xl" variant="light" color="grape"><IconGavel size={24} /></ThemeIcon>
      <Text c="dimmed">{box === "judge" ? t("Kararınızı bekleyen tartışma yok") : t("Henüz tartışma yok — bulgu ayrıntısındaki Tartışma sekmesinden açabilirsiniz")}</Text></Stack></Card>;
  }
  return (
    <Card withBorder p={0}>
      <Table.ScrollContainer minWidth={720}>
        <Table highlightOnHover verticalSpacing="sm">
          <Table.Thead><Table.Tr><Table.Th>{t("Konu")}</Table.Th><Table.Th>{t("Bulgu")}</Table.Th><Table.Th>{t("Açan")}</Table.Th><Table.Th>{t("Tarih")}</Table.Th><Table.Th>{t("Durum")}</Table.Th></Table.Tr></Table.Thead>
          <Table.Tbody>
            {(q.data ?? []).map((d) => (
              <Table.Tr key={d.id} style={{ cursor: "pointer" }} onClick={() => onOpen(d.id)}>
                <Table.Td><Text size="sm" fw={600}>{d.title}</Text><Group gap={4}><IconMessages size={12} /><Text size="xs" c="dimmed">{d.messages_count}</Text></Group></Table.Td>
                <Table.Td><Group gap="xs" wrap="nowrap">{d.finding && <SevBadge sev={d.finding.severity} />}<Text size="sm">{d.finding?.cves?.[0] ?? d.finding?.vuln_id}</Text></Group></Table.Td>
                <Table.Td><Text size="sm">{d.opened_by?.name || d.opened_by?.email}</Text></Table.Td>
                <Table.Td><Text size="sm">{fmtDate(d.created_at)}</Text></Table.Td>
                <Table.Td><DisputeState s={d.status} /></Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>
    </Card>
  );
}

export default function Disputes() {
  const { id } = useParams();
  const nav = useNavigate();
  const me = useQuery<any>({ queryKey: ["me"], queryFn: () => api("/auth/me") });
  const judge = useQuery<any[]>({ queryKey: ["disputes", "judge"], queryFn: () => api("/disputes?box=judge") });
  return (
    <>
      <PageHeader title={t("Tartışmalar")} sub={t("Bulgular üzerindeki görüş ayrılıkları ve yönetici kararları")} />
      <PageIntro id="disputes" guide="collaboration"
        text={t("Bir bulgunun önemi, etkisi veya durumu konusunda ekip içinde fikir ayrılığı olduğunda tartışma açılır. Taraflar görüşlerini yazar; uzlaşılamazsa tartışma yöneticiye taşınır ve yönetici kararı verir ya da yetkili birine vekâlet verir.")}
        points={[t("Karar, bulgunun durumunu değiştirebilir ve bulgu geçmişine işlenir."), t("Karar vericiler, tartışmayı açan kişinin takım yöneticisi ve sorumlusudur."), t("Tüm adımlar denetim kaydına yazılır.")]} />
      <Tabs defaultValue="all">
        <Tabs.List mb="md">
          <Tabs.Tab value="all">{t("Dahil olduklarım")}</Tabs.Tab>
          <Tabs.Tab value="judge" rightSection={judge.data?.length ? <Badge size="xs" color="orange" circle>{judge.data.length}</Badge> : null}>{t("Kararımı bekleyenler")}</Tabs.Tab>
          <Tabs.Tab value="open">{t("Açık olanlar")}</Tabs.Tab>
        </Tabs.List>
        {["all", "judge", "open"].map((b) => <Tabs.Panel key={b} value={b}><List box={b} onOpen={(i) => nav(`/disputes/${i}`)} /></Tabs.Panel>)}
      </Tabs>
      <Drawer opened={!!id} onClose={() => nav("/disputes")} position="right" size="xl" title={<Group gap="xs"><IconGavel size={18} /><Text fw={600}>{t("Tartışma odası")}</Text></Group>}>
        {id && <DisputeRoom id={Number(id)} me={me.data} />}
      </Drawer>
    </>
  );
}
