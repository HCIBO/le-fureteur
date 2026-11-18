import { Anchor, Box, Card, Group, SimpleGrid, Table, Text, Tooltip, Loader } from "@mantine/core";
import { TrendCard } from "../components/TrendCard";
import { useQuery } from "@tanstack/react-query";
import { IconAlertTriangle } from "@tabler/icons-react";
import { Link } from "react-router-dom";
import { api, fmtDate, SEV_COLOR, SEV_LABEL, SEVERITIES, STATUS_LABEL } from "../api";
import { JobBadge, PageHeader } from "../components/ui";
import { t } from "../i18n";

type Dash = {
  open_by_severity: Record<string, number>; open_kev: number; status: Record<string, number>;
  projects: number; targets: number;
  top_components: { component: string; version: string; findings: number; max_cvss: number | null }[];
  recent_scans: any[];
};

function Stat({ label, value, hint }: { label: string; value: number | string; hint?: string }) {
  return (
    <Card withBorder padding="md">
      <Text size="sm" c="dimmed">{label}</Text>
      <Text fz={32} fw={700} lh={1.2}>{value}</Text>
      {hint && <Text size="xs" c="dimmed">{hint}</Text>}
    </Card>
  );
}

function SeverityBars({ data }: { data: Record<string, number> }) {
  const max = Math.max(1, ...SEVERITIES.map((s) => data[s] ?? 0));
  return (
    <Box>
      {SEVERITIES.map((s) => {
        const n = data[s] ?? 0;
        return (
          <Tooltip key={s} label={t("{sev}: {n} açık bulgu", { sev: SEV_LABEL[s], n })} position="top-start" withArrow>
            <Group gap="sm" wrap="nowrap" py={6} style={{ cursor: "default" }}>
              <Text size="sm" w={80}>{SEV_LABEL[s]}</Text>
              <Box style={{ flex: 1, height: 14, display: "flex", alignItems: "center" }}>
                <Box style={{ width: `${(n / max) * 100}%`, minWidth: n ? 4 : 0, height: 14, background: SEV_COLOR[s], borderRadius: "0 4px 4px 0" }} />
              </Box>
              <Text size="sm" fw={600} w={44} ta="right" style={{ fontVariantNumeric: "tabular-nums" }}>{n}</Text>
            </Group>
          </Tooltip>
        );
      })}
    </Box>
  );
}

export default function Dashboard() {
  const { data, isLoading } = useQuery<Dash>({ queryKey: ["dashboard"], queryFn: () => api("/dashboard"), refetchInterval: 15000 });
  if (isLoading || !data) return <Loader />;
  const openTotal = SEVERITIES.reduce((a, s) => a + (data.open_by_severity[s] ?? 0), 0);
  return (
    <>
      <PageHeader title={t("Pano")} sub={t("Açık ve üzerinde çalışılan bulgular")} />
      <SimpleGrid cols={{ base: 2, md: 4 }} mb="lg">
        <Stat label={t("Açık bulgu")} value={openTotal} />
        <Card withBorder padding="md">
          <Group gap={6}><IconAlertTriangle size={16} color="#d03b3b" /><Text size="sm" c="dimmed">{t("Aktif sömürülen (KEV)")}</Text></Group>
          <Text fz={32} fw={700} lh={1.2}>{data.open_kev}</Text>
          <Text size="xs" c="dimmed">{t("CISA KEV listesinde, öncelikli")}</Text>
        </Card>
        <Stat label={t("Projeler")} value={data.projects} />
        <Stat label={t("Hedefler")} value={data.targets} />
      </SimpleGrid>
      <div style={{ marginBottom: "var(--mantine-spacing-lg)" }}><TrendCard /></div>
      <SimpleGrid cols={{ base: 1, md: 2 }} mb="lg">
        <Card withBorder>
          <Text fw={600} mb="sm">{t("Açık bulgular — şiddete göre")}</Text>
          <SeverityBars data={data.open_by_severity} />
        </Card>
        <Card withBorder>
          <Text fw={600} mb="sm">{t("Bulgu durumları (tümü)")}</Text>
          <Table>
            <Table.Tbody>
              {Object.keys(STATUS_LABEL).map((k) => (
                <Table.Tr key={k}><Table.Td>{STATUS_LABEL[k]}</Table.Td><Table.Td ta="right" fw={600}>{data.status[k] ?? 0}</Table.Td></Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Card>
      </SimpleGrid>
      <SimpleGrid cols={{ base: 1, md: 2 }}>
        <Card withBorder>
          <Text fw={600} mb="sm">{t("En çok bulgu üreten bileşenler")}</Text>
          {data.top_components.length === 0 ? <Text c="dimmed" size="sm">{t("Açık bulgu yok")}</Text> : (
            <Table.ScrollContainer minWidth={420}><Table striped>
              <Table.Thead><Table.Tr><Table.Th>{t("Bileşen")}</Table.Th><Table.Th>{t("Sürüm")}</Table.Th><Table.Th ta="right">{t("Bulgu")}</Table.Th><Table.Th ta="right">{t("Maks. CVSS")}</Table.Th></Table.Tr></Table.Thead>
              <Table.Tbody>
                {data.top_components.map((c) => (
                  <Table.Tr key={c.component + c.version}>
                    <Table.Td style={{ wordBreak: "break-word" }}><Anchor component={Link} to={`/findings?q=${encodeURIComponent(c.component)}`}>{c.component}</Anchor></Table.Td>
                    <Table.Td>{c.version}</Table.Td><Table.Td ta="right">{c.findings}</Table.Td><Table.Td ta="right">{c.max_cvss ?? "-"}</Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table></Table.ScrollContainer>
          )}
        </Card>
        <Card withBorder>
          <Text fw={600} mb="sm">{t("Son taramalar")}</Text>
          {data.recent_scans.length === 0 ? <Text c="dimmed" size="sm">{t("Henüz tarama yok")}</Text> : (
            <Table>
              <Table.Tbody>
                {data.recent_scans.map((s) => (
                  <Table.Tr key={s.id}>
                    <Table.Td><Anchor component={Link} to={`/scans/${s.id}`}>#{s.id} {s.target}</Anchor><Text size="xs" c="dimmed">{s.project}</Text></Table.Td>
                    <Table.Td style={{ whiteSpace: "nowrap" }}><JobBadge status={s.job.status} /></Table.Td>
                    <Table.Td><Text size="sm">{fmtDate(s.created_at)}</Text></Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          )}
        </Card>
      </SimpleGrid>
    </>
  );
}
