import { Badge, Card, Group, Pagination, Paper, SegmentedControl, Table, Text, TextInput, Tooltip } from "@mantine/core";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { IconBolt, IconSearch } from "@tabler/icons-react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";
import { t } from "../i18n";
import { SevBadge } from "./ui";

const SIZE = 25;

export function ScanFindings({ targetId }: { targetId: number }) {
  const nav = useNavigate();
  const [q, setQ] = useState("");
  const [sev, setSev] = useState("all");
  const [page, setPage] = useState(1);
  const params = new URLSearchParams({ target_id: String(targetId), evidence: "true", status: "open,in_progress", page: String(page), size: String(SIZE) });
  if (q) params.set("q", q);
  if (sev !== "all") params.set("severity", sev);
  const data = useQuery<any>({ queryKey: ["scan-findings", params.toString()], queryFn: () => api(`/findings?${params}`) });
  return (
    <Card withBorder p={0}>
      <Group p="md" gap="sm">
        <TextInput leftSection={<IconSearch size={14} />} placeholder={t("bileşen, CVE, açıklama")} value={q} onChange={(e) => { setQ(e.currentTarget.value); setPage(1); }} w={260} />
        <SegmentedControl size="xs" value={sev} onChange={(v) => { setSev(v); setPage(1); }} data={[{ value: "all", label: t("Tümü") }, { value: "CRITICAL", label: t("Kritik") }, { value: "CRITICAL,HIGH", label: t("Kritik + Yüksek") }]} />
        <Text size="xs" c="dimmed" ml="auto">{t("Açık bulgular — satıra tıklayınca ayrıntı açılır")}</Text>
      </Group>
      <Table.ScrollContainer minWidth={860}>
        <Table highlightOnHover verticalSpacing="sm">
          <Table.Thead><Table.Tr><Table.Th>{t("Şiddet")}</Table.Th><Table.Th>{t("Zafiyet")}</Table.Th><Table.Th>{t("Bileşen")}</Table.Th><Table.Th>{t("Nerede")}</Table.Th><Table.Th>{t("Çözüm")}</Table.Th></Table.Tr></Table.Thead>
          <Table.Tbody>
            {(data.data?.items ?? []).map((f: any) => (
              <Table.Tr key={f.id} style={{ cursor: "pointer", verticalAlign: "top" }} onClick={() => nav(`/findings?open=${f.id}`)}>
                <Table.Td><SevBadge sev={f.severity} />{f.kev && <Badge mt={4} size="xs" color="red" variant="filled" leftSection={<IconBolt size={10} />}>KEV</Badge>}</Table.Td>
                <Table.Td><Text size="sm" fw={600}>{f.cves?.[0] ?? f.vuln_id}</Text><Text size="xs" c="dimmed" lineClamp={2} maw={280}>{f.summary}</Text></Table.Td>
                <Table.Td><Text size="sm">{f.component}</Text><Text size="xs" c="dimmed">{f.version} · {f.ecosystem}</Text></Table.Td>
                <Table.Td>
                  {(f.locations ?? []).slice(0, 2).map((l: any, i: number) => (
                    <div key={i} style={{ marginBottom: 4 }}>
                      <Text size="xs" ff="monospace" style={{ wordBreak: "break-all" }}>{l.location}{l.line ? <b>:{l.line}</b> : ""}</Text>
                      {l.snippet && <Tooltip label={l.snippet} multiline w={420}><Paper bg="#0d1117" px={6} py={2} radius="sm" mt={2} maw={340}><Text size="xs" ff="monospace" c="#e6edf3" truncate>{l.snippet}</Text></Paper></Tooltip>}
                    </div>
                  ))}
                  {(f.locations ?? []).length > 2 && <Text size="xs" c="dimmed">+{f.locations.length - 2}</Text>}
                </Table.Td>
                <Table.Td>{f.upgrade_to ? <Badge variant="light" color="green" tt="none">→ {f.upgrade_to}</Badge> : <Text size="xs" c="dimmed">{t("düzeltme yok")}</Text>}</Table.Td>
              </Table.Tr>
            ))}
            {data.data?.items?.length === 0 && <Table.Tr><Table.Td colSpan={5}><Text c="dimmed" ta="center" py="lg">{t("Açık bulgu yok")}</Text></Table.Td></Table.Tr>}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>
      {data.data && data.data.total > SIZE && <Group justify="center" p="md"><Pagination total={Math.ceil(data.data.total / SIZE)} value={page} onChange={setPage} /></Group>}
    </Card>
  );
}
