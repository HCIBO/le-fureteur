import { Alert, Anchor, Badge, Button, Card, Group, Progress, ScrollArea, SimpleGrid, Stack, Table, Tabs, Text, TextInput } from "@mantine/core";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { IconCopy, IconDownload, IconShieldLock } from "@tabler/icons-react";
import { ScanFindings } from "../components/ScanFindings";
import { api, fmtDate, fmtSize, SEV_LABEL } from "../api";
import { fail, JobBadge, ok, PageHeader, SevBadge } from "../components/ui";
import { JobTimeline } from "../components/JobTimeline";
import { WAF_NAME, WafCard } from "../components/WafCard";
import { AccessIssueCard, InputNotesCard } from "../components/AccessIssue";
import { t } from "../i18n";

export default function ScanDetail() {
  const { id } = useParams();
  const qc = useQueryClient();
  const nav = useNavigate();
  const scan = useQuery<any>({
    queryKey: ["scan", id], queryFn: () => api(`/scans/${id}`),
    refetchInterval: (q) => (q.state.data && ["queued", "running"].includes(q.state.data.job.status) ? 2000 : false),
  });
  const done = scan.data?.job.status === "done";
  const reports = useQuery<any[]>({ queryKey: ["reports", id], queryFn: () => api(`/scans/${id}/reports`), enabled: done });
  const comps = useQuery<any[]>({ queryKey: ["components", id], queryFn: () => api(`/scans/${id}/components`), enabled: done });
  const [filter, setFilter] = useState("");
  const changes = useQuery<any>({ queryKey: ["changes", id], queryFn: () => api(`/scans/${id}/changes`), enabled: done });
  const tid = scan.data?.target_id;
  const tgt = useQuery<any>({ queryKey: ["target", tid], queryFn: () => api(`/targets/${tid}`), enabled: !!scan.data?.summary?.access });
  if (!scan.data) return null;
  const s = scan.data;
  const sum = s.summary;
  async function cancel() {
    try { await api(`/scans/${id}/cancel`, { method: "POST" }); qc.invalidateQueries({ queryKey: ["scan", id] }); } catch (e) { fail(e); }
  }
  async function regen() {
    try { await api(`/scans/${id}/reports/regenerate`, { method: "POST" }); ok(t("Rapor yeniden üretiliyor (güncel bulgu durumlarıyla)")); setTimeout(() => qc.invalidateQueries({ queryKey: ["reports", id] }), 4000); } catch (e) { fail(e); }
  }
  const list = (comps.data ?? []).filter((c) => !filter || `${c.ecosystem} ${c.name} ${c.version}`.toLowerCase().includes(filter.toLowerCase()));
  return (
    <>
      <PageHeader title={t("Tarama #{n} — {target}", { n: s.id, target: s.target })}
        sub={<><Anchor component={Link} to={`/targets/${s.target_id}`} size="sm">{t("← hedef")}</Anchor> · {s.project} · {fmtDate(s.created_at)}</>}
        right={<Group><JobBadge status={s.job.status} />{["queued", "running"].includes(s.job.status) ? <Button variant="default" color="red" onClick={cancel}>{t("İptal et")}</Button>
          : <Button variant="subtle" color="red" onClick={async () => {
              if (!confirm(t("Tarama #{n} ve raporları silinsin mi? Bulgular hedefte kalır.", { n: s.id }))) return;
              try { await api(`/scans/${s.id}`, { method: "DELETE" }); ok(t("Tarama silindi")); qc.invalidateQueries({ queryKey: ["scans"] }); nav(`/targets/${s.target_id}`); } catch (e) { fail(e); }
            }}>{t("Taramayı sil")}</Button>}</Group>} />
      {["queued", "running"].includes(s.job.status) && <Progress value={s.job.progress} mb="lg" animated />}
      {s.job.error && <Card withBorder mb="lg" bg="var(--mantine-color-red-light)"><Text c="red" fw={600}>{s.job.error}</Text></Card>}
      {sum?.access?.severe && !sum?.waf?.severe && <AccessIssueCard access={sum.access} targetId={s.target_id} projectId={s.project_id} targetOptions={tgt.data?.options} />}
      {sum?.input_notes?.length > 0 && <InputNotesCard notes={sum.input_notes} />}
      {sum?.waf?.severe && <WafCard waf={sum.waf} targetId={s.target_id} projectId={s.project_id} />}
      {sum?.waf && !sum.waf.severe && (
        <Alert color="gray" variant="light" mb="lg" icon={<IconShieldLock size={18} />}>
          {t("{b} / {r} istek {name} nedeniyle yanıt alamadı; tarama büyük ölçüde tamamlandı.", { b: sum.waf.blocked, r: sum.waf.requests, name: WAF_NAME[sum.waf.vendor] ?? sum.waf.vendor })}
        </Alert>
      )}
      {sum && (
        <SimpleGrid cols={{ base: 2, md: 5 }} mb="lg">
          {[[t("Bileşen"), sum.components], [t("Bulgu"), sum.findings], [t("Yeni"), sum.new], [t("Kapanan"), sum.fixed], ["KEV", sum.kev]].map(([l, v]) => (
            <Card withBorder key={l as string} padding="sm"><Text size="xs" c="dimmed">{l}</Text><Text fz={24} fw={700}>{v as number}</Text></Card>
          ))}
        </SimpleGrid>
      )}
      {s.duplicate_of && (
        <Alert mb="lg" color="blue" variant="light" icon={<IconCopy size={18} />} title={t("Önceki taramayla aynı sonuç")}>
          {s.same_input ? t("Bu tarama, #{n} numaralı taramayla aynı girdiyle yapıldı ve aynı bileşen / bulgu kümesini üretti.", { n: s.duplicate_of }) : t("Girdi değişti ama sonuç #{n} numaralı taramayla aynı: yeni bileşen veya bulgu yok.", { n: s.duplicate_of })}{" "}
          <Anchor component={Link} to={`/scans/${s.duplicate_of}`} size="sm">{t("Tarama #{n}", { n: s.duplicate_of })} →</Anchor>
        </Alert>
      )}
      <Tabs defaultValue={done ? "findings" : "log"}>
        <Tabs.List mb="md">
          <Tabs.Tab value="findings" disabled={!done}>{t("Bulgular")}</Tabs.Tab>
          <Tabs.Tab value="reports" disabled={!done}>{t("Raporlar")}</Tabs.Tab>
          <Tabs.Tab value="changes" disabled={!done}>{t("Değişiklikler")}</Tabs.Tab>
          <Tabs.Tab value="components" disabled={!done}>{t("Bileşenler (SBOM)")}</Tabs.Tab>
          <Tabs.Tab value="log">{t("Günlük")}</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="findings">{done && <ScanFindings targetId={s.target_id} />}</Tabs.Panel>
        <Tabs.Panel value="reports">
          <Card withBorder>
            <Group justify="space-between" mb="sm">
              <Text size="sm" c="dimmed">{t("Bulgu durumunu değiştirdiyseniz (risk kabulü vb.) raporu yeniden üretin.")}</Text>
              <Button variant="light" size="xs" onClick={regen}>{t("Raporu yeniden üret")}</Button>
            </Group>
            <Table>
              <Table.Tbody>
                {(reports.data ?? []).map((r) => (
                  <Table.Tr key={r.name}>
                    <Table.Td>{r.name}</Table.Td><Table.Td>{fmtSize(r.size)}</Table.Td>
                    <Table.Td ta="right"><Button component="a" href={`/api/scans/${id}/reports/${encodeURIComponent(r.name)}`} size="xs" variant="subtle" leftSection={<IconDownload size={14} />}>{t("İndir")}</Button></Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
            {sum?.severity && <Group mt="md" gap="xs">{Object.entries(sum.severity).map(([k, v]) => <Badge key={k} variant="outline">{SEV_LABEL[k] ?? k}: {v as number}</Badge>)}</Group>}
          </Card>
        </Tabs.Panel>
        <Tabs.Panel value="changes">
          {changes.data && (
            <Stack>
              <Text size="sm" c="dimmed">{changes.data.previous_scan ? t("Önceki tarama #{n} ile karşılaştırma", { n: changes.data.previous_scan }) : t("Bu hedefin ilk taraması — tüm bulgular yeni.")}</Text>
              {([["new", t("Yeni bulgular")], ["reopened", t("Yeniden açılanlar")], ["fixed", t("Kapananlar (artık görülmüyor)")]] as const).map(([k, label]) => (
                <Card withBorder key={k} p={0}>
                  <Group p="sm" gap="xs"><Text fw={600}>{label}</Text><Badge variant="light">{changes.data[k].length}</Badge></Group>
                  {changes.data[k].length > 0 && (
                    <Table.ScrollContainer minWidth={640}>
                      <Table verticalSpacing={6}>
                        <Table.Tbody>
                          {changes.data[k].slice(0, 200).map((f: any) => (
                            <Table.Tr key={f.id}>
                              <Table.Td w={100}><SevBadge sev={f.severity} /></Table.Td>
                              <Table.Td><Anchor component={Link} to={`/findings?target_id=${s.target_id}&q=${encodeURIComponent(f.vuln_id)}&status=`} size="sm">{f.cves[0] ?? f.vuln_id}</Anchor></Table.Td>
                              <Table.Td><Text size="sm">{f.component} <Text span c="dimmed">{f.version}</Text></Text></Table.Td>
                              <Table.Td><Text size="sm">{f.upgrade_to ? `→ ${f.upgrade_to}` : ""}</Text></Table.Td>
                            </Table.Tr>
                          ))}
                        </Table.Tbody>
                      </Table>
                    </Table.ScrollContainer>
                  )}
                </Card>
              ))}
            </Stack>
          )}
        </Tabs.Panel>
        <Tabs.Panel value="components">
          <Card withBorder p={0}>
            <TextInput m="md" placeholder={t("Ara (ad, ekosistem, sürüm)")} value={filter} onChange={(e) => setFilter(e.currentTarget.value)} />
            <ScrollArea h={560}>
              <Table striped stickyHeader>
                <Table.Thead><Table.Tr><Table.Th>{t("Ekosistem")}</Table.Th><Table.Th>{t("Bileşen")}</Table.Th><Table.Th>{t("Sürüm")}</Table.Th><Table.Th>{t("Lisans")}</Table.Th><Table.Th>{t("Güven")}</Table.Th><Table.Th>{t("Konum")}</Table.Th></Table.Tr></Table.Thead>
                <Table.Tbody>
                  {list.map((c, i) => (
                    <Table.Tr key={i}>
                      <Table.Td>{c.ecosystem}</Table.Td><Table.Td fw={500}>{c.name}</Table.Td><Table.Td>{c.version || "-"}</Table.Td>
                      <Table.Td><Text size="xs">{(c.licenses ?? []).join(", ") || "-"}</Text></Table.Td><Table.Td>{c.confidence}</Table.Td>
                      <Table.Td><Text size="xs" c="dimmed" lineClamp={1} maw={320} ff="monospace">{c.evidence?.[0]?.location}{c.evidence?.[0]?.line ? `:${c.evidence[0].line}` : ""}</Text></Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </ScrollArea>
          </Card>
        </Tabs.Panel>
        <Tabs.Panel value="log">
          <Card withBorder><JobTimeline events={s.job.events ?? []} log={s.job.log} /></Card>
        </Tabs.Panel>
      </Tabs>
    </>
  );
}
