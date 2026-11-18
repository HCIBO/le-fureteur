import { Anchor, Badge, Button, Card, Checkbox, Drawer, Group, MultiSelect, Pagination, Select, Stack, Switch, Table, Text, TextInput, Loader, Avatar, SegmentedControl, Tooltip } from "@mantine/core";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { IconAlertTriangle, IconDownload, IconFilterOff, IconSearch, IconSkull, IconUserCheck, IconWorld, IconFile } from "@tabler/icons-react";
import { api, SEV_LABEL, SEVERITIES, STATUS_LABEL, fmtDay } from "../api";
import { fail, ok, PageHeader, SevBadge, StatusBadge } from "../components/ui";
import { AssignModal } from "../components/Assign";
import { t } from "../i18n";
import { FindingDetail } from "../components/FindingDetail";
import { useJiraPicker } from "../components/JiraInstances";

const SIZE = 50;

export default function Findings() {
  const [sp, setSp] = useSearchParams();
  const [page, setPage] = useState(1);
  const [sel, setSel] = useState<number | null>(null);
  const [picked, setPicked] = useState<Set<number>>(new Set());
  const [pushing, setPushing] = useState(false);
  const qc = useQueryClient();
  const jira = useQuery<any>({ queryKey: ["jira-status"], queryFn: () => api("/jira/status") });
  const picker = useJiraPicker();
  const projects = useQuery<any[]>({ queryKey: ["projects"], queryFn: () => api("/projects") });
  const f = {
    q: sp.get("q") ?? "", project_id: sp.get("project_id") ?? "", target_id: sp.get("target_id") ?? "",
    severity: sp.get("severity") ?? "", status: sp.get("status") ?? "open,in_progress", kev: sp.get("kev") === "1",
    assignee: sp.get("assignee") ?? "", ecosystem: sp.get("ecosystem") ?? "", has_fix: sp.get("has_fix") ?? "",
    since_days: sp.get("since_days") ?? "", target_kind: sp.get("target_kind") ?? "",
  };
  const facets = useQuery<any>({ queryKey: ["findings-facets"], queryFn: () => api("/findings/facets") });
  const [text, setText] = useState(f.q);
  useEffect(() => { const id = window.setTimeout(() => { if (text !== f.q) set("q", text.trim() ? text : ""); }, 350); return () => window.clearTimeout(id); }, [text]);
  useEffect(() => { setText(f.q); }, [f.q]);
  const [assignOpen, setAssignOpen] = useState(false);
  useEffect(() => { const o = sp.get("open"); if (o && /^\d+$/.test(o)) setSel(Number(o)); }, [sp]);
  const set = (k: string, v: string) => { const n = new URLSearchParams(sp); if (v) n.set(k, v); else n.delete(k); setSp(n); setPage(1); };
  const params = new URLSearchParams({ page: String(page), size: String(SIZE) });
  for (const k of ["q", "project_id", "target_id", "severity", "status", "assignee", "ecosystem", "has_fix", "since_days", "target_kind"] as const) if (f[k]) params.set(k, f[k]);
  if (f.kev) params.set("kev", "true");
  const exportParams = new URLSearchParams(params); exportParams.delete("page"); exportParams.delete("size");
  const extraActive = ["q", "project_id", "target_id", "severity", "assignee", "ecosystem", "has_fix", "since_days", "target_kind", "kev"].some((k) => sp.get(k)) || sp.get("status") !== null;
  const data = useQuery<any>({ queryKey: ["findings", params.toString()], queryFn: () => api(`/findings?${params}`) });
  const items: any[] = data.data?.items ?? [];
  const allPicked = items.length > 0 && items.every((x) => picked.has(x.id));
  function togglePick(id: number) {
    const n = new Set(picked);
    if (n.has(id)) n.delete(id); else n.add(id);
    setPicked(n);
  }
  async function pushJira() {
    setPushing(true);
    try {
      let r = await api("/findings/jira", { body: { ids: [...picked] } });
      if (r.errors.length && String(r.errors[0].error).includes("seçin")) {
        const inst = await picker.choose();
        if (inst === undefined) return;
        r = await api("/findings/jira", { body: { ids: [...picked], instance_id: inst } });
      }
      if (r.errors.length) fail(new Error(r.errors[0].error));
      if (r.created.length || r.existing.length) ok(t("Jira: {n} yeni kayıt", { n: r.created.length }) + (r.existing.length ? t(", {n} zaten vardı", { n: r.existing.length }) : ""));
      setPicked(new Set());
      qc.invalidateQueries({ queryKey: ["findings"] });
    } catch (e) { fail(e); } finally { setPushing(false); }
  }
  return (
    <>
      <PageHeader title={t("Bulgular")} sub={t("Öncelik sırası: kötü amaçlı paket → KEV → şiddet → EPSS")}
        right={<Button variant="default" leftSection={<IconDownload size={16} />} component="a" href={`/api/findings.csv?${exportParams}`}>{t("CSV indir")}</Button>} />
      <Card withBorder mb="md">
        <TextInput size="md" mb="sm" leftSection={<IconSearch size={18} />} value={text} onChange={(e) => setText(e.currentTarget.value)}
          placeholder={t("Alan adı, hedef, proje, müşteri, bileşen, sürüm, CVE / GHSA veya açıklamada ara — ör. acme, lodash 4.17, CVE-2021-23337")}
          description={t("Birden fazla kelime yazarsanız hepsini içeren bulgular gösterilir.")} />
        <Group align="flex-end" wrap="wrap">
          <Select label={t("Proje")} clearable w={200} data={(projects.data ?? []).map((p) => ({ value: String(p.id), label: p.name }))} value={f.project_id || null} onChange={(v) => { set("project_id", v ?? ""); }} />
          <MultiSelect label={t("Şiddet")} w={240} data={SEVERITIES.map((s) => ({ value: s, label: SEV_LABEL[s] }))} value={f.severity ? f.severity.split(",") : []} onChange={(v) => set("severity", v.join(","))} />
          <MultiSelect label={t("Durum")} w={300} data={Object.entries(STATUS_LABEL).map(([value, label]) => ({ value, label }))} value={f.status ? f.status.split(",") : []} onChange={(v) => set("status", v.join(","))} />
          <SegmentedControl size="xs" mb={6} value={f.assignee || "all"} onChange={(v) => set("assignee", v === "all" ? "" : v)}
            data={[{ value: "all", label: t("Herkes") }, { value: "me", label: t("Bana atananlar") }, { value: "none", label: t("Atanmamış") }]} />
          <MultiSelect label={t("Ekosistem")} w={180} clearable data={facets.data?.ecosystems ?? []} value={f.ecosystem ? f.ecosystem.split(",") : []} onChange={(v) => set("ecosystem", v.join(","))} />
          <Select label={t("Düzeltme")} w={170} clearable data={[{ value: "true", label: t("Düzeltilmiş sürüm var") }, { value: "false", label: t("Düzeltme yok") }]} value={f.has_fix || null} onChange={(v) => set("has_fix", v ?? "")} />
          <Select label={t("İlk görülme")} w={150} clearable data={[{ value: "1", label: t("Son 24 saat") }, { value: "7", label: t("Son 7 gün") }, { value: "30", label: t("Son 30 gün") }, { value: "90", label: t("Son 90 gün") }]} value={f.since_days || null} onChange={(v) => set("since_days", v ?? "")} />
          <SegmentedControl size="xs" mb={6} value={f.target_kind || "all"} onChange={(v) => set("target_kind", v === "all" ? "" : v)}
            data={[{ value: "all", label: t("Tüm hedefler") }, { value: "web", label: t("Web") }, { value: "upload", label: t("Dosya / kaynak") }]} />
          <Switch label={t("Yalnızca KEV")} checked={f.kev} onChange={(e) => set("kev", e.currentTarget.checked ? "1" : "")} mb={8} />
          {extraActive && <Button size="xs" variant="subtle" mb={6} leftSection={<IconFilterOff size={14} />} onClick={() => { setText(""); setSp(new URLSearchParams()); setPage(1); }}>{t("Filtreleri temizle")}</Button>}
          {f.target_id && <Badge variant="light" rightSection={<Anchor size="xs" onClick={() => set("target_id", "")}>×</Anchor>}>{t("hedef #")}{f.target_id}</Badge>}
        </Group>
      </Card>
      {picked.size > 0 && (
        <Card withBorder mb="sm" p="xs" bg="var(--mantine-color-indigo-light)">
          <Group justify="space-between">
            <Text size="sm">{picked.size} {t("bulgu seçildi")}</Text>
            <Group gap="xs">
              <Button size="xs" variant="default" onClick={() => setPicked(new Set())}>{t("Seçimi temizle")}</Button>
              <Button size="xs" variant="light" leftSection={<IconUserCheck size={14} />} onClick={() => setAssignOpen(true)}>{t("Ata")}</Button>
              <Button size="xs" onClick={pushJira} loading={pushing} disabled={!jira.data?.configured} title={jira.data?.configured ? "" : t("Jira ayarlı değil (Ayarlar → Jira)")}>{t("Jira'ya ekle")}</Button>
            </Group>
          </Group>
        </Card>
      )}
      <Card withBorder p={0}>
        {data.isLoading ? <Loader m="lg" /> : (
          <Table.ScrollContainer minWidth={1080}>
          <Table highlightOnHover verticalSpacing="xs">
            <Table.Thead><Table.Tr><Table.Th w={36}><Checkbox size="xs" checked={allPicked} indeterminate={!allPicked && items.some((x) => picked.has(x.id))} onChange={() => { const n = new Set(picked); items.forEach((x) => (allPicked ? n.delete(x.id) : n.add(x.id))); setPicked(n); }} aria-label={t("Sayfadakilerin hepsini seç")} /></Table.Th><Table.Th>{t("Şiddet")}</Table.Th><Table.Th>{t("Zafiyet")}</Table.Th><Table.Th>{t("Bileşen")}</Table.Th><Table.Th>{t("Hedef")}</Table.Th><Table.Th>{t("Düzeltilmiş sürüm")}</Table.Th><Table.Th>{t("EPSS")}</Table.Th><Table.Th>{t("Durum")}</Table.Th><Table.Th>{t("Atanan")}</Table.Th></Table.Tr></Table.Thead>
            <Table.Tbody>
              {items.map((x: any) => (
                <Table.Tr key={x.id} style={{ cursor: "pointer" }} onClick={() => setSel(x.id)} bg={picked.has(x.id) ? "var(--mantine-color-indigo-light)" : undefined}>
                  <Table.Td onClick={(e) => e.stopPropagation()}><Checkbox size="xs" checked={picked.has(x.id)} onChange={() => togglePick(x.id)} aria-label={t("Seç")} /></Table.Td>
                  <Table.Td miw={110}><Stack gap={4} align="flex-start"><SevBadge sev={x.severity} />{x.kev && <Badge color="red" variant="outline" size="xs" style={{ flexShrink: 0 }} leftSection={<IconAlertTriangle size={10} />}>{t("KEV")}</Badge>}{x.malicious && <Badge color="dark" size="xs" style={{ flexShrink: 0 }} leftSection={<IconSkull size={10} />}>{t("Zararlı")}</Badge>}</Stack></Table.Td>
                  <Table.Td><Text size="sm" fw={500}>{x.cves[0] ?? x.vuln_id}</Text><Text size="xs" c="dimmed" lineClamp={1} maw={360}>{x.summary}</Text></Table.Td>
                  <Table.Td><Text size="sm">{x.component} <Text span c="dimmed">{x.version}</Text></Text><Text size="xs" c="dimmed">{x.ecosystem}</Text></Table.Td>
                  <Table.Td maw={220}><Group gap={4} wrap="nowrap">{x.target_kind === "web" ? <IconWorld size={14} color="var(--mantine-color-dimmed)" /> : <IconFile size={14} color="var(--mantine-color-dimmed)" />}<Text size="sm" truncate title={x.target_url || x.target}>{x.target}</Text></Group><Text size="xs" c="dimmed" truncate>{x.project}</Text></Table.Td>
                  <Table.Td>{x.upgrade_to || "-"}</Table.Td>
                  <Table.Td>{x.epss != null ? `${(x.epss * 100).toFixed(1)}%` : "-"}</Table.Td>
                  <Table.Td><Stack gap={4} align="flex-start"><StatusBadge status={x.status} />{x.jira_key && <Badge size="xs" variant="outline" color="blue">{x.jira_key}</Badge>}</Stack></Table.Td>
                  <Table.Td>{x.assignee ? <Tooltip label={x.assignee.email}><Avatar size="sm" radius="xl" color="indigo">{x.assignee.email[0].toUpperCase()}</Avatar></Tooltip> : <Text size="xs" c="dimmed">—</Text>}
                    {x.due_date && <Text size="xs" c={new Date(x.due_date) < new Date() ? "red" : "dimmed"}>{fmtDay(x.due_date)}</Text>}</Table.Td>
                </Table.Tr>
              ))}
              {data.data?.items.length === 0 && <Table.Tr><Table.Td colSpan={9}>
                {data.data.matched_targets?.length ? (
                  <Stack gap={6} py="md" align="center">
                    <Text size="sm">{t("\"{q}\" ile eşleşen {n} hedef var; bu filtrelerle bulgusu yok.", { q: f.q, n: data.data.matched_targets.length })}</Text>
                    {data.data.matched_targets.map((m: any) => (
                      <Group key={m.id} gap="xs"><Anchor component={Link} to={`/targets/${m.id}`} size="sm" fw={600}>{m.name}</Anchor>
                        <Text size="xs" c="dimmed">{m.project}</Text>
                        <Badge size="xs" variant="light" color={m.open ? "orange" : "teal"}>{m.open ? t("{n} açık bulgu", { n: m.open }) : t("açık bulgu yok")}</Badge></Group>
                    ))}
                    {f.status && <Anchor size="xs" onClick={() => set("status", "open,in_progress,accepted_risk,false_positive,not_affected,fixed")}>{t("Kapanmış bulgular dahil tüm durumları göster")}</Anchor>}
                  </Stack>
                ) : <Text c="dimmed" ta="center" py="lg">{f.q ? t("\"{q}\" için bulgu yok. Hedef, bileşen veya CVE adını kontrol edin ya da durum filtresini genişletin.", { q: f.q }) : t("Filtreye uyan bulgu yok")}</Text>}
              </Table.Td></Table.Tr>}
            </Table.Tbody>
          </Table>
          </Table.ScrollContainer>
        )}
        {data.data && data.data.total > SIZE && <Group justify="center" p="md"><Pagination total={Math.ceil(data.data.total / SIZE)} value={page} onChange={setPage} /></Group>}
      </Card>
      {data.data && <Text size="xs" c="dimmed" mt="xs">{data.data.total} {t("bulgu")}</Text>}
      {picker.modal}
      <AssignModal opened={assignOpen} onClose={() => { setAssignOpen(false); setPicked(new Set()); }} ids={[...picked]} />
      <Drawer opened={sel !== null} onClose={() => { setSel(null); if (sp.get("open")) { const n = new URLSearchParams(sp); n.delete("open"); setSp(n, { replace: true }); } }} position="right" size="xl" title={t("Bulgu ayrıntısı")}>
        {sel !== null && <FindingDetail id={sel} />}
      </Drawer>
    </>
  );
}
