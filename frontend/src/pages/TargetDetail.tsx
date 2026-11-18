import { Anchor, Badge, Button, Card, Group, Menu, Paper, Progress, SimpleGrid, Stack, Table, Text, ThemeIcon, ActionIcon } from "@mantine/core";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { IconFile, IconTrash, IconPlayerPlay, IconChevronDown, IconArrowBarToUp, IconArrowBarToDown } from "@tabler/icons-react";
import { Dropzone, Pending, uploadAll } from "../components/Dropzone";
import { typeOf } from "../components/TargetTypes";
import { TargetOptionsCard } from "../components/TargetOptions";
import { api, fmtDate, fmtSize, User } from "../api";
import { fail, JobBadge, ok, OpenCounts, PageHeader } from "../components/ui";
import { SchedulesCard } from "../components/Schedules";
import { TrendCard } from "../components/TrendCard";
import { QueueHint } from "../components/QueuePanel";
import { WebAuthCard } from "../components/WebAuth";
import { t } from "../i18n";

export default function TargetDetail({ user }: { user: User }) {
  const { id } = useParams();
  const qc = useQueryClient();
  const nav = useNavigate();
  const scans = useQuery<any[]>({ queryKey: ["scans", "target", id], queryFn: () => api(`/scans?target_id=${id}`), refetchInterval: 5000 });
  const target = useQuery<any>({ queryKey: ["target", id], queryFn: () => api(`/targets/${id}`) });
  const [uploading, setUploading] = useState(false);
  const tg = target.data;
  const refresh = () => { qc.invalidateQueries({ queryKey: ["target", id] }); qc.invalidateQueries({ queryKey: ["scans", "target", id] }); };

  const [pending, setPending] = useState<Pending[]>([]);
  const meta = useQuery<any>({ queryKey: ["meta"], queryFn: () => api("/meta") });
  async function upload() {
    setUploading(true);
    try {
      const n = await uploadAll(Number(id), pending, setPending);
      if (n) ok(t("{n} dosya yüklendi", { n }));
      refresh();
      window.setTimeout(() => setPending((cur) => cur.filter((x) => x.status !== "done")), 1500);
    } finally { setUploading(false); }
  }
  async function delFile(stored: string) {
    try { await api(`/targets/${id}/files/${encodeURIComponent(stored)}`, { method: "DELETE" }); refresh(); } catch (e) { fail(e); }
  }
  async function scan(priority?: string) {
    try { const s = await api(`/targets/${id}/scans`, priority ? { body: { priority } } : { method: "POST" }); ok(t("Tarama kuyruğa alındı")); nav(`/scans/${s.id}`); } catch (e) { fail(e); }
  }
  async function remove() {
    if (!confirm(t("Hedef, taramaları ve bulgularıyla birlikte silinsin mi?"))) return;
    try { await api(`/targets/${id}`, { method: "DELETE" }); nav(`/projects/${tg.project_id}`); } catch (e) { fail(e); }
  }
  if (!tg) return null;
  const T = typeOf(tg);
  const running = scans.data?.some((s) => ["queued", "running"].includes(s.job.status));
  return (
    <>
      <PageHeader title={tg.name} sub={<><Anchor component={Link} to={`/projects/${tg.project_id}`} size="sm">{t("← proje")}</Anchor> · <Badge variant="light" color={T.color} tt="none" leftSection={<T.icon size={12} />}>{T.title}</Badge>{tg.kind === "web" ? ` · ${tg.url}` : ""}</>}
        right={<Group><Button variant="default" onClick={remove}>{t("Hedefi sil")}</Button><Group gap={0} wrap="nowrap">
          <Button leftSection={<IconPlayerPlay size={16} />} onClick={() => scan()} disabled={running || (tg.kind === "upload" && !tg.files.length)} style={{ borderTopRightRadius: 0, borderBottomRightRadius: 0 }}>{t("Taramayı başlat")}</Button>
          <Menu position="bottom-end" withinPortal>
            <Menu.Target><Button px={8} disabled={running || (tg.kind === "upload" && !tg.files.length)} style={{ borderTopLeftRadius: 0, borderBottomLeftRadius: 0, borderLeft: "1px solid rgba(255,255,255,.35)" }} aria-label={t("Kuyruk seçenekleri")}><IconChevronDown size={16} /></Button></Menu.Target>
            <Menu.Dropdown>
              <Menu.Label>{t("Kuyruğa nasıl eklensin?")}</Menu.Label>
              {(user.role === "admin" || user.role === "analyst") && <Menu.Item leftSection={<IconArrowBarToUp size={14} />} onClick={() => scan("high")}>{t("Kuyruğun önüne al")}</Menu.Item>}
              <Menu.Item leftSection={<IconPlayerPlay size={14} />} onClick={() => scan("normal")}>{t("Normal (proje kuralı)")}</Menu.Item>
              <Menu.Item leftSection={<IconArrowBarToDown size={14} />} onClick={() => scan("low")}>{t("Sona ekle")}</Menu.Item>
            </Menu.Dropdown>
          </Menu>
        </Group></Group>} />
      <div style={{ marginBottom: "var(--mantine-spacing-md)" }}><QueueHint /></div>
      <SimpleGrid cols={{ base: 1, md: 2 }} mb="lg">
        <Card withBorder>
          <Text fw={600} mb="xs">{t("Açık bulgular")}</Text>
          <OpenCounts open={tg.open} />
          <Anchor component={Link} to={`/findings?target_id=${tg.id}`} size="sm" mt="sm" display="block">{t("Tüm bulgular →")}</Anchor>
        </Card>
        <TargetOptionsCard tg={tg} onSaved={refresh} />
      </SimpleGrid>
      <SimpleGrid cols={{ base: 1, md: tg.kind === "web" ? 2 : 1 }} mb="lg">
        {tg.kind === "web" && <div id="auth"><WebAuthCard target={tg} onSaved={refresh} /></div>}
        <SchedulesCard kind="scan" targetId={tg.id} title={t("Zamanlanmış tarama")}
          help={tg.kind === "upload" ? t("Son yüklenen dosyalar, güncel zafiyet veritabanıyla yeniden taranır — yeni yayımlanan zafiyetler yakalanır.") : t("Web adresi düzenli olarak yeniden taranır.")} />
      </SimpleGrid>
      <div style={{ marginBottom: "var(--mantine-spacing-lg)" }}><TrendCard targetId={tg.id} /></div>
      {tg.kind === "upload" && (
        <Card withBorder mb="lg">
          <Group justify="space-between" mb="sm">
            <div>
              <Text fw={600}>{t("Dosyalar")}</Text>
              <Text size="xs" c="dimmed">{T.desc}</Text>
            </div>
            <Badge variant="light" color={T.color}>{t("{n} / {m} dosya", { n: tg.files.length, m: meta.data?.max_files_per_target ?? 20 })}</Badge>
          </Group>
          <SimpleGrid cols={{ base: 1, md: 2 }}>
            <Stack gap="xs">
              <Dropzone files={pending} onChange={setPending} accept={T.accept} maxFiles={Math.max(0, (meta.data?.max_files_per_target ?? 20) - tg.files.length)} maxMb={meta.data?.max_upload_mb ?? 2048} disabled={uploading} />
              {pending.some((x) => x.status === "waiting") && <Button onClick={upload} loading={uploading}>{t("{n} dosyayı yükle", { n: pending.filter((x) => x.status === "waiting").length })}</Button>}
            </Stack>
            <Stack gap="xs">
              {tg.files.map((f: any) => (
                <Paper key={f.stored} withBorder p="xs" radius="md">
                  <Group wrap="nowrap" gap="sm">
                    <ThemeIcon variant="light" color={T.color}><IconFile size={16} /></ThemeIcon>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <Text size="sm" truncate>{f.name}</Text>
                      <Text size="xs" c="dimmed" ff="monospace">{fmtSize(f.size)} · sha256 {f.sha256.slice(0, 16)}…</Text>
                    </div>
                    <ActionIcon variant="subtle" color="red" onClick={() => delFile(f.stored)} aria-label={t("Sil")}><IconTrash size={16} /></ActionIcon>
                  </Group>
                </Paper>
              ))}
              {tg.files.length === 0 && <Text c="dimmed" size="sm" ta="center" py="md">{t("Henüz dosya yok — soldaki alana sürükleyin")}</Text>}
            </Stack>
          </SimpleGrid>
        </Card>
      )}
      <Card withBorder p={0}>
        <Text fw={600} p="md" pb={0}>{t("Taramalar")}</Text>
        <Table.ScrollContainer minWidth={640}><Table highlightOnHover verticalSpacing="sm">
          <Table.Thead><Table.Tr><Table.Th>#</Table.Th><Table.Th>{t("Durum")}</Table.Th><Table.Th>{t("Başlangıç")}</Table.Th><Table.Th>{t("Sonuç")}</Table.Th></Table.Tr></Table.Thead>
          <Table.Tbody>
            {(scans.data ?? []).map((s) => (
              <Table.Tr key={s.id} style={{ cursor: "pointer" }} onClick={() => nav(`/scans/${s.id}`)}>
                <Table.Td>#{s.id}</Table.Td>
                <Table.Td><Stack gap={4}><JobBadge status={s.job.status} />{s.job.status === "running" && <Progress value={s.job.progress} size="sm" w={120} />}</Stack></Table.Td>
                <Table.Td>{fmtDate(s.created_at)}</Table.Td>
                <Table.Td>{s.summary ? <Text size="sm">{s.summary.components} {t("bileşen ·")} {s.summary.findings} {t("bulgu ·")} {s.summary.new} {t("yeni ·")} {s.summary.fixed} {t("kapandı")}</Text> : s.job.error ? <Text size="sm" c="red">{t(s.job.error)}</Text> : "-"}</Table.Td>
              </Table.Tr>
            ))}
            {scans.data?.length === 0 && <Table.Tr><Table.Td colSpan={4}><Text c="dimmed" ta="center" py="md">{t("Henüz tarama yok")}</Text></Table.Td></Table.Tr>}
          </Table.Tbody>
        </Table></Table.ScrollContainer>
      </Card>
    </>
  );
}
