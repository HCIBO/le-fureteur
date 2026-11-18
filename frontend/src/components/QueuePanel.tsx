import { ActionIcon, Anchor, Badge, Card, Group, NumberInput, Progress, SegmentedControl, Stack, Table, Text, Tooltip } from "@mantine/core";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { IconArrowBarToDown, IconArrowBarToUp, IconChevronDown, IconChevronUp, IconClockPause, IconSettings, IconStack2 } from "@tabler/icons-react";
import { Link } from "react-router-dom";
import { api, fmtDate } from "../api";
import { useEffect, useState } from "react";
import { Button } from "@mantine/core";
import { fail, ok } from "./ui";
import { t } from "../i18n";

export function QueuePanel() {
  const qc = useQueryClient();
  const q = useQuery<any>({ queryKey: ["queue"], queryFn: () => api("/queue"), refetchInterval: 4000 });
  const d = q.data;
  if (!d || (d.running.length === 0 && d.queued.length === 0)) return null;
  async function move(jobId: number, to: string) {
    try { await api(`/queue/${jobId}/move`, { body: { to } }); qc.invalidateQueries({ queryKey: ["queue"] }); } catch (e) { fail(e); }
  }
  const rule = [d.concurrency ? t("aynı anda {n} tarama", { n: d.concurrency }) : t("aynı anda: worker ayarı"),
    d.gap_seconds ? t("taramalar arası {s} sn", { s: d.gap_seconds }) : t("taramalar arası bekleme yok")].join(" · ");
  const name = (x: any) => x.kind === "scan" ? <Anchor component={Link} to={`/scans/${x.scan_id}`} size="sm" fw={500}>{x.target}</Anchor> : <Text size="sm" fw={500}>{t("Zafiyet veritabanı güncellemesi")}</Text>;
  return (
    <Card withBorder mb="md" style={{ borderLeft: "4px solid var(--mantine-color-blue-6)" }}>
      <Group justify="space-between" mb="xs" wrap="wrap">
        <Group gap="xs"><IconStack2 size={18} /><Text fw={700}>{t("Tarama kuyruğu")}</Text>
          <Badge variant="light">{t("{r} çalışıyor · {q} sırada", { r: d.running.length, q: d.queued.length })}</Badge></Group>
        <Group gap={6}><IconClockPause size={14} color="var(--mantine-color-dimmed)" /><Text size="xs" c="dimmed">{rule}</Text>
          {d.can_reorder && <Tooltip label={t("Kuyruk kuralları (Ayarlar → Tarama kuyruğu)")}><ActionIcon component={Link} to="/settings?group=queue" variant="subtle" size="sm" aria-label={t("Kuyruk kuralları")}><IconSettings size={14} /></ActionIcon></Tooltip>}</Group>
      </Group>
      <Table verticalSpacing={6}>
        <Table.Tbody>
          {d.running.map((x: any) => (
            <Table.Tr key={x.job_id}>
              <Table.Td w={70}><Badge color="blue" variant="filled" size="sm">{t("Çalışıyor")}</Badge></Table.Td>
              <Table.Td><Stack gap={2}>{name(x)}<Text size="xs" c="dimmed">{x.project}{x.scheduled ? ` · ${t("zamanlanmış")}` : ""}</Text></Stack></Table.Td>
              <Table.Td w="30%"><Progress value={x.progress} size="sm" animated /></Table.Td>
              <Table.Td><Text size="xs" c="dimmed">{t("Başladı:")} {fmtDate(x.started_at)}</Text></Table.Td>
              <Table.Td />
            </Table.Tr>
          ))}
          {d.queued.map((x: any, i: number) => (
            <Table.Tr key={x.job_id}>
              <Table.Td><Badge color="gray" variant="light" size="sm">#{x.position}</Badge></Table.Td>
              <Table.Td><Stack gap={2}>{name(x)}<Text size="xs" c="dimmed">{x.project}{x.scheduled ? ` · ${t("zamanlanmış")}` : ""}</Text></Stack></Table.Td>
              <Table.Td><Text size="xs" c="dimmed">{t("Sırada")}</Text>{x.rule && (x.rule.parallel || x.rule.gap) ? <Badge size="xs" variant="light" color="grape" tt="none">{ruleText(x.rule)}</Badge> : null}</Table.Td>
              <Table.Td><Text size="xs" c="dimmed">{t("Eklendi:")} {fmtDate(x.created_at)}</Text></Table.Td>
              <Table.Td ta="right">
                {d.can_reorder && (
                  <Group gap={2} justify="flex-end" wrap="nowrap">
                    <Tooltip label={t("En öne al")}><ActionIcon variant="subtle" size="sm" disabled={i === 0} onClick={() => move(x.job_id, "top")} aria-label={t("En öne al")}><IconArrowBarToUp size={15} /></ActionIcon></Tooltip>
                    <Tooltip label={t("Bir yukarı")}><ActionIcon variant="subtle" size="sm" disabled={i === 0} onClick={() => move(x.job_id, "up")} aria-label={t("Bir yukarı")}><IconChevronUp size={15} /></ActionIcon></Tooltip>
                    <Tooltip label={t("Bir aşağı")}><ActionIcon variant="subtle" size="sm" disabled={i === d.queued.length - 1} onClick={() => move(x.job_id, "down")} aria-label={t("Bir aşağı")}><IconChevronDown size={15} /></ActionIcon></Tooltip>
                    <Tooltip label={t("Sona at")}><ActionIcon variant="subtle" size="sm" disabled={i === d.queued.length - 1} onClick={() => move(x.job_id, "bottom")} aria-label={t("Sona at")}><IconArrowBarToDown size={15} /></ActionIcon></Tooltip>
                  </Group>
                )}
              </Table.Td>
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
    </Card>
  );
}

export function QueueHint({ count = 1 }: { count?: number }) {
  const q = useQuery<any>({ queryKey: ["queue"], queryFn: () => api("/queue"), refetchInterval: 10000 });
  const d = q.data;
  if (!d) return null;
  const busy = d.running.length + d.queued.length;
  const rule = [d.concurrency ? t("aynı anda {n} tarama", { n: d.concurrency }) : t("aynı anda: worker ayarı"),
    d.gap_seconds ? t("taramalar arası {s} sn", { s: d.gap_seconds }) : t("taramalar arası bekleme yok")].join(" · ");
  return (
    <Card withBorder padding="xs" bg="var(--mantine-color-default-hover)">
      <Group gap="xs" wrap="nowrap" align="flex-start">
        <IconStack2 size={16} style={{ marginTop: 2, flexShrink: 0 }} />
        <Stack gap={2}>
          <Text size="xs" fw={600}>{busy ? t("Kuyrukta {r} çalışan, {q} bekleyen tarama var; yeni {n} tarama sıranın sonuna eklenir.", { r: d.running.length, q: d.queued.length, n: count })
            : t("Kuyruk boş; tarama hemen başlar.")}</Text>
          <Text size="xs" c="dimmed">{t("Sunucu geneli:")} {rule}{" · "}<Anchor href="/scans" target="_blank" rel="noopener" size="xs">{t("Kuyruğu gör ↗")}</Anchor>
            {d.can_reorder && <>{" · "}<Anchor href="/settings?group=queue" target="_blank" rel="noopener" size="xs">{t("Genel kuralları değiştir ↗")}</Anchor></>}</Text>
        </Stack>
      </Group>
    </Card>
  );
}

export type QueuePolicy = { priority: string; parallel: number; gap: number };
export const ruleText = (r: { parallel: number; gap: number; batch?: boolean }) =>
  [r.parallel === 1 ? t("sırayla") : r.parallel ? t("en fazla {n} aynı anda", { n: r.parallel }) : t("serbest"), r.gap ? t("{s} sn arayla", { s: r.gap }) : ""].filter(Boolean).join(" · ");

export function QueueOptions({ value, onChange, staff }: { value: QueuePolicy; onChange: (v: QueuePolicy) => void; staff: boolean }) {
  const mode = value.parallel === 1 ? "seq" : value.parallel > 1 ? "par" : "free";
  return (
    <Stack gap="xs">
      <Group gap="md" align="flex-end" wrap="wrap">
        <div>
          <Text size="xs" fw={600} mb={4}>{t("Öncelik")}</Text>
          <SegmentedControl size="xs" value={value.priority} onChange={(v) => onChange({ ...value, priority: v })}
            data={[...(staff ? [{ value: "high", label: t("Öne al") }] : []), { value: "normal", label: t("Normal") }, { value: "low", label: t("Sona ekle") }]} />
        </div>
        <div>
          <Text size="xs" fw={600} mb={4}>{t("Çalışma")}</Text>
          <SegmentedControl size="xs" value={mode} onChange={(v) => onChange({ ...value, parallel: v === "seq" ? 1 : v === "par" ? Math.max(2, value.parallel || 2) : 0 })}
            data={[{ value: "seq", label: t("Sırayla") }, { value: "par", label: t("Aynı anda") }, { value: "free", label: t("Serbest") }]} />
        </div>
        {mode === "par" && <NumberInput size="xs" w={120} label={t("En fazla")} min={2} max={20} value={value.parallel} onChange={(v) => onChange({ ...value, parallel: Math.min(20, Math.max(2, Number(v) || 2)) })} suffix={t(" tarama")} />}
        <NumberInput size="xs" w={150} label={t("Aralarında bekleme")} min={0} max={3600} step={10} value={value.gap} onChange={(v) => onChange({ ...value, gap: Math.min(3600, Math.max(0, Number(v) || 0)) })} suffix={t(" sn")} />
      </Group>
      <Text size="xs" c="dimmed">{{ seq: t("Taramalar tek tek çalışır; biri bitince sıradaki başlar."), par: t("En fazla seçilen sayıda tarama birlikte çalışır."), free: t("Sunucuda boş yer oldukça hepsi başlar.") }[mode]}
        {value.gap ? " " + t("Her tarama arasında {s} sn beklenir.", { s: value.gap }) : ""} {t("Diğer projelerin taramaları bu kuraldan etkilenmez.")}</Text>
    </Stack>
  );
}

export function ProjectQueueCard({ project, staff }: { project: any; staff: boolean }) {
  const qc = useQueryClient();
  const [v, setV] = useState<QueuePolicy>(project.queue_policy);
  const [busy, setBusy] = useState(false);
  useEffect(() => setV(project.queue_policy), [project.queue_policy]);
  const dirty = JSON.stringify(v) !== JSON.stringify(project.queue_policy);
  async function save() {
    setBusy(true);
    try { await api(`/projects/${project.id}`, { method: "PATCH", body: { queue_policy: v } }); ok(t("Kaydedildi")); qc.invalidateQueries({ queryKey: ["project", String(project.id)] }); qc.invalidateQueries({ queryKey: ["project"] }); }
    catch (e) { fail(e); } finally { setBusy(false); }
  }
  return (
    <Card withBorder>
      <Group gap="xs" mb={4}><IconStack2 size={18} /><Text fw={600}>{t("Proje kuyruk kuralı")}</Text></Group>
      <Text size="xs" c="dimmed" mb="sm">{t("Bu projenin taramaları (elle başlatılan, toplu ve zamanlanmış) birbirine göre bu kurala uyar; ör. 50 alan adı sırayla veya en fazla 3'er 3'er, aralarında bekleyerek taranır. Sunucu geneli kurallar üst sınırdır.")}</Text>
      <QueueOptions value={v} onChange={setV} staff={staff} />
      <Group justify="flex-end" mt="sm"><Button size="xs" onClick={save} loading={busy} disabled={!dirty}>{t("Kaydet")}</Button></Group>
    </Card>
  );
}
