import { ActionIcon, Badge, Button, Card, Chip, Group, NumberInput, SegmentedControl, Select, Stack, Switch, Table, Text, TextInput } from "@mantine/core";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { IconTrash } from "@tabler/icons-react";
import { api, fmtDate } from "../api";
import { fail, ok } from "./ui";
import { t } from "../i18n";

const DAYS = () => [
  { v: 1, l: t("Pzt") }, { v: 2, l: t("Sal") }, { v: 3, l: t("Çar") }, { v: 4, l: t("Per") }, { v: 5, l: t("Cum") }, { v: 6, l: t("Cmt") }, { v: 0, l: t("Paz") },
];
const HOURS = Array.from({ length: 24 }, (_, h) => ({ value: String(h), label: `${String(h).padStart(2, "0")}:00` }));
const EVERY = [1, 2, 3, 4, 6, 8, 12].map((n) => ({ value: String(n), label: n === 1 ? t("her saat") : t("her {n} saatte bir", { n }) }));
const hh = (h: number | string) => `${String(h).padStart(2, "0")}:00`;
const zoned = (iso: string) => `${iso.slice(8, 10)}.${iso.slice(5, 7)}.${iso.slice(0, 4)} ${iso.slice(11, 16)}`;

function daysField(days: number[]): string {
  const s = [...new Set(days)].sort((a, b) => a - b);
  if (s.length === 0 || s.length === 7) return "*";
  if (s.join(",") === "1,2,3,4,5") return "1-5";
  return s.join(",");
}

function parseDays(f: string): number[] | null {
  if (f === "*") return [0, 1, 2, 3, 4, 5, 6];
  const out: number[] = [];
  for (const part of f.split(",")) {
    const m = part.match(/^(\d)(?:-(\d))?$/);
    if (!m) return null;
    const a = Number(m[1]), b = m[2] ? Number(m[2]) : a;
    for (let d = a; d <= b; d++) out.push(d % 7);
  }
  return out;
}

function daysLabel(days: number[]): string {
  const s = new Set(days);
  if (s.size === 7) return t("Her gün");
  if (s.size === 5 && [1, 2, 3, 4, 5].every((d) => s.has(d))) return t("Hafta içi");
  if (s.size === 2 && s.has(0) && s.has(6)) return t("Hafta sonu");
  return DAYS().filter((d) => s.has(d.v)).map((d) => d.l).join(", ");
}

export function describeCron(cron: string): string {
  const p = cron.trim().split(/\s+/);
  if (p.length !== 5 || p[0] !== "0") return t("Özel: {c}", { c: cron });
  const [, h, dom, mon, dow] = p;
  const days = parseDays(dow);
  if (mon !== "*" || !days) return t("Özel: {c}", { c: cron });
  if (dom !== "*") return /^\d+$/.test(dom) && /^\d+$/.test(h) && dow === "*" ? t("Her ayın {d}. günü {h}", { d: dom, h: hh(h) }) : t("Özel: {c}", { c: cron });
  const win = h.match(/^(\d+)-(\d+)(?:\/(\d+))?$/);
  if (win) {
    const n = Number(win[3] ?? 1);
    return t("{days} · {a}–{b} arası {every}", { days: daysLabel(days), a: hh(win[1]), b: hh(win[2]), every: n === 1 ? t("her saat") : t("her {n} saatte bir", { n }) });
  }
  if (/^\d+$/.test(h)) {
    const n = new Set(days).size;
    return n === 7 ? t("Her gün {h}", { h: hh(h) }) : t("{days} {h} (haftada {n} kez)", { days: daysLabel(days), h: hh(h), n });
  }
  return t("Özel: {c}", { c: cron });
}

type Mode = "window" | "weekly" | "daily" | "monthly" | "custom";

export function ScheduleBuilder({ onChange }: { onChange: (cron: string, valid: boolean) => void }) {
  const [mode, setMode] = useState<Mode>("weekly");
  const [days, setDays] = useState<string[]>(["1", "4"]);
  const [hour, setHour] = useState("3");
  const [start, setStart] = useState("9");
  const [end, setEnd] = useState("18");
  const [every, setEvery] = useState("3");
  const [dom, setDom] = useState<number>(1);
  const [custom, setCustom] = useState("0 2 * * *");
  const dayNums = days.map(Number);
  const cron = useMemo(() => {
    if (mode === "daily") return `0 ${hour} * * *`;
    if (mode === "monthly") return `0 ${hour} ${dom} * *`;
    if (mode === "weekly") return `0 ${hour} * * ${daysField(dayNums)}`;
    if (mode === "window") return `0 ${start}-${end}${every !== "1" ? `/${every}` : ""} * * ${daysField(dayNums)}`;
    return custom.trim();
  }, [mode, hour, dom, days, start, end, every, custom]);
  const localErr = (mode === "weekly" || mode === "window") && days.length === 0 ? t("En az bir gün seçin")
    : mode === "window" && Number(start) >= Number(end) ? t("Bitiş saati başlangıçtan sonra olmalı") : "";
  const [preview, setPreview] = useState<{ next: string[]; timezone: string } | null>(null);
  const [err, setErr] = useState("");
  useEffect(() => {
    if (localErr) { setPreview(null); setErr(localErr); onChange(cron, false); return; }
    const tg = setTimeout(() => {
      api(`/schedules/preview?cron=${encodeURIComponent(cron)}`).then((p) => { setPreview(p); setErr(""); onChange(cron, true); })
        .catch((e) => { setPreview(null); setErr(e.message); onChange(cron, false); });
    }, 300);
    return () => clearTimeout(tg);
  }, [cron, localErr]);
  const quick: { l: string; apply: () => void }[] = [
    { l: t("Haftada 1 (Pzt 03:00)"), apply: () => { setMode("weekly"); setDays(["1"]); setHour("3"); } },
    { l: t("Haftada 2 (Pzt + Per 03:00)"), apply: () => { setMode("weekly"); setDays(["1", "4"]); setHour("3"); } },
    { l: t("Mesai saatlerinde 3 saatte bir"), apply: () => { setMode("window"); setDays(["1", "2", "3", "4", "5"]); setStart("9"); setEnd("18"); setEvery("3"); } },
    { l: t("Gece her gün 02:00"), apply: () => { setMode("daily"); setHour("2"); } },
  ];
  return (
    <Stack gap="xs">
      <Group gap={6}>{quick.map((q) => <Badge key={q.l} variant="light" tt="none" style={{ cursor: "pointer" }} onClick={q.apply}>{q.l}</Badge>)}</Group>
      <SegmentedControl size="xs" value={mode} onChange={(v) => setMode(v as Mode)} data={[
        { value: "window", label: t("Sürekli (saat aralığı)") }, { value: "weekly", label: t("Belirli günlerde") },
        { value: "daily", label: t("Her gün") }, { value: "monthly", label: t("Ayda bir") }, { value: "custom", label: t("Cron") }]} />
      {(mode === "window" || mode === "weekly") && (
        <Chip.Group multiple value={days} onChange={setDays}>
          <Group gap={4}>{DAYS().map((d) => <Chip key={d.v} value={String(d.v)} size="xs">{d.l}</Chip>)}</Group>
        </Chip.Group>
      )}
      {mode === "window" && (
        <Group grow>
          <Select label={t("Başlangıç")} data={HOURS} value={start} onChange={(v) => setStart(v ?? "9")} allowDeselect={false} />
          <Select label={t("Bitiş")} data={HOURS} value={end} onChange={(v) => setEnd(v ?? "18")} allowDeselect={false} />
          <Select label={t("Sıklık")} data={EVERY} value={every} onChange={(v) => setEvery(v ?? "3")} allowDeselect={false} />
        </Group>
      )}
      {(mode === "weekly" || mode === "daily" || mode === "monthly") && (
        <Group grow>
          {mode === "monthly" && <NumberInput label={t("Ayın günü")} min={1} max={28} value={dom} onChange={(v) => setDom(Math.min(28, Math.max(1, Number(v) || 1)))} />}
          <Select label={t("Saat")} data={HOURS} value={hour} onChange={(v) => setHour(v ?? "3")} allowDeselect={false} />
        </Group>
      )}
      {mode === "custom" && <TextInput label={t("Cron (dakika saat gün ay haftanın-günü)")} value={custom} onChange={(e) => setCustom(e.currentTarget.value)} ff="monospace" />}
      {err ? <Text size="xs" c="red">{err}</Text> : preview && (
        <Text size="xs" c="dimmed"><Text span fw={600} c="var(--mantine-color-text)">{describeCron(cron)}</Text> · {t("Sonraki çalışmalar (")}{preview.timezone}): {preview.next.slice(0, 3).map(zoned).join(" · ")}</Text>
      )}
    </Stack>
  );
}

export function SchedulesCard({ kind, targetId, title, help }: { kind: "scan" | "db_update"; targetId?: number; title: string; help: string }) {
  const qc = useQueryClient();
  const key = ["schedules", kind, targetId ?? 0];
  const list = useQuery<any[]>({ queryKey: key, queryFn: () => api(`/schedules?kind=${kind}${targetId ? `&target_id=${targetId}` : ""}`) });
  const [cron, setCron] = useState("");
  const [valid, setValid] = useState(false);
  const refresh = () => qc.invalidateQueries({ queryKey: key });
  async function add() {
    try { await api("/schedules", { body: { kind, target_id: targetId ?? null, cron } }); ok(t("Zamanlama eklendi")); refresh(); } catch (e) { fail(e); }
  }
  async function toggle(s: any) {
    try { await api(`/schedules/${s.id}`, { method: "PATCH", body: { enabled: !s.enabled } }); refresh(); } catch (e) { fail(e); }
  }
  async function remove(s: any) {
    try { await api(`/schedules/${s.id}`, { method: "DELETE" }); refresh(); } catch (e) { fail(e); }
  }
  return (
    <Card withBorder>
      <Text fw={600}>{title}</Text>
      <Text size="xs" c="dimmed" mb="sm">{help}</Text>
      {(list.data ?? []).length > 0 && (
        <Table mb="sm">
          <Table.Tbody>
            {list.data!.map((s) => (
              <Table.Tr key={s.id}>
                <Table.Td><Text size="sm" fw={500}>{describeCron(s.cron)}</Text><Text size="xs" c="dimmed" ff="monospace">{s.cron}</Text></Table.Td>
                <Table.Td><Text size="xs">{t("Sonraki:")} {s.enabled ? fmtDate(s.next_run_at) : "—"}</Text><Text size="xs" c="dimmed">{t("Son:")} {fmtDate(s.last_run_at)}</Text></Table.Td>
                <Table.Td><Switch size="xs" checked={s.enabled} onChange={() => toggle(s)} aria-label={t("Etkin")} /></Table.Td>
                <Table.Td ta="right"><ActionIcon variant="subtle" color="red" onClick={() => remove(s)} aria-label={t("Sil")}><IconTrash size={16} /></ActionIcon></Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}
      <ScheduleBuilder onChange={(c, v) => { setCron(c); setValid(v); }} />
      <Group justify="flex-end" mt="xs"><Button size="xs" variant="light" onClick={add} disabled={!valid}>{t("Zamanlama ekle")}</Button></Group>
      {(list.data ?? []).length === 0 && <Badge variant="light" color="gray" mt="xs">{t("Zamanlama yok")}</Badge>}
    </Card>
  );
}

export function ProjectSchedulesCard({ projectId }: { projectId: number }) {
  const qc = useQueryClient();
  const key = ["schedules", "project", projectId];
  const list = useQuery<any[]>({ queryKey: key, queryFn: () => api(`/schedules?kind=scan&project_id=${projectId}`) });
  const [cron, setCron] = useState("");
  const [valid, setValid] = useState(false);
  const [kind, setKind] = useState("web");
  const [replace, setReplace] = useState(true);
  const [busy, setBusy] = useState(false);
  const groups = Object.entries((list.data ?? []).reduce((m: Record<string, any[]>, s: any) => { (m[s.cron] ||= []).push(s); return m; }, {}));
  const refresh = () => { qc.invalidateQueries({ queryKey: key }); qc.invalidateQueries({ queryKey: ["schedules"] }); };
  async function apply() {
    setBusy(true);
    try {
      const r = await api(`/projects/${projectId}/schedules`, { body: { cron, target_kind: kind, replace } });
      ok(t("{n} hedefe zamanlama eklendi", { n: r.created }) + (r.skipped ? t(" ({n} hedefte zaten vardı)", { n: r.skipped }) : ""));
      refresh();
    } catch (e) { fail(e); } finally { setBusy(false); }
  }
  async function clearAll() {
    if (!confirm(t("Bu projedeki tüm tarama zamanlamaları silinsin mi?"))) return;
    try { const r = await api(`/projects/${projectId}/schedules`, { method: "DELETE" }); ok(t("{n} zamanlama silindi", { n: r.deleted })); refresh(); } catch (e) { fail(e); }
  }
  return (
    <Card withBorder>
      <Group justify="space-between" mb={4}>
        <Text fw={600}>{t("Sürekli tarama")}</Text>
        {groups.length > 0 && <Button size="compact-xs" variant="subtle" color="red" onClick={clearAll}>{t("Tümünü kaldır")}</Button>}
      </Group>
      <Text size="xs" c="dimmed" mb="sm">{t("Projedeki hedefler seçtiğiniz düzende kendiliğinden yeniden taranır; değişimler Eğilim grafiğinde ve bildirimlerde görünür. Aynı anda başlayan taramalar kuyruk kurallarına göre sırayla çalışır.")}</Text>
      {groups.length > 0 && (
        <Stack gap={4} mb="sm">
          {groups.map(([c, items]) => (
            <Group key={c} justify="space-between" wrap="nowrap">
              <div><Text size="sm" fw={500}>{describeCron(c)}</Text><Text size="xs" c="dimmed">{t("{n} hedef", { n: items.length })} · {t("Sonraki:")} {fmtDate(items.map((x: any) => x.next_run_at).filter(Boolean).sort()[0])}</Text></div>
              <Badge variant="light" color={items.every((x: any) => x.enabled) ? "green" : "gray"}>{items.filter((x: any) => x.enabled).length}/{items.length} {t("etkin")}</Badge>
            </Group>
          ))}
        </Stack>
      )}
      <ScheduleBuilder onChange={(c, v) => { setCron(c); setValid(v); }} />
      <Group mt="sm" justify="space-between" wrap="wrap">
        <Group gap="sm">
          <SegmentedControl size="xs" value={kind} onChange={setKind} data={[{ value: "web", label: t("Web hedefleri") }, { value: "upload", label: t("Dosya hedefleri") }, { value: "all", label: t("Tümü") }]} />
          <Switch size="xs" label={t("Mevcut zamanlamaların yerine geçsin")} checked={replace} onChange={(e) => setReplace(e.currentTarget.checked)} />
        </Group>
        <Button size="xs" onClick={apply} loading={busy} disabled={!valid}>{t("Tüm hedeflere uygula")}</Button>
      </Group>
    </Card>
  );
}
