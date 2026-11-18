import { Card, Group, Paper, ScrollArea, SegmentedControl, SimpleGrid, Table, Text } from "@mantine/core";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useElementSize } from "@mantine/hooks";
import { IconChartLine, IconTable } from "@tabler/icons-react";
import { api } from "../api";
import { t } from "../i18n";

const PERIODS: Record<string, number> = { hour: 24, day: 14, week: 12 };
const SIZES: Record<string, { h1: number; h2: number; tiles: boolean }> = {
  s: { h1: 70, h2: 0, tiles: false }, m: { h1: 120, h2: 80, tiles: true }, l: { h1: 180, h2: 120, tiles: true },
};
const PAD = { l: 36, r: 12, t: 10, b: 22 };
const SIZE_KEY = "lf_trend_size";
const C_OPEN = "var(--mantine-color-indigo-6)", C_NEW = "var(--mantine-color-orange-6)", C_FIXED = "var(--mantine-color-teal-6)";

function label(iso: string, bucket: string) {
  return bucket === "hour" ? `${iso.slice(11, 13)}:00` : `${iso.slice(8, 10)}.${iso.slice(5, 7)}`;
}
const full = (iso: string) => `${iso.slice(8, 10)}.${iso.slice(5, 7)}.${iso.slice(0, 4)} ${iso.slice(11, 16)}`;

function niceMax(v: number) {
  if (v <= 4) return 4;
  const p = 10 ** Math.floor(Math.log10(v)), n = v / p;
  return (n <= 2 ? 2 : n <= 5 ? 5 : 10) * p;
}

const sign = (n: number) => (n > 0 ? `+${n}` : String(n));

export function TrendCard({ projectId, targetId }: { projectId?: number; targetId?: number }) {
  const [bucket, setBucket] = useState("day");
  const [view, setView] = useState("chart");
  const [hover, setHover] = useState<number | null>(null);
  const [size, setSizeState] = useState<string>(() => { try { return localStorage.getItem(SIZE_KEY) ?? "m"; } catch { return "m"; } });
  const setSize = (v: string) => { setSizeState(v); try { localStorage.setItem(SIZE_KEY, v); } catch {  } };
  const { ref, width } = useElementSize();
  const W = Math.max(320, Math.round(width) || 640);
  const { h1: H1, h2: H2, tiles } = SIZES[size] ?? SIZES.m;
  const qs = new URLSearchParams({ bucket, periods: String(PERIODS[bucket]) });
  if (projectId) qs.set("project_id", String(projectId));
  if (targetId) qs.set("target_id", String(targetId));
  const q = useQuery<any>({ queryKey: ["trends", qs.toString()], queryFn: () => api(`/trends?${qs}`) });
  const items: any[] = q.data?.items ?? [];
  const n = items.length;
  const last = items[n - 1], prev = items[n - 2];
  const totals = items.reduce((a, x) => ({ scans: a.scans + x.scans, new: a.new + x.new, fixed: a.fixed + x.fixed }), { scans: 0, new: 0, fixed: 0 });
  const iw = W - PAD.l - PAD.r, bw = n ? iw / n : 0;
  const x = (i: number) => PAD.l + bw * i + bw / 2;
  const maxOpen = niceMax(Math.max(1, ...items.map((i) => i.open)));
  const y1 = (v: number) => PAD.t + (H1 - PAD.t - PAD.b) * (1 - v / maxOpen);
  const maxBar = niceMax(Math.max(1, ...items.map((i) => Math.max(i.new, i.fixed))));
  const mid = PAD.t + (H2 - PAD.t - PAD.b) / 2, half = (H2 - PAD.t - PAD.b) / 2;
  const line = items.map((it, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y1(it.open).toFixed(1)}`).join(" ");
  const area = n ? `${line} L${x(n - 1).toFixed(1)},${y1(0)} L${x(0).toFixed(1)},${y1(0)} Z` : "";
  const every = Math.ceil(n / 7);
  const vsPrev = { hour: t("Önceki saate göre"), day: t("Önceki güne göre"), week: t("Önceki haftaya göre") }[bucket];
  const onMove = (e: React.MouseEvent<SVGRectElement>) => {
    const r = e.currentTarget.getBoundingClientRect();
    const i = Math.floor(((e.clientX - r.left) / r.width) * n);
    setHover(i >= 0 && i < n ? i : null);
  };
  const hv = hover !== null ? items[hover] : null;
  const axisLabels = (h: number) => items.map((it, i) => (i % every === 0 || i === n - 1) && (
    <text key={i} x={x(i)} y={h - 6} fontSize={10} textAnchor="middle" fill="var(--mantine-color-dimmed)">{label(it.start, bucket)}</text>));
  const overlay = (h: number) => <rect x={PAD.l} y={0} width={iw} height={h} fill="transparent" onMouseMove={onMove} onMouseLeave={() => setHover(null)} />;
  const guide = (h: number) => hover !== null && <line x1={x(hover)} x2={x(hover)} y1={PAD.t} y2={h - PAD.b} stroke="var(--mantine-color-default-border)" strokeWidth={1} />;
  return (
    <Card withBorder>
      <Group justify="space-between" mb="sm" wrap="wrap">
        <div><Text fw={600}>{t("Eğilim")}</Text><Text size="xs" c="dimmed">{t("Dönem sonundaki açık bulgu sayısı ve dönem içinde yeni / kapanan bulgular (her hedefin son taramasına göre)")}</Text></div>
        <Group gap="xs">
          <SegmentedControl size="xs" value={bucket} onChange={setBucket} data={[{ value: "hour", label: t("Saat") }, { value: "day", label: t("Gün") }, { value: "week", label: t("Hafta") }]} />
          <SegmentedControl size="xs" value={size} onChange={setSize} data={[{ value: "s", label: t("Küçük") }, { value: "m", label: t("Orta") }, { value: "l", label: t("Büyük") }]} />
          <SegmentedControl size="xs" value={view} onChange={setView} data={[{ value: "chart", label: <IconChartLine size={14} aria-label={t("Grafik")} /> }, { value: "table", label: <IconTable size={14} aria-label={t("Tablo")} /> }]} />
        </Group>
      </Group>
      {last && tiles && (
        <SimpleGrid cols={{ base: 2, sm: 4 }} mb="sm" spacing="xs">
          <Paper withBorder p="xs"><Text size="xs" c="dimmed">{t("Açık bulgu")}</Text><Text fw={800} size="lg">{last.open}</Text></Paper>
          <Paper withBorder p="xs"><Text size="xs" c="dimmed">{vsPrev}</Text>
            <Text fw={800} size="lg" c={last.delta_open > 0 ? "red" : last.delta_open < 0 ? "teal" : undefined}>{prev ? sign(last.open - prev.open) : "—"}</Text></Paper>
          <Paper withBorder p="xs"><Text size="xs" c="dimmed">{t("Yeni / kapanan (aralık)")}</Text><Text fw={800} size="lg">+{totals.new} / {totals.fixed ? `−${totals.fixed}` : "0"}</Text></Paper>
          <Paper withBorder p="xs"><Text size="xs" c="dimmed">{t("Tarama (aralık)")}</Text><Text fw={800} size="lg">{totals.scans}</Text></Paper>
        </SimpleGrid>
      )}
      {n > 0 && totals.scans === 0 && items.every((i) => i.open === 0) ? (
        <Text size="sm" c="dimmed" ta="center" py="lg">{t("Bu aralıkta tamamlanan tarama yok. Sürekli tarama zamanlaması eklerseniz değişim burada görünür.")}</Text>
      ) : view === "table" ? (
<>        <ScrollArea.Autosize mah={size === "m" ? 260 : undefined} type="auto"><Table.ScrollContainer minWidth={520}><Table striped stickyHeader verticalSpacing={size === "l" ? 8 : size === "m" ? 4 : 2} fz={size === "s" ? "xs" : "sm"}>
          <Table.Thead><Table.Tr><Table.Th>{t("Dönem")}</Table.Th><Table.Th ta="right">{t("Açık")}</Table.Th><Table.Th ta="right">{t("Fark")}</Table.Th><Table.Th ta="right">{t("Yeni")}</Table.Th><Table.Th ta="right">{t("Kapanan")}</Table.Th><Table.Th ta="right">{t("Tarama")}</Table.Th><Table.Th ta="right">{t("Bileşen")}</Table.Th></Table.Tr></Table.Thead>
          <Table.Tbody>{[...items].reverse().slice(0, size === "s" ? 5 : undefined).map((it) => (
            <Table.Tr key={it.start}><Table.Td><Text size="xs">{full(it.start)}</Text></Table.Td><Table.Td ta="right">{it.open}</Table.Td>
              <Table.Td ta="right"><Text size="sm" c={it.delta_open > 0 ? "red" : it.delta_open < 0 ? "teal" : "dimmed"}>{sign(it.delta_open)}</Text></Table.Td>
              <Table.Td ta="right">{it.new}</Table.Td><Table.Td ta="right">{it.fixed}</Table.Td><Table.Td ta="right">{it.scans}</Table.Td><Table.Td ta="right">{it.components}</Table.Td></Table.Tr>
          ))}</Table.Tbody>
        </Table></Table.ScrollContainer></ScrollArea.Autosize>
        {size === "s" && n > 5 && <Text size="xs" c="dimmed" mt={4}>{t("Son 5 dönem gösteriliyor; tamamı için Orta veya Büyük seçin.")}</Text>}</>
      ) : (
        <div ref={ref} style={{ position: "relative" }}>
          <Text size="xs" fw={600} mb={2}>{t("Açık bulgu")}{!tiles && last ? ` · ${last.open} (${prev ? sign(last.open - prev.open) : "0"})` : ""}</Text>
          <svg viewBox={`0 0 ${W} ${H1}`} width={W} height={H1} style={{ display: "block", maxWidth: "100%" }} role="img" aria-label={t("Açık bulgu eğilimi")}>
            {[0, 0.5, 1].map((f) => <g key={f}><line x1={PAD.l} x2={W - PAD.r} y1={y1(maxOpen * f)} y2={y1(maxOpen * f)} stroke="var(--mantine-color-default-border)" strokeWidth={0.5} />
              <text x={PAD.l - 6} y={y1(maxOpen * f) + 3} fontSize={10} textAnchor="end" fill="var(--mantine-color-dimmed)">{Math.round(maxOpen * f)}</text></g>)}
            <path d={area} fill={C_OPEN} opacity={0.1} />
            <path d={line} fill="none" stroke={C_OPEN} strokeWidth={2} strokeLinejoin="round" />
            {guide(H1)}
            {items.map((it, i) => (hover === i || i === n - 1) && <circle key={i} cx={x(i)} cy={y1(it.open)} r={4} fill={C_OPEN} stroke="var(--mantine-color-body)" strokeWidth={2} />)}
            {axisLabels(H1)}
            {overlay(H1)}
          </svg>
          {H2 > 0 && <>
          <Group justify="space-between" mt={6} mb={2}>
            <Text size="xs" fw={600}>{t("Yeni / kapanan bulgular")}</Text>
            <Group gap="sm">
              <Group gap={4}><span style={{ width: 10, height: 10, borderRadius: 2, background: C_NEW, display: "inline-block" }} /><Text size="xs">{t("Yeni")}</Text></Group>
              <Group gap={4}><span style={{ width: 10, height: 10, borderRadius: 2, background: C_FIXED, display: "inline-block" }} /><Text size="xs">{t("Kapanan")}</Text></Group>
            </Group>
          </Group>
          <svg viewBox={`0 0 ${W} ${H2}`} width={W} height={H2} style={{ display: "block", maxWidth: "100%" }} role="img" aria-label={t("Yeni ve kapanan bulgular")}>
            <line x1={PAD.l} x2={W - PAD.r} y1={mid} y2={mid} stroke="var(--mantine-color-default-border)" strokeWidth={1} />
            <text x={PAD.l - 6} y={PAD.t + 3} fontSize={10} textAnchor="end" fill="var(--mantine-color-dimmed)">+{maxBar}</text>
            <text x={PAD.l - 6} y={H2 - PAD.b + 3} fontSize={10} textAnchor="end" fill="var(--mantine-color-dimmed)">−{maxBar}</text>
            {guide(H2)}
            {items.map((it, i) => {
              const w = Math.max(2, Math.min(18, bw * 0.55)), hN = (it.new / maxBar) * half, hF = (it.fixed / maxBar) * half;
              return <g key={i}>
                {it.new > 0 && <rect x={x(i) - w / 2} y={mid - hN} width={w} height={Math.max(1, hN - 1)} rx={3} fill={C_NEW} />}
                {it.fixed > 0 && <rect x={x(i) - w / 2} y={mid + 1} width={w} height={Math.max(1, hF - 1)} rx={3} fill={C_FIXED} />}
              </g>;
            })}
            {axisLabels(H2)}
            {overlay(H2)}
          </svg>
          </>}
          {hv && (
            <Paper withBorder shadow="sm" p={8} style={{ position: "absolute", top: 18, left: Math.min(x(hover!) + 12, W - 190), width: 180, pointerEvents: "none" }}>
              <Text size="xs" fw={700}>{full(hv.start)}</Text>
              <Text size="xs">{t("Açık bulgu")}: <b>{hv.open}</b> <Text span size="xs" c={hv.delta_open > 0 ? "red" : hv.delta_open < 0 ? "teal" : "dimmed"}>({sign(hv.delta_open)})</Text></Text>
              <Text size="xs">{t("Yeni")}: {hv.new} · {t("Kapanan")}: {hv.fixed}</Text>
              <Text size="xs" c="dimmed">{t("{n} tarama · {c} bileşen", { n: hv.scans, c: hv.components })}</Text>
            </Paper>
          )}
        </div>
      )}
    </Card>
  );
}
