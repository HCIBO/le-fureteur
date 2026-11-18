import { Badge, Group, Select, TextInput } from "@mantine/core";
import { useQuery } from "@tanstack/react-query";
import { IconAlertTriangle, IconCalendarDue } from "@tabler/icons-react";
import { api, fmtDay } from "../api";
import { t } from "../i18n";

export const PROJECT_STATUS: Record<string, { label: string; color: string }> = {
  planning: { label: t("Planlanıyor"), color: "gray" },
  active: { label: t("Devam ediyor"), color: "blue" },
  on_hold: { label: t("Beklemede"), color: "yellow" },
  done: { label: t("Tamamlandı"), color: "green" },
};

export const ProjectStatusBadge = ({ s }: { s: string }) => <Badge variant="light" color={PROJECT_STATUS[s]?.color}>{PROJECT_STATUS[s]?.label ?? s}</Badge>;

export function DueBadge({ due, done }: { due?: string | null; done?: boolean }) {
  if (!due) return <span style={{ color: "var(--mantine-color-dimmed)", fontSize: 12 }}>—</span>;
  const days = Math.ceil((new Date(due).getTime() - Date.now()) / 86400e3);
  const late = days < 0 && !done;
  const soon = days >= 0 && days <= 7 && !done;
  return (
    <Badge variant={late ? "filled" : "light"} color={done ? "gray" : late ? "red" : soon ? "orange" : "gray"} tt="none"
      leftSection={late ? <IconAlertTriangle size={11} /> : <IconCalendarDue size={11} />}>
      {fmtDay(due)}{late ? ` · ${t("{n} gün gecikti", { n: -days })}` : soon ? ` · ${t("{n} gün kaldı", { n: days })}` : ""}
    </Badge>
  );
}

const toInput = (s?: string | null) => (s ? s.slice(0, 10) : "");
export const fromInput = (v: string) => (v ? new Date(`${v}T23:59:00`).toISOString() : null);

export function ProjectPlanFields({ orgId, value, onChange }: { orgId: number | null; value: { status: string; due_date: string | null; owner_id: string | null }; onChange: (v: any) => void }) {
  const people = useQuery<any[]>({ queryKey: ["directory", orgId], queryFn: () => api(`/directory${orgId ? `?org_id=${orgId}` : ""}`), enabled: !!orgId });
  return (
    <Group grow align="flex-start">
      <Select label={t("Durum")} data={Object.entries(PROJECT_STATUS).map(([value, s]) => ({ value, label: s.label }))} value={value.status} onChange={(v) => onChange({ ...value, status: v ?? "active" })} allowDeselect={false} />
      <TextInput type="date" label={t("Son tarih")} value={toInput(value.due_date)} onChange={(e) => onChange({ ...value, due_date: fromInput(e.currentTarget.value) })} />
      <Select label={t("Proje sahibi")} clearable searchable placeholder="—" disabled={!orgId} data={(people.data ?? []).map((u) => ({ value: String(u.id), label: u.name || u.email }))} value={value.owner_id} onChange={(v) => onChange({ ...value, owner_id: v })} />
    </Group>
  );
}
