import { Badge, Group, Text, Title } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { JOB_LABEL, SEV_COLOR, SEV_LABEL, STATUS_LABEL } from "../api";
import { ReactNode } from "react";
import { t } from "../i18n";

export function SevBadge({ sev }: { sev: string }) {
  const dark = sev === "MEDIUM";
  return (
    <Badge miw="fit-content" styles={{ label: { overflow: "visible" } }} variant="filled" style={{ background: SEV_COLOR[sev] ?? "#999", color: dark ? "#0b0b0b" : "#fff", flexShrink: 0, overflow: "visible" }}>
      {SEV_LABEL[sev] ?? sev}
    </Badge>
  );
}

const STATUS_COLOR: Record<string, string> = {
  open: "red", in_progress: "blue", accepted_risk: "yellow", false_positive: "gray", not_affected: "gray", fixed: "green",
};
export function StatusBadge({ status }: { status: string }) {
  return <Badge miw="fit-content" styles={{ label: { overflow: "visible" } }} variant="light" color={STATUS_COLOR[status] ?? "gray"}>{STATUS_LABEL[status] ?? status}</Badge>;
}

const JOB_COLOR: Record<string, string> = { queued: "gray", running: "blue", done: "green", failed: "red", canceled: "dark" };
export function JobBadge({ status }: { status: string }) {
  return <Badge miw="fit-content" styles={{ label: { overflow: "visible" } }} variant="light" color={JOB_COLOR[status]}>{JOB_LABEL[status] ?? status}</Badge>;
}

export function PageHeader({ title, sub, right }: { title: string; sub?: ReactNode; right?: ReactNode }) {
  return (
    <Group justify="space-between" mb="lg" align="flex-end">
      <div>
        <Title order={2}>{title}</Title>
        {sub && <Text c="dimmed" size="sm">{sub}</Text>}
      </div>
      {right}
    </Group>
  );
}

export function OpenCounts({ open }: { open: Record<string, number> }) {
  const items = ["CRITICAL", "HIGH", "MEDIUM", "LOW"].filter((s) => open?.[s]);
  if (!items.length) return <Text size="sm" c="dimmed">{t("Açık bulgu yok")}</Text>;
  return (
    <Group gap={4}>
      {items.map((s) => (
        <Badge key={s} size="sm" variant="filled" style={{ background: SEV_COLOR[s], color: s === "MEDIUM" ? "#0b0b0b" : "#fff" }}>
          {SEV_LABEL[s]} {open[s]}
        </Badge>
      ))}
    </Group>
  );
}

export function ok(message: string) {
  notifications.show({ color: "green", message });
}
export function fail(e: unknown) {
  notifications.show({ color: "red", title: t("Hata"), message: t(e instanceof Error ? e.message : String(e)) });
}
