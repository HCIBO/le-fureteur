import { Avatar, Badge, Group, Paper, Text, Tooltip } from "@mantine/core";
import { IconCrown, IconUser, IconUserStar } from "@tabler/icons-react";
import { t } from "../i18n";

export const TEAM_ROLE: Record<string, { label: string; color: string; icon: any }> = {
  manager: { label: t("Yönetici"), color: "red", icon: IconCrown },
  lead: { label: t("Sorumlu"), color: "orange", icon: IconUserStar },
  member: { label: t("Üye"), color: "gray", icon: IconUser },
};

const CSS = `
.lf-org, .lf-org ul { padding: 0; margin: 0; list-style: none; display: flex; justify-content: center; }
.lf-org ul { padding-top: 22px; position: relative; }
.lf-org li { position: relative; padding: 22px 8px 0; display: flex; flex-direction: column; align-items: center; }
.lf-org > li { padding-top: 0; }
.lf-org li::before, .lf-org li::after { content: ""; position: absolute; top: 0; width: 50%; height: 22px; border-top: 2px solid var(--lf-line); }
.lf-org li::before { right: 50%; }
.lf-org li::after { left: 50%; border-left: 2px solid var(--lf-line); }
.lf-org li:only-child::before, .lf-org li:only-child::after { display: none; }
.lf-org li:only-child { padding-top: 22px; }
.lf-org > li:only-child { padding-top: 0; }
.lf-org li:first-child::before, .lf-org li:last-child::after { border: 0 none; }
.lf-org li:last-child::before { border-right: 2px solid var(--lf-line); border-top-right-radius: 8px; }
.lf-org li:first-child::after { border-top-left-radius: 8px; }
.lf-org ul::before { content: ""; position: absolute; top: 0; left: 50%; height: 22px; border-left: 2px solid var(--lf-line); }
.lf-org li:only-child > .lf-node::before { content: ""; position: absolute; top: -22px; left: 50%; height: 22px; border-left: 2px solid var(--lf-line); }
.lf-org > li:only-child > .lf-node::before { display: none; }
.lf-node { position: relative; transition: transform .15s ease, box-shadow .15s ease; }
.lf-node:hover { transform: translateY(-2px); box-shadow: var(--mantine-shadow-md); }
`;

export type ChartMember = { user: any; role: string; reports_to: number | null; open?: number; overdue?: number };

function Node({ m, onClick }: { m: ChartMember; onClick?: (m: ChartMember) => void }) {
  const R = TEAM_ROLE[m.role] ?? TEAM_ROLE.member;
  return (
    <Paper className="lf-node" withBorder radius="md" p="xs" w={168} shadow="xs" onClick={() => onClick?.(m)}
      style={{ cursor: onClick ? "pointer" : undefined, borderTop: `3px solid var(--mantine-color-${R.color}-6)` }}>
      <Group gap={8} wrap="nowrap">
        <Avatar radius="xl" size="md" color={R.color} variant="light">{(m.user?.name || m.user?.email || "?")[0].toUpperCase()}</Avatar>
        <div style={{ minWidth: 0 }}>
          <Text size="sm" fw={600} truncate>{m.user?.name || m.user?.email}</Text>
          <Group gap={4} wrap="nowrap"><R.icon size={11} color={`var(--mantine-color-${R.color}-6)`} /><Text size="xs" c="dimmed">{R.label}</Text></Group>
        </div>
      </Group>
      {m.open !== undefined && (
        <Group gap={4} mt={6} justify="center">
          <Tooltip label={t("Açık atanmış bulgu")}><Badge size="xs" variant="light" color={m.open ? "indigo" : "gray"}>{t("{n} açık", { n: m.open })}</Badge></Tooltip>
          {!!m.overdue && <Tooltip label={t("Son tarihi geçmiş")}><Badge size="xs" variant="filled" color="red">{t("{n} gecikmiş", { n: m.overdue })}</Badge></Tooltip>}
        </Group>
      )}
    </Paper>
  );
}

export function OrgChart({ members, onClick }: { members: ChartMember[]; onClick?: (m: ChartMember) => void }) {
  if (!members.length) return <Text size="sm" c="dimmed" ta="center">{t("Henüz üye yok")}</Text>;
  const ids = new Set(members.map((m) => m.user.id));
  const seen = new Set<number>();
  const kids = (id: number) => members.filter((m) => m.reports_to === id && !seen.has(m.user.id));
  const render = (m: ChartMember, depth: number): any => {
    seen.add(m.user.id);
    const ch = depth < 5 ? kids(m.user.id) : [];
    return (
      <li key={m.user.id}>
        <Node m={m} onClick={onClick} />
        {ch.length > 0 && <ul>{ch.map((c) => render(c, depth + 1))}</ul>}
      </li>
    );
  };
  const order = (m: ChartMember) => (m.role === "manager" ? 0 : m.role === "lead" ? 1 : 2);
  const roots = members.filter((m) => !m.reports_to || !ids.has(m.reports_to)).sort((a, b) => order(a) - order(b));
  const managers = roots.filter((m) => m.role === "manager");
  const rest = roots.filter((m) => m.role !== "manager");
  let tree;
  if (managers.length === 1) {
    const top = managers[0];
    seen.add(top.user.id);
    const ch = [...kids(top.user.id), ...rest.filter((r) => r.user.id !== top.user.id)];
    tree = <li><Node m={top} onClick={onClick} />{ch.length > 0 && <ul>{ch.map((c) => render(c, 1))}</ul>}</li>;
  } else {
    tree = roots.map((r) => render(r, 0));
  }
  const left = members.filter((m) => !seen.has(m.user.id));
  return (
    <div style={{ overflowX: "auto", padding: "8px 0 4px", ["--lf-line" as any]: "var(--mantine-color-default-border)" }}>
      <style>{CSS}</style>
      <ul className="lf-org" style={{ minWidth: "max-content", margin: "0 auto" }}>{tree}{left.map((m) => render(m, 0))}</ul>
    </div>
  );
}
