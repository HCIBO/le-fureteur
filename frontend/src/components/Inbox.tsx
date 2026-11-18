import { ActionIcon, Badge, Button, Divider, Group, Indicator, Popover, ScrollArea, Stack, Text, ThemeIcon, UnstyledButton } from "@mantine/core";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { IconBell, IconCheck, IconAlarm, IconChecks, IconGavel, IconMail, IconMessageCircle, IconShare, IconUserCheck, IconX } from "@tabler/icons-react";
import { useNavigate } from "react-router-dom";
import { api, fmtDate, STATUS_LABEL } from "../api";
import { t } from "../i18n";

export type InboxItem = { id: number; kind: string; params: any; link: string; read: boolean; created_at: string };

export function inboxText(n: InboxItem): { icon: any; color: string; title: string; detail?: string } {
  const p = n.params ?? {};
  const f = `${p.vuln ?? ""} — ${p.component ?? ""} ${p.version ?? ""}`.trim();
  switch (n.kind) {
    case "assigned": return { icon: IconUserCheck, color: "indigo", title: t("{actor} size bir bulgu atadı", { actor: p.actor }), detail: f + (p.note ? ` · ${p.note}` : "") };
    case "assigned_bulk": return { icon: IconUserCheck, color: "indigo", title: t("{actor} size {n} bulgu atadı", { actor: p.actor, n: p.count }), detail: p.note };
    case "shared": return { icon: IconShare, color: "teal", title: t("{actor} bir bulgu paylaştı", { actor: p.actor }), detail: f + (p.message ? ` · “${p.message}”` : "") };
    case "approval_requested": return { icon: IconChecks, color: "orange", title: t("{actor} onayınızı istiyor: {status}", { actor: p.actor, status: STATUS_LABEL[p.status] ?? p.status }), detail: f + (p.reason ? ` · ${p.reason}` : "") };
    case "approval_decided": return p.approved
      ? { icon: IconCheck, color: "green", title: t("{actor} talebinizi onayladı: {status}", { actor: p.actor, status: STATUS_LABEL[p.status] ?? p.status }), detail: f + (p.note ? ` · ${p.note}` : "") }
      : { icon: IconX, color: "red", title: t("{actor} talebinizi reddetti: {status}", { actor: p.actor, status: STATUS_LABEL[p.status] ?? p.status }), detail: f + (p.note ? ` · ${p.note}` : "") };
    case "mentioned": return { icon: IconMessageCircle, color: "grape", title: t("{actor} sizi bir yorumda andı", { actor: p.actor }), detail: `${f} · ${p.text ?? ""}` };
    case "dispute_opened": return { icon: IconGavel, color: "grape", title: t("{actor} sizi bir tartışmaya ekledi: {title}", { actor: p.actor, title: p.title }), detail: f };
    case "dispute_message": return { icon: IconGavel, color: "grape", title: t("{actor} tartışmaya yazdı: {title}", { actor: p.actor, title: p.title }), detail: p.text };
    case "dispute_escalated": return { icon: IconGavel, color: "orange", title: t("{actor} bir tartışmayı kararınıza taşıdı: {title}", { actor: p.actor, title: p.title }), detail: f + (p.note ? ` · ${p.note}` : "") };
    case "dispute_delegated": return { icon: IconGavel, color: "orange", title: t("{actor} bir tartışmanın kararını size devretti: {title}", { actor: p.actor, title: p.title }), detail: f + (p.note ? ` · ${p.note}` : "") };
    case "dispute_resolved": return { icon: IconGavel, color: "green", title: t("Tartışma sonuçlandı: {title}", { title: p.title }), detail: (p.status ? `${STATUS_LABEL[p.status]} · ` : "") + (p.resolution ?? "") };
    case "waf_assist": return { icon: IconBell, color: "orange", title: t("Tarama WAF'a takıldı: {target}", { target: p.target }), detail: t("Tarayıcı yardımcısını başlatarak taramayı tamamlayın.") };
    case "reminder": return { icon: IconAlarm, color: "orange", title: t("Hatırlatıcı"), detail: p.text };
    case "message_nudge": return { icon: IconMail, color: "indigo", title: t("{actor} mesajını okumanızı hatırlatıyor", { actor: p.actor }), detail: p.subject };
    default: return { icon: IconBell, color: "gray", title: n.kind };
  }
}

export function InboxRow({ n, onOpen }: { n: InboxItem; onOpen: (n: InboxItem) => void }) {
  const x = inboxText(n);
  return (
    <UnstyledButton onClick={() => onOpen(n)} p="xs" style={{ borderRadius: 8, background: n.read ? undefined : "var(--mantine-color-indigo-light)", width: "100%" }}>
      <Group wrap="nowrap" align="flex-start" gap="sm">
        <ThemeIcon variant="light" color={x.color} radius="xl" size={30}><x.icon size={16} /></ThemeIcon>
        <div style={{ flex: 1, minWidth: 0 }}>
          <Text size="sm" fw={n.read ? 400 : 600}>{x.title}</Text>
          {x.detail && <Text size="xs" c="dimmed" lineClamp={2}>{x.detail}</Text>}
          <Text size="xs" c="dimmed">{fmtDate(n.created_at)}</Text>
        </div>
      </Group>
    </UnstyledButton>
  );
}

export function InboxBell() {
  const qc = useQueryClient();
  const nav = useNavigate();
  const [open, setOpen] = useState(false);
  const count = useQuery<{ unread: number }>({ queryKey: ["inbox-count"], queryFn: () => api("/inbox/count"), refetchInterval: 30000 });
  const items = useQuery<InboxItem[]>({ queryKey: ["inbox", "recent"], queryFn: () => api("/inbox?limit=8"), enabled: open });
  const unread = count.data?.unread ?? 0;
  async function openItem(n: InboxItem) {
    if (!n.read) await api("/inbox/read", { body: { ids: [n.id] } }).catch(() => undefined);
    qc.invalidateQueries({ queryKey: ["inbox-count"] });
    qc.invalidateQueries({ queryKey: ["inbox"] });
    setOpen(false);
    if (n.link) nav(n.link);
  }
  async function readAll() {
    await api("/inbox/read", { body: { all: true } }).catch(() => undefined);
    qc.invalidateQueries({ queryKey: ["inbox-count"] });
    qc.invalidateQueries({ queryKey: ["inbox"] });
  }
  return (
    <Popover opened={open} onChange={setOpen} position="bottom-end" width={380} shadow="md">
      <Popover.Target>
        <Indicator label={unread > 99 ? "99+" : unread} size={16} disabled={!unread} color="red" offset={4}>
          <ActionIcon variant="subtle" color="gray" size="lg" onClick={() => setOpen((o) => !o)} aria-label={t("Bildirimler")}><IconBell size={20} /></ActionIcon>
        </Indicator>
      </Popover.Target>
      <Popover.Dropdown p="xs">
        <Group justify="space-between" px={4} mb={4}>
          <Text fw={600} size="sm">{t("Bildirimler")}</Text>
          {unread > 0 && <Button size="compact-xs" variant="subtle" onClick={readAll}>{t("Tümünü okundu say")}</Button>}
        </Group>
        <ScrollArea.Autosize mah={380}>
          <Stack gap={4}>
            {(items.data ?? []).map((n) => <InboxRow key={n.id} n={n} onOpen={openItem} />)}
            {items.data?.length === 0 && <Text size="sm" c="dimmed" ta="center" py="md">{t("Bildirim yok")}</Text>}
          </Stack>
        </ScrollArea.Autosize>
        <Divider my={6} />
        <Button fullWidth variant="subtle" size="xs" onClick={() => { setOpen(false); nav("/inbox"); }}>{t("Tümünü gör")}</Button>
      </Popover.Dropdown>
    </Popover>
  );
}

export function PendingBadge() {
  const q = useQuery<{ pending: number }>({ queryKey: ["approvals-count"], queryFn: () => api("/approvals/count"), refetchInterval: 60000 });
  return q.data?.pending ? <Badge size="xs" color="orange" variant="filled" circle>{q.data.pending}</Badge> : null;
}
