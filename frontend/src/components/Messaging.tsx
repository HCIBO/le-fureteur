import { ActionIcon, Button, Group, Indicator, Modal, MultiSelect, SegmentedControl, Select, Stack, Text, Textarea, TextInput, Tooltip } from "@mantine/core";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { IconAlarm, IconCheck, IconChecks, IconMail } from "@tabler/icons-react";
import { useNavigate } from "react-router-dom";
import { api, fmtDate } from "../api";
import { t } from "../i18n";
import { fail, ok } from "./ui";

export function Ticks({ state, receipts }: { state?: string | null; receipts?: any[] }) {
  if (!state) return null;
  const icon = state === "sent" ? <IconCheck size={15} color="var(--mantine-color-gray-6)" />
    : <IconChecks size={15} color={state === "read" ? "var(--mantine-color-blue-6)" : "var(--mantine-color-gray-6)"} />;
  const label = { sent: t("Gönderildi"), delivered: t("İletildi"), read: t("Okundu") }[state];
  if (!receipts?.length) return <Tooltip label={label}>{icon}</Tooltip>;
  return (
    <Tooltip multiline w={260} label={
      <Stack gap={2}>
        {receipts.map((r: any) => (
          <Text key={r.user.id} size="xs">{r.user.name || r.user.email}: {r.read_at ? `${t("okundu")} ${fmtDate(r.read_at)}` : r.delivered_at ? `${t("iletildi")} ${fmtDate(r.delivered_at)}` : t("henüz iletilmedi")}</Text>
        ))}
      </Stack>}>
      {icon}
    </Tooltip>
  );
}

export function MessagesBell() {
  const nav = useNavigate();
  const q = useQuery<{ unread: number }>({ queryKey: ["messages-count"], queryFn: () => api("/messages/count"), refetchInterval: 30000 });
  return (
    <Tooltip label={t("Mesajlar")}>
      <Indicator label={q.data?.unread} size={16} disabled={!q.data?.unread} color="indigo" offset={4}>
        <ActionIcon variant="subtle" size="lg" onClick={() => nav("/messages")} aria-label={t("Mesajlar")}><IconMail size={20} /></ActionIcon>
      </Indicator>
    </Tooltip>
  );
}

export function ComposeModal({ opened, onClose, teamId, userIds, findingId, subject }: { opened: boolean; onClose: () => void; teamId?: number; userIds?: number[]; findingId?: number; subject?: string }) {
  const qc = useQueryClient();
  const nav = useNavigate();
  const rec = useQuery<any>({ queryKey: ["msg-recipients"], queryFn: () => api("/messages/recipients"), enabled: opened });
  const [mode, setMode] = useState<"people" | "team">(teamId ? "team" : "people");
  const [to, setTo] = useState<string[]>([]);
  const [team, setTeam] = useState<string | null>(null);
  const [form, setForm] = useState({ subject: "", body: "" });
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (!opened) return;
    setMode(teamId ? "team" : "people"); setTeam(teamId ? String(teamId) : null);
    setTo((userIds ?? []).map(String)); setForm({ subject: subject ?? "", body: "" });
  }, [opened, teamId, userIds, subject]);
  async function send() {
    setBusy(true);
    try {
      const r = await api("/messages/threads", { body: { ...form, to: mode === "people" ? to.map(Number) : [], team_id: mode === "team" ? Number(team) : null, finding_id: findingId ?? null } });
      ok(t("Mesaj gönderildi")); onClose(); qc.invalidateQueries({ queryKey: ["threads"] }); nav(`/messages/${r.id}`);
    } catch (e) { fail(e); } finally { setBusy(false); }
  }
  const valid = form.subject.trim() && form.body.trim() && (mode === "people" ? to.length > 0 : !!team);
  return (
    <Modal opened={opened} onClose={onClose} title={t("Yeni mesaj")} size="lg">
      <Stack>
        <SegmentedControl value={mode} onChange={(v) => setMode(v as any)} data={[{ value: "people", label: t("Kişilere") }, { value: "team", label: t("Takıma") }]} />
        {mode === "people"
          ? <MultiSelect label={t("Alıcılar")} searchable data={(rec.data?.users ?? []).map((u: any) => ({ value: String(u.id), label: u.name ? `${u.name} — ${u.email}` : u.email }))} value={to} onChange={setTo} />
          : <Select label={t("Takım")} data={(rec.data?.teams ?? []).map((x: any) => ({ value: String(x.id), label: `${x.name} (${t("{n} kişi", { n: x.members })})` }))} value={team} onChange={setTeam} />}
        <TextInput label={t("Konu")} value={form.subject} onChange={(e) => setForm({ ...form, subject: e.currentTarget.value })} maxLength={200} />
        <Textarea label={t("Mesaj")} value={form.body} onChange={(e) => setForm({ ...form, body: e.currentTarget.value })} autosize minRows={5} maxLength={10000} />
        {findingId && <Text size="xs" c="dimmed">{t("Mesaj bu bulguya bağlanır; alıcıların bulguyu görebilmesi gerekir.")}</Text>}
        <Group justify="flex-end"><Button onClick={send} loading={busy} disabled={!valid}>{t("Gönder")}</Button></Group>
      </Stack>
    </Modal>
  );
}

function localInput(d: Date) {
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}

export function presets(): { label: string; at: Date }[] {
  const now = new Date();
  const hour = new Date(now.getTime() + 3600e3);
  const tomorrow = new Date(now); tomorrow.setDate(now.getDate() + 1); tomorrow.setHours(9, 0, 0, 0);
  const monday = new Date(now); monday.setDate(now.getDate() + ((8 - now.getDay()) % 7 || 7)); monday.setHours(9, 0, 0, 0);
  return [{ label: t("1 saat sonra"), at: hour }, { label: t("Yarın 09:00"), at: tomorrow }, { label: t("Pazartesi 09:00"), at: monday }];
}

export function ReminderModal({ opened, onClose, link, text }: { opened: boolean; onClose: () => void; link?: string; text?: string }) {
  const qc = useQueryClient();
  const [body, setBody] = useState("");
  const [at, setAt] = useState("");
  useEffect(() => { if (opened) { setBody(text ?? ""); setAt(localInput(presets()[1].at)); } }, [opened, text]);
  async function save() {
    try {
      await api("/reminders", { body: { text: body, due_at: new Date(at).toISOString(), link: link ?? "" } });
      ok(t("Hatırlatıcı kuruldu")); onClose(); qc.invalidateQueries({ queryKey: ["reminders"] });
    } catch (e) { fail(e); }
  }
  return (
    <Modal opened={opened} onClose={onClose} title={<Group gap="xs"><IconAlarm size={18} /><Text fw={600}>{t("Hatırlatıcı kur")}</Text></Group>}>
      <Stack>
        <TextInput label={t("Neyi hatırlatalım?")} value={body} onChange={(e) => setBody(e.currentTarget.value)} maxLength={500} />
        <Group gap="xs">{presets().map((p) => <Button key={p.label} size="xs" variant={localInput(p.at) === at ? "filled" : "default"} onClick={() => setAt(localInput(p.at))}>{p.label}</Button>)}</Group>
        <TextInput type="datetime-local" label={t("Zaman")} value={at} onChange={(e) => setAt(e.currentTarget.value)} />
        <Text size="xs" c="dimmed">{t("Zamanı geldiğinde bildirim kutunuza düşer.")}</Text>
        <Group justify="flex-end"><Button onClick={save} disabled={!body.trim() || !at}>{t("Kaydet")}</Button></Group>
      </Stack>
    </Modal>
  );
}
