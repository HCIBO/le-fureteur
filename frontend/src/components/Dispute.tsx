import { Anchor, Avatar, Badge, Button, Card, Group, Modal, MultiSelect, Paper, Select, Stack, Text, Textarea, TextInput, ThemeIcon } from "@mantine/core";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { IconArrowUpRight, IconCheck, IconGavel, IconHandStop, IconMessages, IconPlus, IconSend, IconUserShare } from "@tabler/icons-react";
import { Link } from "react-router-dom";
import { api, fmtDate, STATUS_LABEL } from "../api";
import { t } from "../i18n";
import { fail, ok, SevBadge } from "./ui";

const STATE: Record<string, { color: string; label: string }> = {
  open: { color: "blue", label: t("Tartışılıyor") }, escalated: { color: "orange", label: t("Yöneticide") }, resolved: { color: "green", label: t("Sonuçlandı") },
};
export const DisputeState = ({ s }: { s: string }) => <Badge variant="light" color={STATE[s]?.color}>{STATE[s]?.label ?? s}</Badge>;

const name = (u: any) => (u ? u.name || u.email : "—");

function People({ title, users, color }: { title: string; users: any[]; color: string }) {
  return (
    <div>
      <Text size="xs" c="dimmed" tt="uppercase" fw={600} mb={4}>{title}</Text>
      <Group gap={6}>{users.length ? users.map((u) => <Badge key={u.id} variant="light" color={color} tt="none" leftSection={<Avatar size={14} radius="xl">{u.email[0].toUpperCase()}</Avatar>}>{name(u)}</Badge>) : <Text size="xs" c="dimmed">—</Text>}</Group>
    </div>
  );
}

export function DisputeRoom({ id, me }: { id: number; me?: any }) {
  const qc = useQueryClient();
  const d = useQuery<any>({ queryKey: ["dispute", id], queryFn: () => api(`/disputes/${id}`), refetchInterval: 15000 });
  const people = useQuery<any[]>({ queryKey: ["directory", "finding", d.data?.finding_id], queryFn: () => api(`/directory?finding_id=${d.data.finding_id}`), enabled: !!d.data });
  const [text, setText] = useState("");
  const [modal, setModal] = useState<null | "escalate" | "delegate" | "resolve" | "close">(null);
  const [note, setNote] = useState("");
  const [who, setWho] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  if (!d.data) return null;
  const x = d.data;
  const refresh = () => { qc.invalidateQueries({ queryKey: ["dispute", id] }); qc.invalidateQueries({ queryKey: ["disputes"] }); qc.invalidateQueries({ queryKey: ["finding", x.finding_id] }); };
  async function send() {
    try { await api(`/disputes/${id}/messages`, { body: { text } }); setText(""); refresh(); } catch (e) { fail(e); }
  }
  async function act() {
    try {
      if (modal === "escalate") await api(`/disputes/${id}/escalate`, { body: { note } });
      if (modal === "delegate") await api(`/disputes/${id}/delegate`, { body: { user_id: Number(who), note } });
      if (modal === "resolve" || modal === "close") await api(`/disputes/${id}/resolve`, { body: { resolution: note, status: modal === "resolve" ? status : null } });
      ok(t("Kaydedildi")); setModal(null); setNote(""); setWho(null); setStatus(null); refresh();
    } catch (e) { fail(e); }
  }
  const sysText = (m: any) => {
    const e = m.meta?.event;
    if (e === "escalated") return t("{who} tartışmayı yöneticiye taşıdı", { who: name(m.user) }) + (m.meta.note ? ` — “${m.meta.note}”` : "");
    if (e === "delegated") return t("{who} kararı {to} kişisine devretti (vekâlet)", { who: name(m.user), to: m.meta.to }) + (m.meta.note ? ` — “${m.meta.note}”` : "");
    if (e === "resolved") return t("{who} tartışmayı sonuçlandırdı", { who: name(m.user) }) + (m.meta.status ? ` → ${STATUS_LABEL[m.meta.status]}` : "");
    return m.text;
  };
  const isOpener = me && x.opened_by?.id === me.id;
  return (
    <Stack>
      <Card withBorder>
        <Group justify="space-between" align="flex-start" wrap="nowrap">
          <div>
            <Group gap="xs"><ThemeIcon variant="light" color="grape"><IconGavel size={16} /></ThemeIcon><Text fw={700} size="lg">{x.title}</Text><DisputeState s={x.status} /></Group>
            {x.finding && <Group gap={6} mt={6}><SevBadge sev={x.finding.severity} /><Anchor component={Link} to={`/findings?open=${x.finding_id}`} size="sm">{x.finding.cves?.[0] ?? x.finding.vuln_id} — {x.finding.component} {x.finding.version}</Anchor></Group>}
          </div>
          <Text size="xs" c="dimmed">{fmtDate(x.created_at)}</Text>
        </Group>
        <Group mt="md" gap="xl" align="flex-start">
          <People title={t("Açan")} users={x.opened_by ? [x.opened_by] : []} color="indigo" />
          <People title={t("Katılımcılar")} users={x.participants} color="gray" />
          {x.status !== "open" && <People title={t("Karar veren")} users={x.delegate ? [x.delegate] : x.judges} color="orange" />}
        </Group>
        {x.status === "resolved" && (
          <Paper mt="md" p="sm" radius="md" bg="var(--mantine-color-green-light)">
            <Group gap={6} mb={4}><IconCheck size={16} /><Text fw={600} size="sm">{t("Karar")}{x.resolved_status ? `: ${STATUS_LABEL[x.resolved_status]}` : ""}</Text></Group>
            <Text size="sm" style={{ whiteSpace: "pre-wrap" }}>{x.resolution}</Text>
            <Text size="xs" c="dimmed" mt={4}>{name(x.resolved_by)} · {fmtDate(x.resolved_at)}</Text>
          </Paper>
        )}
      </Card>

      <Stack gap="sm">
        {(x.messages ?? []).map((m: any) => m.kind === "system" ? (
          <Group key={m.id} justify="center"><Paper px="md" py={6} radius="xl" bg="var(--mantine-color-default-hover)" maw="90%"><Text size="xs" c="dimmed" ta="center">{sysText(m)} · {fmtDate(m.at)}</Text></Paper></Group>
        ) : (
          <Group key={m.id} align="flex-start" wrap="nowrap" justify={me && m.user?.id === me.id ? "flex-end" : "flex-start"}>
            {!(me && m.user?.id === me.id) && <Avatar radius="xl" color="indigo">{m.user?.email?.[0]?.toUpperCase()}</Avatar>}
            <Paper p="sm" radius="lg" maw="80%" bg={me && m.user?.id === me.id ? "var(--mantine-color-indigo-light)" : "var(--mantine-color-default-hover)"}>
              <Group gap={6} mb={2}><Text size="xs" fw={700}>{name(m.user)}</Text><Text size="xs" c="dimmed">{fmtDate(m.at)}</Text></Group>
              <Text size="sm" style={{ whiteSpace: "pre-wrap" }}>{m.text}</Text>
            </Paper>
          </Group>
        ))}
      </Stack>

      {x.status !== "resolved" && (
        <Card withBorder padding="sm">
          <Textarea placeholder={t("Görüşünüzü yazın…")} value={text} onChange={(e) => setText(e.currentTarget.value)} autosize minRows={2} />
          <Group justify="space-between" mt="xs" wrap="wrap" gap="xs">
            <Group gap="xs" wrap="wrap">
              {x.status === "open" && <Button size="xs" variant="light" color="orange" leftSection={<IconArrowUpRight size={14} />} onClick={() => setModal("escalate")}>{t("Yöneticiye taşı")}</Button>}
              {x.status === "escalated" && x.can_judge && <Button size="xs" variant="light" leftSection={<IconUserShare size={14} />} onClick={() => setModal("delegate")}>{t("Vekâlet ver")}</Button>}
              {x.status === "escalated" && x.can_judge && <Button size="xs" color="green" leftSection={<IconGavel size={14} />} onClick={() => setModal("resolve")}>{t("Karar ver")}</Button>}
              {x.status === "open" && (isOpener || x.can_judge) && <Button size="xs" variant="default" leftSection={<IconHandStop size={14} />} onClick={() => setModal("close")}>{t("Uzlaşmayla kapat")}</Button>}
            </Group>
            <Button size="xs" leftSection={<IconSend size={14} />} onClick={send} disabled={!text.trim()}>{t("Gönder")}</Button>
          </Group>
        </Card>
      )}

      <Modal opened={modal !== null} onClose={() => setModal(null)} title={{ escalate: t("Yöneticiye taşı"), delegate: t("Vekâlet ver"), resolve: t("Karar ver"), close: t("Uzlaşmayla kapat") }[modal ?? "escalate"]}>
        <Stack>
          {modal === "escalate" && <Text size="sm">{t("Tartışma, açan kişinin takım yöneticisine / sorumlusuna karar için gönderilir. Karar verilene kadar bulgunun durumu değişmez.")}</Text>}
          {modal === "delegate" && <Select label={t("Kime")} searchable data={(people.data ?? []).filter((u) => u.id !== x.opened_by?.id).map((u) => ({ value: String(u.id), label: u.name ? `${u.name} — ${u.email}` : u.email }))} value={who} onChange={setWho} />}
          {modal === "resolve" && <Select label={t("Bulgunun yeni durumu (isteğe bağlı)")} clearable data={Object.entries(STATUS_LABEL).filter(([k]) => k !== "fixed").map(([value, label]) => ({ value, label }))} value={status} onChange={setStatus} />}
          <Textarea label={modal === "resolve" || modal === "close" ? t("Karar / gerekçe") : t("Not (isteğe bağlı)")} value={note} onChange={(e) => setNote(e.currentTarget.value)} autosize minRows={3} />
          <Group justify="flex-end"><Button onClick={act} disabled={(modal === "delegate" && !who) || ((modal === "resolve" || modal === "close") && !note.trim())}>{t("Onayla")}</Button></Group>
        </Stack>
      </Modal>
    </Stack>
  );
}

export function DisputeList({ findingId }: { findingId: number }) {
  const qc = useQueryClient();
  const me = useQuery<any>({ queryKey: ["me"], queryFn: () => api("/auth/me") });
  const list = useQuery<any[]>({ queryKey: ["disputes", "finding", findingId], queryFn: () => api(`/findings/${findingId}/disputes`) });
  const people = useQuery<any[]>({ queryKey: ["directory", "finding", findingId], queryFn: () => api(`/directory?finding_id=${findingId}`) });
  const [open, setOpen] = useState(false);
  const [sel, setSel] = useState<number | null>(null);
  const [form, setForm] = useState({ title: "", message: "", participants: [] as string[] });
  async function create() {
    try {
      const d = await api(`/findings/${findingId}/disputes`, { body: { ...form, participants: form.participants.map(Number) } });
      setOpen(false); setForm({ title: "", message: "", participants: [] }); setSel(d.id);
      qc.invalidateQueries({ queryKey: ["disputes"] }); qc.invalidateQueries({ queryKey: ["finding", findingId] });
    } catch (e) { fail(e); }
  }
  if (sel) return <Stack><Anchor size="sm" onClick={() => setSel(null)}>← {t("Tartışmalar")}</Anchor><DisputeRoom id={sel} me={me.data} /></Stack>;
  return (
    <Stack>
      <Card withBorder padding="sm" bg="var(--mantine-color-grape-light)">
        <Group justify="space-between" wrap="wrap" gap="sm">
          <Text size="sm" style={{ flex: "1 1 240px", minWidth: 0 }}>{t("Bu bulgu hakkında görüş ayrılığı mı var? Tartışma açın, ilgili kişileri ekleyin; uzlaşamazsanız yöneticiye taşıyın.")}</Text>
          <Button size="xs" style={{ flexShrink: 0 }} leftSection={<IconPlus size={14} />} onClick={() => setOpen(true)}>{t("Tartışma aç")}</Button>
        </Group>
      </Card>
      {(list.data ?? []).map((d) => (
        <Card key={d.id} withBorder padding="sm" style={{ cursor: "pointer" }} onClick={() => setSel(d.id)}>
          <Group justify="space-between" wrap="nowrap">
            <div><Text fw={600} size="sm">{d.title}</Text><Text size="xs" c="dimmed">{name(d.opened_by)} · {fmtDate(d.created_at)}</Text></div>
            <Group gap="xs" wrap="nowrap"><Badge variant="light" leftSection={<IconMessages size={12} />}>{d.messages_count}</Badge><DisputeState s={d.status} /></Group>
          </Group>
        </Card>
      ))}
      {list.data?.length === 0 && <Text size="sm" c="dimmed" ta="center">{t("Bu bulgu için tartışma yok")}</Text>}
      <Modal opened={open} onClose={() => setOpen(false)} title={t("Tartışma aç")}>
        <Stack>
          <TextInput label={t("Konu")} placeholder={t("ör. Bu açık bizim kullanımımızda tetiklenebilir mi?")} value={form.title} onChange={(e) => setForm({ ...form, title: e.currentTarget.value })} maxLength={200} />
          <MultiSelect label={t("Katılımcılar")} searchable data={(people.data ?? []).filter((u) => u.id !== me.data?.id).map((u) => ({ value: String(u.id), label: u.name ? `${u.name} — ${u.email}` : u.email }))} value={form.participants} onChange={(v) => setForm({ ...form, participants: v })} />
          <Textarea label={t("Görüşünüz")} value={form.message} onChange={(e) => setForm({ ...form, message: e.currentTarget.value })} autosize minRows={3} />
          <Group justify="flex-end"><Button onClick={create} disabled={form.title.trim().length < 3 || !form.message.trim()}>{t("Aç")}</Button></Group>
        </Stack>
      </Modal>
    </Stack>
  );
}
