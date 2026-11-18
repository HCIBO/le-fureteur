import { Anchor, Avatar, Badge, Button, Card, Grid, Group, Menu, Paper, ScrollArea, Stack, Tabs, Text, Textarea, TextInput, ThemeIcon, UnstyledButton } from "@mantine/core";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { IconAlarm, IconBellRinging, IconCheck, IconClockPause, IconInbox, IconMailOpened, IconPencil, IconSearch, IconSend, IconTrash, IconUsersGroup } from "@tabler/icons-react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { api, fmtDate, fmtDay } from "../api";
import { t } from "../i18n";
import { fail, ok, PageHeader } from "../components/ui";
import { PageIntro } from "../components/PageIntro";
import { ComposeModal, presets, ReminderModal, Ticks } from "../components/Messaging";

const who = (u: any) => (u ? u.name || u.email : t("Silinmiş kullanıcı"));

function Empty({ icon: I, text }: { icon: any; text: string }) {
  return <Stack align="center" gap={6} py={40}><ThemeIcon size={48} radius="xl" variant="light"><I size={24} /></ThemeIcon><Text c="dimmed" size="sm" ta="center">{text}</Text></Stack>;
}

function ThreadList({ box, sel, q }: { box: string; sel?: number; q: string }) {
  const nav = useNavigate();
  const list = useQuery<any[]>({ queryKey: ["threads", box, q], queryFn: () => api(`/messages/threads?box=${box}&q=${encodeURIComponent(q)}`), refetchInterval: 30000 });
  if (list.data?.length === 0) return <Empty icon={IconInbox} text={box === "unread" ? t("Okunmamış mesaj yok") : t("Henüz mesaj yok")} />;
  return (
    <Stack gap={4}>
      {(list.data ?? []).map((x) => {
        const others = x.participants.filter((p: any) => p.id !== x.created_by?.id || x.participants.length === 1);
        return (
          <UnstyledButton key={x.id} onClick={() => nav(`/messages/${x.id}`)} p="sm"
            style={{ borderRadius: 8, background: sel === x.id ? "var(--mantine-color-indigo-light)" : x.unread ? "var(--mantine-color-default-hover)" : undefined }}>
            <Group wrap="nowrap" align="flex-start" gap="sm">
              {x.team ? <ThemeIcon radius="xl" size={36} variant="light" color="teal"><IconUsersGroup size={18} /></ThemeIcon>
                : <Avatar radius="xl" color="indigo">{(others[0]?.email ?? "?")[0].toUpperCase()}</Avatar>}
              <div style={{ flex: 1, minWidth: 0 }}>
                <Group justify="space-between" wrap="nowrap" gap={4}>
                  <Text size="sm" fw={x.unread ? 700 : 500} truncate>{x.team ? x.team.name : others.map(who).join(", ")}</Text>
                  <Text size="xs" c="dimmed" style={{ whiteSpace: "nowrap" }}>{fmtDay(x.last_at)}</Text>
                </Group>
                <Text size="sm" fw={x.unread ? 600 : 400} truncate>{x.subject}</Text>
                <Group gap={4} wrap="nowrap">
                  {x.last?.state && <Ticks state={x.last.state} />}
                  <Text size="xs" c="dimmed" truncate style={{ flex: 1 }}>{x.last?.sender ? `${who(x.last.sender)}: ` : ""}{x.last?.body}</Text>
                  {x.unread > 0 && <Badge size="xs" circle color="indigo">{x.unread}</Badge>}
                </Group>
              </div>
            </Group>
          </UnstyledButton>
        );
      })}
    </Stack>
  );
}

function Conversation({ id }: { id: number }) {
  const qc = useQueryClient();
  const th = useQuery<any>({ queryKey: ["thread", id], queryFn: () => api(`/messages/threads/${id}`), refetchInterval: 15000 });
  const [text, setText] = useState("");
  const [remind, setRemind] = useState(false);
  const end = useRef<HTMLDivElement>(null);
  useEffect(() => { qc.invalidateQueries({ queryKey: ["messages-count"] }); qc.invalidateQueries({ queryKey: ["threads"] }); }, [th.data?.messages?.length, qc]);
  useEffect(() => { end.current?.scrollIntoView({ block: "end" }); }, [th.data?.messages?.length]);
  if (!th.data) return null;
  const x = th.data;
  async function send() {
    try { await api(`/messages/threads/${id}/reply`, { body: { body: text } }); setText(""); qc.invalidateQueries({ queryKey: ["thread", id] }); } catch (e) { fail(e); }
  }
  async function nudge() {
    try { const r = await api(`/messages/threads/${id}/nudge`, { method: "POST" }); ok(t("{n} kişiye hatırlatma gönderildi", { n: r.nudged })); } catch (e) { fail(e); }
  }
  const lastMine = [...x.messages].reverse().find((m: any) => m.mine);
  return (
    <Card withBorder p={0} h="100%" style={{ display: "flex", flexDirection: "column" }}>
      <Group justify="space-between" p="md" style={{ borderBottom: "1px solid var(--mantine-color-default-border)" }} wrap="nowrap">
        <div style={{ minWidth: 0 }}>
          <Text fw={700} truncate>{x.subject}</Text>
          <Group gap={6}>
            {x.team && <Badge size="sm" variant="light" color="teal" leftSection={<IconUsersGroup size={12} />}>{x.team.name}</Badge>}
            <Text size="xs" c="dimmed" truncate>{x.participants.map(who).join(", ")}</Text>
          </Group>
          {x.finding_id && <Anchor component={Link} to={`/findings?open=${x.finding_id}`} size="xs">{t("İlgili bulguyu aç")} →</Anchor>}
        </div>
        <Group gap="xs" wrap="nowrap">
          {lastMine && lastMine.state !== "read" && <Button size="xs" variant="light" color="orange" leftSection={<IconBellRinging size={14} />} onClick={nudge}>{t("Okumayanlara hatırlat")}</Button>}
          <Button size="xs" variant="default" leftSection={<IconAlarm size={14} />} onClick={() => setRemind(true)}>{t("Bana hatırlat")}</Button>
        </Group>
      </Group>
      <ScrollArea style={{ flex: 1 }} p="md" h={480}>
        <Stack gap="sm">
          {x.messages.map((m: any) => (
            <Group key={m.id} justify={m.mine ? "flex-end" : "flex-start"} align="flex-end" wrap="nowrap" gap="xs">
              {!m.mine && <Avatar size="sm" radius="xl" color="indigo">{(m.sender?.email ?? "?")[0].toUpperCase()}</Avatar>}
              <Paper p="sm" radius="lg" maw="75%" bg={m.mine ? "var(--mantine-color-indigo-light)" : "var(--mantine-color-default-hover)"}>
                {!m.mine && <Text size="xs" fw={700} mb={2}>{who(m.sender)}</Text>}
                <Text size="sm" style={{ whiteSpace: "pre-wrap", wordBreak: "break-word" }}>{m.body}</Text>
                <Group gap={4} justify="flex-end" mt={2}><Text size="xs" c="dimmed">{fmtDate(m.at)}</Text>{m.mine && <Ticks state={m.state} receipts={m.receipts} />}</Group>
              </Paper>
            </Group>
          ))}
          <div ref={end} />
        </Stack>
      </ScrollArea>
      <Group p="sm" gap="xs" align="flex-end" wrap="nowrap" style={{ borderTop: "1px solid var(--mantine-color-default-border)" }}>
        <Textarea style={{ flex: 1 }} placeholder={t("Yanıt yazın… (Ctrl+Enter ile gönder)")} value={text} onChange={(e) => setText(e.currentTarget.value)} autosize minRows={1} maxRows={6}
          onKeyDown={(e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey) && text.trim()) send(); }} />
        <Button leftSection={<IconSend size={14} />} onClick={send} disabled={!text.trim()}>{t("Gönder")}</Button>
      </Group>
      <ReminderModal opened={remind} onClose={() => setRemind(false)} link={`/messages/${id}`} text={x.subject} />
    </Card>
  );
}

function Reminders() {
  const qc = useQueryClient();
  const nav = useNavigate();
  const q = useQuery<any[]>({ queryKey: ["reminders"], queryFn: () => api("/reminders") });
  const [open, setOpen] = useState(false);
  const refresh = () => qc.invalidateQueries({ queryKey: ["reminders"] });
  async function patch(id: number, body: any) { try { await api(`/reminders/${id}`, { method: "PATCH", body }); refresh(); } catch (e) { fail(e); } }
  async function del(id: number) { try { await api(`/reminders/${id}`, { method: "DELETE" }); refresh(); } catch (e) { fail(e); } }
  const rows = q.data ?? [];
  const now = Date.now();
  return (
    <Card withBorder>
      <Group justify="space-between" mb="md">
        <Text size="sm" c="dimmed">{t("Kendinize not bırakın; zamanı geldiğinde bildirim kutunuza düşer. Bulgu ve mesajlardan da hatırlatıcı kurabilirsiniz.")}</Text>
        <Button size="xs" leftSection={<IconAlarm size={14} />} onClick={() => setOpen(true)}>{t("Hatırlatıcı kur")}</Button>
      </Group>
      {rows.length === 0 ? <Empty icon={IconAlarm} text={t("Hatırlatıcınız yok")} /> : (
        <Stack gap="xs">
          {rows.map((r) => {
            const due = new Date(r.due_at).getTime() <= now && !r.done_at;
            return (
              <Paper key={r.id} withBorder p="sm" radius="md" style={{ opacity: r.done_at ? 0.55 : 1, borderLeft: `3px solid var(--mantine-color-${r.done_at ? "green" : due ? "orange" : "indigo"}-6)` }}>
                <Group justify="space-between" wrap="nowrap">
                  <div style={{ minWidth: 0 }}>
                    <Text size="sm" fw={600} td={r.done_at ? "line-through" : undefined}>{r.text}</Text>
                    <Group gap={6}>
                      <Badge size="xs" variant="light" color={r.done_at ? "green" : due ? "orange" : "indigo"}>{r.done_at ? t("Tamamlandı") : due ? t("Zamanı geldi") : t("Bekliyor")}</Badge>
                      <Text size="xs" c="dimmed">{fmtDate(r.due_at)}</Text>
                      {r.link && <Anchor size="xs" onClick={() => nav(r.link)}>{t("Aç")} →</Anchor>}
                    </Group>
                  </div>
                  <Group gap={4} wrap="nowrap">
                    {!r.done_at && <Button size="xs" variant="light" color="green" leftSection={<IconCheck size={14} />} onClick={() => patch(r.id, { done: true })}>{t("Tamam")}</Button>}
                    {!r.done_at && (
                      <Menu position="bottom-end">
                        <Menu.Target><Button size="xs" variant="default" leftSection={<IconClockPause size={14} />}>{t("Ertele")}</Button></Menu.Target>
                        <Menu.Dropdown>{presets().map((p) => <Menu.Item key={p.label} onClick={() => patch(r.id, { due_at: p.at.toISOString() })}>{p.label}</Menu.Item>)}</Menu.Dropdown>
                      </Menu>
                    )}
                    <Button size="xs" variant="subtle" color="red" onClick={() => del(r.id)} aria-label={t("Sil")}><IconTrash size={14} /></Button>
                  </Group>
                </Group>
              </Paper>
            );
          })}
        </Stack>
      )}
      <ReminderModal opened={open} onClose={() => setOpen(false)} />
    </Card>
  );
}

export default function Messages() {
  const { id } = useParams();
  const [sp, setSp] = useSearchParams();
  const tab = sp.get("tab") ?? "inbox";
  const [compose, setCompose] = useState(false);
  const [q, setQ] = useState("");
  const setTab = (v: string | null) => { const n = new URLSearchParams(sp); n.set("tab", v ?? "inbox"); setSp(n, { replace: true }); };
  const teamParam = sp.get("team");
  useEffect(() => { if (teamParam) setCompose(true); }, [teamParam]);
  return (
    <>
      <PageHeader title={t("Mesajlar")} sub={t("Ekip içi yazışmalar ve hatırlatıcılar")}
        right={<Button leftSection={<IconPencil size={16} />} onClick={() => setCompose(true)}>{t("Yeni mesaj")}</Button>} />
      <PageIntro id="messages" guide="collaboration"
        text={t("Kişilere veya bir takımın tamamına mesaj gönderin. Her mesajın yanında durum işareti görünür: tek tik gönderildi, çift gri tik alıcıya iletildi, çift mavi tik okundu.")}
        points={[t("Mesajı okumayanlara tek tıkla hatırlatma gönderebilirsiniz (saatte bir)."), t("Müşteri kullanıcıları yalnızca kendi organizasyonuna ve danışmanlık ekibine yazabilir."), t("Hatırlatıcılar sekmesinden kendinize zamanlı not bırakabilirsiniz.")]} />
      <Tabs value={tab} onChange={setTab}>
        <Tabs.List mb="md">
          <Tabs.Tab value="inbox" leftSection={<IconInbox size={14} />}>{t("Gelen")}</Tabs.Tab>
          <Tabs.Tab value="sent" leftSection={<IconSend size={14} />}>{t("Giden")}</Tabs.Tab>
          <Tabs.Tab value="unread" leftSection={<IconMailOpened size={14} />}>{t("Okunmamış")}</Tabs.Tab>
          <Tabs.Tab value="reminders" leftSection={<IconAlarm size={14} />}>{t("Hatırlatıcılar")}</Tabs.Tab>
        </Tabs.List>
      </Tabs>
      {tab === "reminders" ? <Reminders /> : (
        <Grid>
          <Grid.Col span={{ base: 12, md: 4 }}>
            <Card withBorder p="xs">
              <TextInput mb="xs" leftSection={<IconSearch size={14} />} placeholder={t("Konuda ara")} value={q} onChange={(e) => setQ(e.currentTarget.value)} />
              <ScrollArea h={560}><ThreadList box={tab} sel={id ? Number(id) : undefined} q={q} /></ScrollArea>
            </Card>
          </Grid.Col>
          <Grid.Col span={{ base: 12, md: 8 }}>
            {id ? <Conversation id={Number(id)} /> : <Card withBorder h="100%"><Empty icon={IconMailOpened} text={t("Okumak için soldan bir konuşma seçin veya yeni mesaj yazın")} /></Card>}
          </Grid.Col>
        </Grid>
      )}
      <ComposeModal opened={compose} onClose={() => { setCompose(false); if (teamParam) { const n = new URLSearchParams(sp); n.delete("team"); setSp(n, { replace: true }); } }} teamId={teamParam ? Number(teamParam) : undefined} />
    </>
  );
}
