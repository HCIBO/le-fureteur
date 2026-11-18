import { ActionIcon, Badge, Button, Card, Checkbox, Group, Modal, Paper, Select, SimpleGrid, Stack, Switch, TagsInput, Text, TextInput, PasswordInput, ThemeIcon, UnstyledButton } from "@mantine/core";
import { PageIntro } from "../components/PageIntro";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { IconAlertTriangle, IconBrandSlack, IconCircleCheck, IconMail, IconPencil, IconPlus, IconSend, IconTrash, IconWebhook, IconUsersGroup } from "@tabler/icons-react";
import { api, fmtDate, SEV_LABEL } from "../api";
import { fail, ok, PageHeader } from "../components/ui";
import { t } from "../i18n";

const KIND: Record<string, { label: string; icon: any; help: string; color: string }> = {
  slack: { label: t("Slack"), icon: IconBrandSlack, color: "grape", help: t("Slack → Apps → Incoming Webhooks → kanal seçip oluşturulan https://hooks.slack.com/services/... adresi") },
  teams: { label: t("Microsoft Teams"), icon: IconUsersGroup, color: "indigo", help: t("Teams kanalı → Workflows → \"Post to a channel when a webhook request is received\" ile oluşturulan adres") },
  email: { label: t("E-posta"), icon: IconMail, color: "blue", help: t("Ayarlar → E-posta (SMTP) bölümündeki sunucu kullanılır") },
  webhook: { label: t("Genel webhook"), icon: IconWebhook, color: "teal", help: t("JSON POST. Gizli anahtar verilirse gövdenin HMAC-SHA256 imzası X-Scakit-Signature başlığında gönderilir") },
};

const EMPTY = { name: "", kind: "slack", url: "", secret: "", to: [] as string[], events: ["scan_done", "new_findings", "kev", "scan_failed"], min_severity: "HIGH", organization_id: "", enabled: true };

export default function Notifications() {
  const qc = useQueryClient();
  const list = useQuery<any[]>({ queryKey: ["channels"], queryFn: () => api("/notifications") });
  const meta = useQuery<any>({ queryKey: ["notify-meta"], queryFn: () => api("/notifications/meta") });
  const orgs = useQuery<any[]>({ queryKey: ["orgs"], queryFn: () => api("/orgs") });
  const [edit, setEdit] = useState<any | null>(null);
  const refresh = () => qc.invalidateQueries({ queryKey: ["channels"] });

  async function save() {
    const config = edit.kind === "email" ? { to: edit.to } : (edit.url ? { url: edit.url, ...(edit.secret ? { secret: edit.secret } : {}) } : {});
    const body: any = { name: edit.name, events: edit.events, min_severity: edit.min_severity, organization_id: edit.organization_id ? Number(edit.organization_id) : null, enabled: edit.enabled };
    try {
      if (edit.id) await api(`/notifications/${edit.id}`, { method: "PATCH", body: { ...body, ...(Object.keys(config).length && (edit.kind !== "email" || edit.to.length) ? { config } : {}) } });
      else await api("/notifications", { body: { ...body, kind: edit.kind, config } });
      setEdit(null);
      refresh();
      ok(t("Kaydedildi"));
    } catch (e) { fail(e); }
  }
  async function test(c: any) {
    try { await api(`/notifications/${c.id}/test`, { method: "POST" }); ok(t("Test bildirimi gönderildi")); } catch (e) { fail(e); }
    refresh();
  }
  async function remove(c: any) {
    if (!confirm(t("\"{name}\" kanalı silinsin mi?", { name: c.name }))) return;
    try { await api(`/notifications/${c.id}`, { method: "DELETE" }); refresh(); } catch (e) { fail(e); }
  }
  const events: Record<string, string> = meta.data?.events ?? {};
  const chans = list.data ?? [];
  return (
    <>
      <PageHeader title={t("Bildirim kanalları")} sub={t("Tarama sonuçları ve yeni kritik bulgular Slack, Teams, e-posta veya webhook ile bildirilir.")}
        right={<Button leftSection={<IconPlus size={16} />} onClick={() => setEdit({ ...EMPTY })}>{t("Yeni kanal")}</Button>} />
      <PageIntro id="notifications" guide="automation"
        text={t("Bir kanal; hangi olaylarda (tarama bitti, yeni bulgu, aktif sömürülen açık, tarama başarısız), hangi şiddetten itibaren ve hangi organizasyon için bildirim gideceğini belirler.")}
        points={[t("Webhook adresleri şifreli saklanır ve ekranda maskelenir."), t("Kanalı kaydettikten sonra \"Test gönder\" ile doğrulayın; sonuç kartta görünür."), t("Bildirim gönderilemezse tarama etkilenmez; hata kartta ve tarama günlüğünde yazar.")]} />
      {chans.length === 0 ? (
        <Card withBorder py="xl">
          <Text fw={700} ta="center">{t("Henüz kanal yok — nereye bildirim gitsin?")}</Text>
          <SimpleGrid cols={{ base: 1, sm: 2, md: 4 }} mt="lg">
            {Object.entries(KIND).map(([k, K]) => (
              <UnstyledButton key={k} onClick={() => setEdit({ ...EMPTY, kind: k })}>
                <Card withBorder h="100%"><ThemeIcon size={44} radius="md" variant="light" color={K.color}><K.icon size={24} /></ThemeIcon>
                  <Text fw={700} mt="sm">{K.label}</Text><Text size="xs" c="dimmed" mt={4} lineClamp={3}>{K.help}</Text></Card>
              </UnstyledButton>
            ))}
          </SimpleGrid>
        </Card>
      ) : (
        <SimpleGrid cols={{ base: 1, md: 2 }}>
          {chans.map((c) => {
            const K = KIND[c.kind];
            const okSt = c.last_status === "ok";
            return (
              <Card key={c.id} withBorder style={{ opacity: c.enabled ? 1 : 0.6, borderLeft: `4px solid var(--mantine-color-${!c.last_status ? "gray" : okSt ? "green" : "red"}-5)` }}>
                <Group justify="space-between" wrap="nowrap" align="flex-start">
                  <Group gap="sm" wrap="nowrap" style={{ minWidth: 0 }}>
                    <ThemeIcon size={42} radius="md" variant="light" color={K.color}><K.icon size={22} /></ThemeIcon>
                    <div style={{ minWidth: 0 }}>
                      <Group gap={6}><Text fw={700} truncate>{c.name}</Text>{!c.enabled && <Badge size="xs" color="gray">{t("Kapalı")}</Badge>}</Group>
                      <Text size="xs" c="dimmed" truncate>{K.label} · {c.kind === "email" ? c.config.to.join(", ") : c.config.url}</Text>
                    </div>
                  </Group>
                  <Group gap={4} wrap="nowrap">
                    <Button size="xs" variant="light" leftSection={<IconSend size={14} />} onClick={() => test(c)}>{t("Test gönder")}</Button>
                    <ActionIcon variant="subtle" onClick={() => setEdit({ ...EMPTY, ...c, url: "", secret: "", to: c.kind === "email" ? c.config.to : [], organization_id: c.organization_id ? String(c.organization_id) : "" })} aria-label={t("Düzenle")}><IconPencil size={16} /></ActionIcon>
                    <ActionIcon variant="subtle" color="red" onClick={() => remove(c)} aria-label={t("Sil")}><IconTrash size={16} /></ActionIcon>
                  </Group>
                </Group>
                <Group gap={4} mt="sm">{c.events.map((e: string) => <Badge key={e} size="sm" variant="light" tt="none">{t(events[e] ?? e)}</Badge>)}</Group>
                <Text size="xs" c="dimmed" mt={6}>{t("Eşik:")} {SEV_LABEL[c.min_severity]} {t("ve üzeri (KEV her zaman)")} · {c.organization_id ? orgs.data?.find((o) => o.id === c.organization_id)?.name ?? `#${c.organization_id}` : t("Tüm organizasyonlar")}</Text>
                <Paper mt="sm" p="xs" radius="md" bg={!c.last_status ? "var(--mantine-color-default-hover)" : okSt ? "var(--mantine-color-green-light)" : "var(--mantine-color-red-light)"}>
                  {!c.last_status ? <Text size="xs" c="dimmed">{t("Henüz gönderim yapılmadı")}</Text> : (
                    <Group gap={6} wrap="nowrap" align="flex-start">
                      {okSt ? <IconCircleCheck size={16} color="var(--mantine-color-green-7)" /> : <IconAlertTriangle size={16} color="var(--mantine-color-red-7)" />}
                      <div><Text size="xs" fw={600}>{okSt ? t("Son gönderim başarılı") : t("Son gönderim başarısız")} · {fmtDate(c.last_sent_at)}</Text>
                        {!okSt && <Text size="xs">{t(c.last_status)}</Text>}</div>
                    </Group>
                  )}
                </Paper>
              </Card>
            );
          })}
        </SimpleGrid>
      )}
      <Modal opened={edit !== null} onClose={() => setEdit(null)} title={edit?.id ? t("Kanalı düzenle") : t("Yeni bildirim kanalı")} size="lg">
        {edit && <Stack>
          <Group grow>
            <TextInput label={t("Ad")} value={edit.name} onChange={(e) => setEdit({ ...edit, name: e.currentTarget.value })} placeholder={t("Güvenlik ekibi Slack")} />
            <Select label={t("Tür")} disabled={!!edit.id} data={Object.entries(KIND).map(([value, k]) => ({ value, label: k.label }))} value={edit.kind} onChange={(v) => setEdit({ ...edit, kind: v })} allowDeselect={false} />
          </Group>
          <Text size="xs" c="dimmed">{KIND[edit.kind].help}</Text>
          {edit.kind === "email" ? (
            <TagsInput label={t("Alıcılar")} description={t("Enter ile ekleyin")} value={edit.to} onChange={(v) => setEdit({ ...edit, to: v })} />
          ) : (
            <>
              <PasswordInput label={t("Webhook adresi")} description={edit.id ? t("Değiştirmek için yeni adresi yazın; boş bırakılırsa mevcut adres korunur (gizli saklanır)") : t("Gizli saklanır")} value={edit.url} onChange={(e) => setEdit({ ...edit, url: e.currentTarget.value })} autoComplete="off" />
              {edit.kind === "webhook" && <PasswordInput label={t("İmza anahtarı (isteğe bağlı)")} value={edit.secret} onChange={(e) => setEdit({ ...edit, secret: e.currentTarget.value })} autoComplete="off" />}
            </>
          )}
          <Checkbox.Group label={t("Olaylar")} value={edit.events} onChange={(v) => setEdit({ ...edit, events: v })}>
            <Stack gap={6} mt={6}>{Object.entries(events).map(([k, l]) => <Checkbox key={k} value={k} label={t(l)} />)}</Stack>
          </Checkbox.Group>
          <Group grow>
            <Select label={t("Yeni bulgu eşiği")} data={["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((v) => ({ value: v, label: t("{sev} ve üzeri", { sev: SEV_LABEL[v] }) }))} value={edit.min_severity} onChange={(v) => setEdit({ ...edit, min_severity: v })} allowDeselect={false} />
            <Select label={t("Kapsam")} data={[{ value: "", label: t("Tüm organizasyonlar") }, ...(orgs.data ?? []).map((o) => ({ value: String(o.id), label: o.name }))]} value={edit.organization_id} onChange={(v) => setEdit({ ...edit, organization_id: v ?? "" })} allowDeselect={false} />
          </Group>
          <Switch label={t("Etkin")} checked={edit.enabled} onChange={(e) => setEdit({ ...edit, enabled: e.currentTarget.checked })} />
          <Group justify="flex-end"><Button onClick={save} disabled={!edit.name || (!edit.id && (edit.kind === "email" ? !edit.to.length : !edit.url))}>{t("Kaydet")}</Button></Group>
        </Stack>}
      </Modal>
    </>
  );
}
