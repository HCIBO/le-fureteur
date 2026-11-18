import { ActionIcon, Alert, Badge, Button, Card, Checkbox, Group, Modal, MultiSelect, PasswordInput, SegmentedControl, Select, SimpleGrid, Stack, Switch, Text, TextInput, Tooltip } from "@mantine/core";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { IconCheck, IconPencil, IconPlugConnected, IconPlus, IconTicket, IconTrash, IconX } from "@tabler/icons-react";
import { api } from "../api";
import { fail, ok } from "./ui";
import { t } from "../i18n";

const ROLE_LABEL = () => ({ admin: t("Yönetici"), analyst: t("Analist"), customer: t("Müşteri") } as Record<string, string>);
const EMPTY = { name: "", url: "", auth: "cloud", user: "", token: "", project_key: "", issue_type: "Bug", labels: "", auto_min_severity: "",
  comment_on_fix: true, enabled: true, roles: ["admin", "analyst"], user_ids: [] as string[], org_ids: [] as string[] };

export function JiraInstances() {
  const qc = useQueryClient();
  const list = useQuery<any[]>({ queryKey: ["jira-instances"], queryFn: () => api("/jira/instances") });
  const users = useQuery<any[]>({ queryKey: ["users"], queryFn: () => api("/users") });
  const orgs = useQuery<any[]>({ queryKey: ["orgs"], queryFn: () => api("/orgs") });
  const [edit, setEdit] = useState<any | null>(null);
  const [test, setTest] = useState<Record<number, { ok: boolean; text: string }>>({});
  const [busy, setBusy] = useState(false);
  const refresh = () => { qc.invalidateQueries({ queryKey: ["jira-instances"] }); qc.invalidateQueries({ queryKey: ["jira-status"] }); };
  const uName = (id: number) => users.data?.find((u) => u.id === id)?.email ?? `#${id}`;
  const oName = (id: number) => orgs.data?.find((o) => o.id === id)?.name ?? `#${id}`;
  async function save() {
    setBusy(true);
    try {
      const body = { ...edit, token: edit.token ? edit.token : null, user_ids: edit.user_ids.map(Number), org_ids: edit.org_ids.map(Number) };
      if (edit.id) await api(`/jira/instances/${edit.id}`, { method: "PUT", body }); else await api("/jira/instances", { body });
      ok(t("Kaydedildi")); setEdit(null); refresh();
    } catch (e) { fail(e); } finally { setBusy(false); }
  }
  async function remove(i: any) {
    if (!confirm(t("\"{n}\" Jira bağlantısı silinsin mi? Açılmış kayıtların bağlantıları bulgularda kalır.", { n: i.name }))) return;
    try { await api(`/jira/instances/${i.id}`, { method: "DELETE" }); refresh(); } catch (e) { fail(e); }
  }
  async function runTest(i: any) {
    try { const r = await api("/jira/test", { body: { instance_id: i.id } }); setTest({ ...test, [i.id]: { ok: true, text: t("Bağlantı tamam: {user}", { user: r.user }) + (r.project ? ` · ${r.project}` : "") } }); }
    catch (e: any) { setTest({ ...test, [i.id]: { ok: false, text: t(e?.message ?? String(e)) } }); }
  }
  const open = (i?: any) => setEdit(i ? { ...EMPTY, ...i, token: "", user_ids: i.user_ids.map(String), org_ids: i.org_ids.map(String) } : { ...EMPTY });
  return (
    <Stack>
      <Group justify="space-between">
        <Text size="sm" c="dimmed">{t("{n} Jira bağlantısı", { n: list.data?.length ?? 0 })}</Text>
        <Button size="xs" leftSection={<IconPlus size={14} />} onClick={() => open()}>{t("Jira bağlantısı ekle")}</Button>
      </Group>
      {(list.data ?? []).map((i) => (
        <Card key={i.id} withBorder padding="sm">
          <Group justify="space-between" wrap="nowrap" align="flex-start">
            <div style={{ minWidth: 0 }}>
              <Group gap="xs"><IconTicket size={16} /><Text fw={700}>{i.name}</Text>
                {!i.enabled && <Badge color="gray" variant="light">{t("Kapalı")}</Badge>}
                {i.enabled && !i.ready && <Badge color="orange" variant="light">{t("Eksik ayar")}</Badge>}
                {i.project_key && <Badge variant="outline">{i.project_key}</Badge>}
                {i.auto_min_severity && <Badge variant="light" color="grape">{t("Otomatik: {s}+", { s: i.auto_min_severity })}</Badge>}</Group>
              <Text size="xs" c="dimmed" truncate>{i.url} · {i.auth === "server" ? "Server / DC" : "Cloud"}{i.user ? ` · ${i.user}` : ""}</Text>
              <Group gap={4} mt={6}>
                {i.roles.map((r: string) => <Badge key={r} size="xs" variant="light">{ROLE_LABEL()[r] ?? r}</Badge>)}
                {i.user_ids.length > 0 && <Tooltip label={i.user_ids.map(uName).join(", ")} multiline w={300}><Badge size="xs" color="teal" variant="light">{t("{n} kullanıcıyla sınırlı", { n: i.user_ids.length })}</Badge></Tooltip>}
                <Badge size="xs" color="indigo" variant="light">{i.org_ids.length ? i.org_ids.map(oName).join(", ") : t("Tüm organizasyonlar")}</Badge>
              </Group>
              {test[i.id] && <Text size="xs" mt={6} c={test[i.id].ok ? "teal" : "red"}>{test[i.id].ok ? <IconCheck size={12} /> : <IconX size={12} />} {test[i.id].text}</Text>}
            </div>
            <Group gap={4} wrap="nowrap">
              <Tooltip label={t("Bağlantıyı test et")}><ActionIcon variant="subtle" onClick={() => runTest(i)} aria-label={t("Bağlantıyı test et")}><IconPlugConnected size={16} /></ActionIcon></Tooltip>
              <Tooltip label={t("Düzenle")}><ActionIcon variant="subtle" onClick={() => open(i)} aria-label={t("Düzenle")}><IconPencil size={16} /></ActionIcon></Tooltip>
              <Tooltip label={t("Sil")}><ActionIcon variant="subtle" color="red" onClick={() => remove(i)} aria-label={t("Sil")}><IconTrash size={16} /></ActionIcon></Tooltip>
            </Group>
          </Group>
        </Card>
      ))}
      {list.data?.length === 0 && <Alert variant="light" color="gray">{t("Henüz Jira bağlantısı yok. Her müşteri veya ekip için ayrı bir Jira ekleyip kimlerin kullanabileceğini belirleyebilirsiniz.")}</Alert>}
      <Modal opened={edit !== null} onClose={() => setEdit(null)} title={edit?.id ? t("Jira bağlantısını düzenle") : t("Jira bağlantısı ekle")} size="lg">
        {edit && (
          <Stack>
            <SimpleGrid cols={{ base: 1, sm: 2 }}>
              <TextInput label={t("Ad")} required placeholder={t("ör. Acme Jira")} value={edit.name} onChange={(e) => setEdit({ ...edit, name: e.currentTarget.value })} maxLength={100} />
              <TextInput label={t("Jira adresi")} required placeholder="https://acme.atlassian.net" value={edit.url} onChange={(e) => setEdit({ ...edit, url: e.currentTarget.value })} />
            </SimpleGrid>
            <SegmentedControl value={edit.auth} onChange={(v) => setEdit({ ...edit, auth: v })} data={[{ value: "cloud", label: t("Cloud (e-posta + API token)") }, { value: "server", label: t("Server / Data Center (kişisel erişim token'ı)") }]} />
            <SimpleGrid cols={{ base: 1, sm: 2 }}>
              {edit.auth === "cloud" && <TextInput label={t("E-posta")} value={edit.user} onChange={(e) => setEdit({ ...edit, user: e.currentTarget.value })} />}
              <PasswordInput label={t("Token")} autoComplete="new-password" placeholder={edit.id && edit.token_set ? t("•••••••• (ayarlı — değiştirmek için yazın)") : ""} value={edit.token} onChange={(e) => setEdit({ ...edit, token: e.currentTarget.value })} />
            </SimpleGrid>
            <SimpleGrid cols={{ base: 1, sm: 3 }}>
              <TextInput label={t("Proje anahtarı")} placeholder="SEC" value={edit.project_key} onChange={(e) => setEdit({ ...edit, project_key: e.currentTarget.value.toUpperCase() })} />
              <TextInput label={t("Kayıt türü")} value={edit.issue_type} onChange={(e) => setEdit({ ...edit, issue_type: e.currentTarget.value })} />
              <TextInput label={t("Etiketler")} placeholder="security, sca" value={edit.labels} onChange={(e) => setEdit({ ...edit, labels: e.currentTarget.value })} />
            </SimpleGrid>
            <Select label={t("Taramada otomatik Jira kaydı")} description={t("Bu şiddet ve üzeri yeni bulgular için kayıt kendiliğinden açılır (projenin varsayılan Jira'sı veya kapsadığı organizasyon).")}
              data={[{ value: "", label: t("Kapalı") }, { value: "CRITICAL", label: t("Kritik") }, { value: "HIGH", label: t("Yüksek ve üzeri") }, { value: "MEDIUM", label: t("Orta ve üzeri") }, { value: "LOW", label: t("Düşük ve üzeri") }]}
              value={edit.auto_min_severity} onChange={(v) => setEdit({ ...edit, auto_min_severity: v ?? "" })} allowDeselect={false} />
            <Card withBorder padding="sm">
              <Text fw={600} size="sm">{t("Kimler kullanabilir?")}</Text>
              <Text size="xs" c="dimmed" mb="xs">{t("Yöneticiler her bağlantıyı kullanabilir. Diğerleri yalnızca seçilen rollerdeyse (ve kullanıcı listesi doluysa listedeyse) kullanabilir. Müşteriler yalnızca kendi organizasyonlarının bulgularını gönderebilir.")}</Text>
              <Checkbox.Group value={edit.roles} onChange={(v) => setEdit({ ...edit, roles: v })}>
                <Group gap="md">{["admin", "analyst", "customer"].map((r) => <Checkbox key={r} value={r} label={ROLE_LABEL()[r]} disabled={r === "admin"} />)}</Group>
              </Checkbox.Group>
              <MultiSelect mt="sm" label={t("Yalnızca bu kullanıcılar (boş = seçili rollerdeki herkes)")} searchable clearable
                data={(users.data ?? []).filter((u) => u.role !== "admin").map((u) => ({ value: String(u.id), label: `${u.email} (${ROLE_LABEL()[u.role] ?? u.role})` }))}
                value={edit.user_ids} onChange={(v) => setEdit({ ...edit, user_ids: v })} />
              <MultiSelect mt="sm" label={t("Yalnızca bu organizasyonların bulguları (boş = tümü)")} searchable clearable
                data={(orgs.data ?? []).map((o) => ({ value: String(o.id), label: o.name }))} value={edit.org_ids} onChange={(v) => setEdit({ ...edit, org_ids: v })} />
            </Card>
            <Group>
              <Switch label={t("Bulgu düzelince / yeniden açılınca kayda yorum yaz")} checked={edit.comment_on_fix} onChange={(e) => setEdit({ ...edit, comment_on_fix: e.currentTarget.checked })} />
              <Switch label={t("Etkin")} checked={edit.enabled} onChange={(e) => setEdit({ ...edit, enabled: e.currentTarget.checked })} />
            </Group>
            <Group justify="flex-end"><Button variant="default" onClick={() => setEdit(null)}>{t("Vazgeç")}</Button><Button onClick={save} loading={busy} disabled={!edit.name.trim() || !edit.url.trim()}>{t("Kaydet")}</Button></Group>
          </Stack>
        )}
      </Modal>
    </Stack>
  );
}

export function useJiraPicker() {
  const status = useQuery<any>({ queryKey: ["jira-status"], queryFn: () => api("/jira/status") });
  const [pending, setPending] = useState<((id: number | null) => void) | null>(null);
  const [choice, setChoice] = useState<string | null>(null);
  const instances: any[] = status.data?.instances ?? [];
  function choose(): Promise<number | null | undefined> {
    if (instances.length <= 1) return Promise.resolve(instances[0]?.id ?? null);
    return new Promise((resolve) => { setChoice(String(instances[0].id)); setPending(() => (v: number | null) => resolve(v ?? undefined)); });
  }
  const modal = (
    <Modal opened={pending !== null} onClose={() => { pending?.(null); setPending(null); }} title={t("Hangi Jira'ya eklensin?")}>
      <Stack>
        <Select data={instances.map((i) => ({ value: String(i.id), label: i.project_key ? `${i.name} · ${i.project_key}` : i.name }))} value={choice} onChange={setChoice} allowDeselect={false} />
        <Text size="xs" c="dimmed">{t("Yalnızca kullanma yetkiniz olan Jira bağlantıları listelenir. Projeye varsayılan Jira atanırsa bu soru sorulmaz.")}</Text>
        <Group justify="flex-end"><Button variant="default" onClick={() => { pending?.(null); setPending(null); }}>{t("Vazgeç")}</Button>
          <Button onClick={() => { pending?.(Number(choice)); setPending(null); }}>{t("Ekle")}</Button></Group>
      </Stack>
    </Modal>
  );
  return { configured: !!status.data?.configured, instances, choose, modal };
}
