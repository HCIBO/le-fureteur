import { ActionIcon, Anchor, Badge, Button, Card, Group, Modal, PasswordInput, Select, Stack, Switch, Table, Text, TextInput } from "@mantine/core";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";
import { IconPencil, IconTrash } from "@tabler/icons-react";
import { api, fmtDate, ROLE_LABEL, User } from "../api";
import { fail, ok, PageHeader } from "../components/ui";
import { PageIntro } from "../components/PageIntro";
import { t } from "../i18n";

const ROLE_HELP: Record<string, string> = {
  admin: t("Her şey: kullanıcılar, ayarlar, veritabanı, tüm organizasyonlar."),
  analyst: t("Tüm organizasyonlarda proje / hedef / tarama / bulgu yönetimi; ayarları göremez."),
  customer: t("Yalnızca kendi organizasyonu: hedef ekler, tarar, bulgu durumunu yönetir."),
};

export default function Users() {
  const qc = useQueryClient();
  const users = useQuery<User[]>({ queryKey: ["users"], queryFn: () => api("/users") });
  const orgs = useQuery<any[]>({ queryKey: ["orgs"], queryFn: () => api("/orgs") });
  const [edit, setEdit] = useState<any | null>(null);
  async function save() {
    try {
      const body: any = { name: edit.name, role: edit.role, organization_id: edit.organization_id ? Number(edit.organization_id) : null };
      if (edit.password) body.password = edit.password;
      if (edit.id) await api(`/users/${edit.id}`, { method: "PATCH", body: { ...body, active: edit.active, ...(edit.role !== "admin" ? { permissions: edit.permissions ?? [] } : {}) } });
      else await api("/users", { body: { ...body, email: edit.email } });
      qc.invalidateQueries({ queryKey: ["users"] });
      setEdit(null);
      ok(t("Kaydedildi"));
    } catch (e) { fail(e); }
  }
  async function remove(u: User) {
    if (!confirm(`${u.email} silinsin mi?`)) return;
    try { await api(`/users/${u.id}`, { method: "DELETE" }); qc.invalidateQueries({ queryKey: ["users"] }); } catch (e) { fail(e); }
  }
  return (
    <>
      <PageHeader title={t("Kullanıcılar")} right={<Button onClick={() => setEdit({ email: "", name: "", role: "analyst", organization_id: "", password: "", active: true })}>{t("Yeni kullanıcı")}</Button>} />
      <PageIntro id="users" guide="admin"
        text={t("Kullanıcıları, rollerini ve organizasyonlarını yönetin. Bir kullanıcıya tıklayınca giriş geçmişini, etkin oturumlarını, cihaz / IP bilgisini ve son işlemlerini görürsünüz.")}
        points={[t("Şüpheli bir durumda kullanıcının tüm oturumlarını tek tıkla sonlandırabilirsiniz."), t("Devre dışı bırakılan kullanıcı giriş yapamaz; API token'ları da çalışmaz.")]} />
      <Card withBorder p={0}>
        <Table.ScrollContainer minWidth={640}><Table verticalSpacing="sm">
          <Table.Thead><Table.Tr><Table.Th>{t("E-posta")}</Table.Th><Table.Th>{t("Rol")}</Table.Th><Table.Th>{t("Organizasyon")}</Table.Th><Table.Th>{t("Son giriş")}</Table.Th><Table.Th /></Table.Tr></Table.Thead>
          <Table.Tbody>
            {(users.data ?? []).map((u) => (
              <Table.Tr key={u.id} style={{ opacity: u.active ? 1 : 0.5 }}>
                <Table.Td><Anchor component={Link} to={`/users/${u.id}`} fw={600}>{u.email}</Anchor><Text size="xs" c="dimmed">{u.name}{!u.active && t(" · devre dışı")}</Text></Table.Td>
                <Table.Td><Group gap={4}><Badge variant="light" color={u.role === "admin" ? "red" : u.role === "analyst" ? "indigo" : "teal"}>{ROLE_LABEL[u.role]}</Badge>
                  {u.role !== "admin" && u.permissions?.includes("bulk_delete") && <Badge variant="outline" color="red" size="xs" tt="none">{t("Toplu silme")}</Badge>}</Group></Table.Td>
                <Table.Td>{u.organization ?? "-"}</Table.Td>
                <Table.Td>{fmtDate(u.last_login)}</Table.Td>
                <Table.Td ta="right"><Group gap={4} justify="flex-end">
                  <ActionIcon variant="subtle" onClick={() => setEdit({ ...u, organization_id: u.organization_id ? String(u.organization_id) : "", password: "" })} aria-label={t("Düzenle")}><IconPencil size={16} /></ActionIcon>
                  <ActionIcon variant="subtle" color="red" onClick={() => remove(u)} aria-label={t("Sil")}><IconTrash size={16} /></ActionIcon></Group></Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table></Table.ScrollContainer>
      </Card>
      <Modal opened={edit !== null} onClose={() => setEdit(null)} title={edit?.id ? t("Kullanıcıyı düzenle") : t("Yeni kullanıcı")}>
        {edit && <Stack>
          <TextInput label={t("E-posta")} value={edit.email} disabled={!!edit.id} onChange={(e) => setEdit({ ...edit, email: e.currentTarget.value })} />
          <TextInput label={t("Ad")} value={edit.name} onChange={(e) => setEdit({ ...edit, name: e.currentTarget.value })} />
          <Select label={t("Rol")} data={Object.entries(ROLE_LABEL).map(([value, label]) => ({ value, label }))} value={edit.role} onChange={(v) => setEdit({ ...edit, role: v })} description={ROLE_HELP[edit.role]} />
          <Select label={t("Organizasyon")} clearable required={edit.role === "customer"} data={(orgs.data ?? []).map((o) => ({ value: String(o.id), label: o.name }))} value={edit.organization_id || null} onChange={(v) => setEdit({ ...edit, organization_id: v ?? "" })} />
          <PasswordInput label={edit.id ? t("Yeni parola (değiştirmek için)") : t("Parola")} description={t("En az 10 karakter")} value={edit.password} onChange={(e) => setEdit({ ...edit, password: e.currentTarget.value })} />
          {edit.id && <Switch label={t("Aktif")} checked={edit.active} onChange={(e) => setEdit({ ...edit, active: e.currentTarget.checked })} />}
          {edit.id && edit.role !== "admin" && (
            <Switch label={t("Toplu silme yetkisi")} description={t("Projeleri, hedefleri ve taramaları toplu seçip silebilir (yalnızca erişebildiği kayıtlar). Yöneticilerde her zaman açıktır.")}
              checked={(edit.permissions ?? []).includes("bulk_delete")}
              onChange={(e) => setEdit({ ...edit, permissions: e.currentTarget.checked ? [...new Set([...(edit.permissions ?? []), "bulk_delete"])] : (edit.permissions ?? []).filter((x: string) => x !== "bulk_delete") })} />
          )}
          <Group justify="flex-end"><Button onClick={save} disabled={!edit.email || (!edit.id && !edit.password)}>{t("Kaydet")}</Button></Group>
        </Stack>}
      </Modal>
    </>
  );
}
