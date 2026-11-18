import { Badge, Button, Card, Group, Modal, PasswordInput, SegmentedControl, Select, Stack, Text, TextInput } from "@mantine/core";
import { useState } from "react";
import { IconLock } from "@tabler/icons-react";
import { api } from "../api";
import { t } from "../i18n";
import { fail, ok } from "./ui";

const TYPES = [
  { value: "none", label: t("Yok") }, { value: "basic", label: "Basic" }, { value: "bearer", label: "Bearer" },
  { value: "header", label: t("Özel başlık") }, { value: "cookie", label: t("Çerez") }, { value: "form", label: t("Form ile giriş") },
];

export function WebAuthCard({ target, onSaved }: { target: any; onSaved: () => void }) {
  const cur = target.auth ?? { type: "none" };
  const [open, setOpen] = useState(false);
  const [f, setF] = useState<any>({});
  const label = TYPES.find((x) => x.value === cur.type)?.label ?? cur.type;
  function start() {
    setF({ type: cur.type, format: "form", username_field: "username", password_field: "password", ...Object.fromEntries(Object.entries(cur).filter(([, v]) => typeof v === "string")) });
    setOpen(true);
  }
  async function save() {
    try {
      await api(`/targets/${target.id}`, { method: "PATCH", body: { auth: f } });
      ok(t("Kimlik doğrulama kaydedildi"));
      setOpen(false);
      onSaved();
    } catch (e) { fail(e); }
  }
  const set = (k: string) => (e: any) => setF({ ...f, [k]: e?.currentTarget ? e.currentTarget.value : e });
  const kept = (k: string) => (cur.type === f.type && cur[k] === true ? t("Kayıtlı — değiştirmek için yazın") : "");
  return (
    <Card withBorder>
      <Group justify="space-between" mb={4}>
        <Group gap="xs"><IconLock size={16} /><Text fw={600}>{t("Kimlik doğrulama")}</Text></Group>
        <Button size="xs" variant="light" onClick={start}>{t("Düzenle")}</Button>
      </Group>
      <Group gap="xs">
        <Badge variant="light" color={cur.type === "none" ? "gray" : "green"}>{label}</Badge>
        {cur.username && <Text size="sm">{cur.username}</Text>}
        {cur.name && <Text size="sm" ff="monospace">{cur.name}</Text>}
        {cur.login_url && <Text size="xs" c="dimmed" ff="monospace">{cur.login_url}</Text>}
      </Group>
      <Text size="xs" c="dimmed" mt={6}>{t("Oturum gerektiren sayfaları taramak için. Bilgiler şifreli saklanır, ekrana ve günlüğe yazılmaz. Oturumlu taramada çıkış / silme bağlantılarına gidilmez.")}</Text>
      <Modal opened={open} onClose={() => setOpen(false)} title={t("Kimlik doğrulama")} size="lg">
        <Stack>
          <SegmentedControl data={TYPES} value={f.type} onChange={(v) => setF({ ...f, type: v })} />
          {f.type === "basic" && <>
            <TextInput label={t("Kullanıcı adı")} value={f.username ?? ""} onChange={set("username")} autoComplete="off" />
            <PasswordInput label={t("Parola")} placeholder={kept("password")} value={f.password ?? ""} onChange={set("password")} autoComplete="new-password" />
          </>}
          {f.type === "bearer" && <PasswordInput label="Token" placeholder={kept("token")} value={f.token ?? ""} onChange={set("token")} autoComplete="off" />}
          {f.type === "header" && <>
            <TextInput label={t("Başlık adı")} placeholder="X-API-Key" value={f.name ?? ""} onChange={set("name")} />
            <PasswordInput label={t("Başlık değeri")} placeholder={kept("value")} value={f.value ?? ""} onChange={set("value")} autoComplete="off" />
          </>}
          {f.type === "cookie" && <PasswordInput label={t("Çerez")} description="session=abc123; other=x" placeholder={kept("cookie")} value={f.cookie ?? ""} onChange={set("cookie")} autoComplete="off" />}
          {f.type === "form" && <>
            <Group grow>
              <TextInput label={t("Giriş sayfası")} placeholder="https://app.ornek.com/login" value={f.login_url ?? ""} onChange={set("login_url")} />
              <TextInput label={t("Gönderim adresi (farklıysa)")} value={f.action_url ?? ""} onChange={set("action_url")} />
            </Group>
            <Group grow>
              <Select label={t("Biçim")} data={[{ value: "form", label: "application/x-www-form-urlencoded" }, { value: "json", label: "JSON" }]} value={f.format ?? "form"} onChange={(v) => setF({ ...f, format: v })} allowDeselect={false} />
              <TextInput label={t("CSRF alanı (varsa)")} placeholder="csrf_token" value={f.csrf_field ?? ""} onChange={set("csrf_field")} />
            </Group>
            <Group grow>
              <TextInput label={t("Kullanıcı adı alanı")} value={f.username_field ?? ""} onChange={set("username_field")} />
              <TextInput label={t("Parola alanı")} value={f.password_field ?? ""} onChange={set("password_field")} />
            </Group>
            <Group grow>
              <TextInput label={t("Kullanıcı adı")} value={f.username ?? ""} onChange={set("username")} autoComplete="off" />
              <PasswordInput label={t("Parola")} placeholder={kept("password")} value={f.password ?? ""} onChange={set("password")} autoComplete="new-password" />
            </Group>
            <Group grow>
              <TextInput label={t("Başarı metni (isteğe bağlı)")} description={t("Girişten sonra sayfada görünmesi gereken metin")} value={f.success_text ?? ""} onChange={set("success_text")} />
              <TextInput label={t("Hata metni (isteğe bağlı)")} description={t("Görünürse giriş başarısız sayılır")} value={f.failure_text ?? ""} onChange={set("failure_text")} />
            </Group>
          </>}
          <Text size="xs" c="dimmed">{t("Test hesabı kullanın; üretim yöneticisi hesabı vermeyin.")}</Text>
          <Group justify="flex-end"><Button onClick={save}>{t("Kaydet")}</Button></Group>
        </Stack>
      </Modal>
    </Card>
  );
}
