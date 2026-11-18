import { Alert, Button, Card, Checkbox, Group, List, Modal, Stack, Text, Tooltip } from "@mantine/core";
import { useState } from "react";
import { IconTrash, IconX } from "@tabler/icons-react";
import { api, User } from "../api";
import { fail, ok } from "./ui";
import { t } from "../i18n";

export const can = (u: User | null | undefined, perm: string) => !!u && (u.role === "admin" || (u.permissions ?? []).includes(perm));

export function useSelection() {
  const [sel, setSel] = useState<Set<number>>(new Set());
  const toggle = (id: number) => setSel((s) => { const n = new Set(s); if (n.has(id)) n.delete(id); else n.add(id); return n; });
  const header = (ids: number[]) => {
    const all = ids.length > 0 && ids.every((i) => sel.has(i));
    return <Checkbox size="xs" aria-label={t("Hepsini seç")} checked={all} indeterminate={!all && ids.some((i) => sel.has(i))}
      onChange={() => setSel((s) => { const n = new Set(s); ids.forEach((i) => (all ? n.delete(i) : n.add(i))); return n; })} onClick={(e) => e.stopPropagation()} />;
  };
  const cell = (id: number, disabled = false) => (
    <Checkbox size="xs" aria-label={t("Seç")} checked={sel.has(id)} disabled={disabled} onChange={() => toggle(id)} onClick={(e) => e.stopPropagation()} />
  );
  return { sel, ids: [...sel], clear: () => setSel(new Set()), header, cell };
}

const SELECTED = (n: number) => ({ projects: t("{n} proje seçildi", { n }), targets: t("{n} hedef seçildi", { n }), scans: t("{n} tarama seçildi", { n }) } as Record<string, string>);
const DELETED = (n: number) => ({ projects: t("{n} proje silindi", { n }), targets: t("{n} hedef silindi", { n }), scans: t("{n} tarama silindi", { n }) } as Record<string, string>);

export function BulkBar({ kind, ids, user, onClear, onDone, children }:
  { kind: "projects" | "targets" | "scans"; ids: number[]; user: User; onClear: () => void; onDone: () => void; children?: React.ReactNode }) {
  const [preview, setPreview] = useState<any | null>(null);
  const [sure, setSure] = useState(false);
  const [busy, setBusy] = useState(false);
  const allowed = can(user, "bulk_delete");
  if (!ids.length) return null;
  async function openPreview() {
    setBusy(true);
    try { setPreview(await api("/bulk/preview", { body: { kind, ids } })); setSure(false); } catch (e) { fail(e); } finally { setBusy(false); }
  }
  async function remove() {
    setBusy(true);
    try {
      const r = await api("/bulk/delete", { body: { kind, ids } });
      ok(DELETED(r.deleted.length)[kind] + (r.errors.length ? t(" · {n} silinemedi", { n: r.errors.length }) : ""));
      if (r.errors.length) fail(new Error(r.errors[0].error));
      setPreview(null); onClear(); onDone();
    } catch (e) { fail(e); } finally { setBusy(false); }
  }
  const c = preview?.counts ?? {};
  const parts = [c.projects && t("{n} proje", { n: c.projects }), c.targets && t("{n} hedef", { n: c.targets }), c.scans && t("{n} tarama", { n: c.scans }),
    c.findings && t("{n} bulgu", { n: c.findings })].filter(Boolean);
  return (
    <>
      <Card withBorder mb="sm" p="xs" bg="var(--mantine-color-indigo-light)">
        <Group justify="space-between" wrap="wrap" gap="xs">
          <Text size="sm" fw={600}>{SELECTED(ids.length)[kind]}</Text>
          <Group gap="xs">
            {children}
            <Button size="xs" variant="default" leftSection={<IconX size={14} />} onClick={onClear}>{t("Seçimi temizle")}</Button>
            <Tooltip label={t("Toplu silme yetkiniz yok; yöneticiden isteyin")} disabled={allowed}>
              <Button size="xs" color="red" variant="light" leftSection={<IconTrash size={14} />} onClick={openPreview} loading={busy && !preview} disabled={!allowed}>{t("Seçilenleri sil")}</Button>
            </Tooltip>
          </Group>
        </Group>
      </Card>
      <Modal opened={preview !== null} onClose={() => setPreview(null)} title={t("Toplu silme")}>
        {preview && (
          <Stack>
            <Alert color="red" variant="light" icon={<IconTrash size={16} />}>
              <Text size="sm" fw={600}>{t("Silinecekler: {list}", { list: parts.join(", ") || "—" })}</Text>
              {kind !== "scans" && <Text size="xs" mt={4}>{t("Projeler ve hedefler; içlerindeki taramalar, bulgular, yüklenen dosyalar ve raporlarla birlikte silinir.")}</Text>}
              {kind === "scans" && <Text size="xs" mt={4}>{t("Taramalar ve raporları silinir; bulgular hedefte kalır.")}{c.active ? " " + t("Sıradaki / çalışan {n} tarama silinmez.", { n: c.active }) : ""}</Text>}
            </Alert>
            {preview.names?.length > 0 && <List size="xs" spacing={0}>{preview.names.slice(0, 10).map((n: string, i: number) => <List.Item key={i}>{n}</List.Item>)}{preview.names.length > 10 && <List.Item>…</List.Item>}</List>}
            {preview.errors?.length > 0 && <Text size="xs" c="orange">{t("{n} öğeye erişiminiz yok; bunlar silinmez.", { n: preview.errors.length })}</Text>}
            <Checkbox label={t("Bu işlemin geri alınamayacağını anlıyorum")} checked={sure} onChange={(e) => setSure(e.currentTarget.checked)} />
            <Group justify="flex-end"><Button variant="default" onClick={() => setPreview(null)}>{t("Vazgeç")}</Button>
              <Button color="red" onClick={remove} loading={busy} disabled={!sure}>{t("Kalıcı olarak sil")}</Button></Group>
          </Stack>
        )}
      </Modal>
    </>
  );
}
