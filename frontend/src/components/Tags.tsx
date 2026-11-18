import { ActionIcon, Badge, Button, CheckIcon, ColorSwatch, Group, Modal, MultiSelect, Stack, Table, Text, TextInput, Tooltip } from "@mantine/core";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { IconTag, IconTrash } from "@tabler/icons-react";
import { api, User } from "../api";
import { t } from "../i18n";
import { fail, ok } from "./ui";

export type Tag = { id: number; name: string; color: string; builtin: boolean; organization_id: number | null; organization: string | null; projects: number };

export const tagLabel = (tg: { name: string; builtin: boolean }) => (tg.builtin ? t(tg.name) : tg.name);

export function useTags() {
  return useQuery<{ colors: string[]; items: Tag[] }>({ queryKey: ["tags"], queryFn: () => api("/tags") });
}

export function TagBadge({ tag, size = "sm" }: { tag: { name: string; color: string; builtin: boolean }; size?: string }) {
  return <Badge size={size} variant="light" color={tag.color} leftSection={<IconTag size={10} />} tt="none">{tagLabel(tag)}</Badge>;
}

export function TagPicker({ value, onChange, orgId }: { value: number[]; onChange: (v: number[]) => void; orgId?: number | null }) {
  const tags = useTags();
  const items = (tags.data?.items ?? []).filter((tg) => !tg.organization_id || !orgId || tg.organization_id === orgId);
  const byId = Object.fromEntries(items.map((tg) => [String(tg.id), tg]));
  return (
    <MultiSelect label={t("Etiketler")} placeholder={value.length ? "" : t("Etiket seçin")} searchable clearable
      data={items.map((tg) => ({ value: String(tg.id), label: tagLabel(tg) }))}
      value={value.map(String)} onChange={(v) => onChange(v.map(Number))}
      renderOption={({ option, checked }) => (
        <Group gap="xs">{checked && <CheckIcon size={10} />}<ColorSwatch size={12} color={`var(--mantine-color-${byId[option.value]?.color ?? "gray"}-6)`} /><Text size="sm">{option.label}</Text></Group>
      )} />
  );
}

export function TagManager({ opened, onClose, user, orgs }: { opened: boolean; onClose: () => void; user: User; orgs: any[] }) {
  const qc = useQueryClient();
  const tags = useTags();
  const colors = tags.data?.colors ?? [];
  const [name, setName] = useState("");
  const [color, setColor] = useState("blue");
  const [org, setOrg] = useState<string | null>(null);
  const refresh = () => { qc.invalidateQueries({ queryKey: ["tags"] }); qc.invalidateQueries({ queryKey: ["projects"] }); };
  async function create() {
    try {
      await api("/tags", { body: { name, color, organization_id: org ? Number(org) : null } });
      setName(""); ok(t("Etiket oluşturuldu")); refresh();
    } catch (e) { fail(e); }
  }
  async function recolor(tg: Tag, c: string) {
    try { await api(`/tags/${tg.id}`, { method: "PATCH", body: { color: c } }); refresh(); } catch (e) { fail(e); }
  }
  async function remove(tg: Tag) {
    if (!confirm(t("\"{name}\" etiketi silinsin mi? {n} projeden kaldırılacak.", { name: tg.name, n: tg.projects }))) return;
    try { await api(`/tags/${tg.id}`, { method: "DELETE" }); refresh(); } catch (e) { fail(e); }
  }
  const canEdit = (tg: Tag) => (tg.builtin ? user.role === "admin" : user.role !== "customer" || tg.organization_id === user.organization_id);
  return (
    <Modal opened={opened} onClose={onClose} title={t("Etiketleri yönet")} size="lg">
      <Stack>
        <Text size="sm" c="dimmed">{t("Etiketler projeleri türüne veya ekibe göre ayırmanızı sağlar. Yerleşik etiketler: Web, Mobil, API, Kaynak kod.")}</Text>
        <Group align="flex-end" wrap="nowrap">
          <TextInput label={t("Yeni etiket")} placeholder={t("ör. Ödeme, İç sistem, PCI")} value={name} onChange={(e) => setName(e.currentTarget.value)} maxLength={40} style={{ flex: 1 }} />
          {user.role !== "customer" && (
            <TextInput component="select" label={t("Kapsam")} value={org ?? ""} onChange={(e: any) => setOrg(e.currentTarget.value || null)} w={180}>
              <option value="">{t("Tüm organizasyonlar")}</option>
              {orgs.map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}
            </TextInput>
          )}
          <Button onClick={create} disabled={!name.trim()}>{t("Oluştur")}</Button>
        </Group>
        <Group gap={6}>
          {colors.map((c) => (
            <Tooltip key={c} label={c}><ColorSwatch component="button" type="button" color={`var(--mantine-color-${c}-6)`} size={22} onClick={() => setColor(c)} style={{ cursor: "pointer" }}>
              {color === c && <CheckIcon size={10} color="white" />}</ColorSwatch></Tooltip>
          ))}
        </Group>
        <Table verticalSpacing={6}>
          <Table.Tbody>
            {(tags.data?.items ?? []).map((tg) => (
              <Table.Tr key={tg.id}>
                <Table.Td><TagBadge tag={tg} /></Table.Td>
                <Table.Td><Text size="xs" c="dimmed">{tg.builtin ? t("Yerleşik") : tg.organization ?? t("Tüm organizasyonlar")}</Text></Table.Td>
                <Table.Td><Text size="xs" c="dimmed">{t("{n} proje", { n: tg.projects })}</Text></Table.Td>
                <Table.Td>{canEdit(tg) && <Group gap={3}>{colors.map((c) => <ColorSwatch key={c} component="button" type="button" size={12} color={`var(--mantine-color-${c}-6)`} onClick={() => recolor(tg, c)} style={{ cursor: "pointer", opacity: c === tg.color ? 1 : 0.45 }} />)}</Group>}</Table.Td>
                <Table.Td ta="right">{canEdit(tg) && !tg.builtin && <ActionIcon variant="subtle" color="red" onClick={() => remove(tg)} aria-label={t("Sil")}><IconTrash size={14} /></ActionIcon>}</Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Stack>
    </Modal>
  );
}
