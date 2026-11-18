import { Button, Group, Modal, MultiSelect, Select, Stack, Text, Textarea, TextInput } from "@mantine/core";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { api } from "../api";
import { t } from "../i18n";
import { fail, ok } from "./ui";

function usePeople(findingId?: number) {
  return useQuery<any[]>({ queryKey: ["directory", "finding", findingId ?? 0], queryFn: () => api(`/directory${findingId ? `?finding_id=${findingId}` : ""}`) });
}
const label = (u: any) => (u.name ? `${u.name} — ${u.email}` : u.email);

export function AssignModal({ opened, onClose, ids, findingId, current }: { opened: boolean; onClose: () => void; ids?: number[]; findingId?: number; current?: any }) {
  const qc = useQueryClient();
  const people = usePeople(findingId ?? ids?.[0]);
  const [who, setWho] = useState<string | null>(null);
  const [due, setDue] = useState("");
  const [note, setNote] = useState("");
  useEffect(() => { if (opened) { setWho(current?.assignee ? String(current.assignee.id) : null); setDue(current?.due_date?.slice(0, 10) ?? ""); setNote(""); } }, [opened]);
  async function save() {
    const body = { assignee_id: who ? Number(who) : null, due_date: due ? `${due}T00:00:00Z` : null, note };
    try {
      if (findingId) await api(`/findings/${findingId}/assign`, { method: "PATCH", body });
      else await api("/findings/assign", { body: { ...body, ids } });
      ok(who ? t("Atandı") : t("Atama kaldırıldı"));
      qc.invalidateQueries({ queryKey: ["findings"] });
      if (findingId) qc.invalidateQueries({ queryKey: ["finding", findingId] });
      onClose();
    } catch (e) { fail(e); }
  }
  return (
    <Modal opened={opened} onClose={onClose} title={ids ? t("{n} bulguyu ata", { n: ids.length }) : t("Bulguyu ata")}>
      <Stack>
        <Select label={t("Kime")} placeholder={t("Kişi seçin")} searchable clearable data={(people.data ?? []).map((u) => ({ value: String(u.id), label: label(u) }))} value={who} onChange={setWho}
          description={t("Yalnızca bu bulguyu görebilen kişiler listelenir.")} />
        <TextInput type="date" label={t("Son tarih (isteğe bağlı)")} value={due} onChange={(e) => setDue(e.currentTarget.value)} w={220} />
        <Textarea label={t("Not (isteğe bağlı)")} placeholder={t("ör. Bir sonraki sürümde yükseltelim")} value={note} onChange={(e) => setNote(e.currentTarget.value)} maxLength={1000} />
        <Text size="xs" c="dimmed">{t("Atanan kişiye uygulama içi bildirim gönderilir.")}</Text>
        <Group justify="flex-end">
          {current?.assignee && <Button variant="subtle" color="red" onClick={async () => {
            try { await api(`/findings/${findingId}/assign`, { method: "PATCH", body: { assignee_id: null } }); ok(t("Atama kaldırıldı"));
              qc.invalidateQueries({ queryKey: ["findings"] }); qc.invalidateQueries({ queryKey: ["finding", findingId] }); onClose(); } catch (e) { fail(e); } }}>{t("Atamayı kaldır")}</Button>}
          <Button onClick={save}>{t("Kaydet")}</Button>
        </Group>
      </Stack>
    </Modal>
  );
}

export function ShareModal({ opened, onClose, findingId }: { opened: boolean; onClose: () => void; findingId: number }) {
  const qc = useQueryClient();
  const people = usePeople(findingId);
  const [who, setWho] = useState<string[]>([]);
  const [msg, setMsg] = useState("");
  async function send() {
    try {
      await api(`/findings/${findingId}/share`, { body: { user_ids: who.map(Number), message: msg } });
      ok(t("Paylaşıldı"));
      qc.invalidateQueries({ queryKey: ["finding", findingId] });
      setWho([]); setMsg(""); onClose();
    } catch (e) { fail(e); }
  }
  return (
    <Modal opened={opened} onClose={onClose} title={t("Bulguyu paylaş")}>
      <Stack>
        <MultiSelect label={t("Kişiler")} searchable data={(people.data ?? []).map((u) => ({ value: String(u.id), label: label(u) }))} value={who} onChange={setWho} />
        <Textarea label={t("Mesaj")} placeholder={t("ör. Bu kütüphaneyi bizim serviste de kullanıyor muyuz?")} value={msg} onChange={(e) => setMsg(e.currentTarget.value)} maxLength={2000} autosize minRows={3} />
        <Text size="xs" c="dimmed">{t("Seçilen kişilere bildirim gider; paylaşım bulgunun geçmişine yazılır.")}</Text>
        <Group justify="flex-end"><Button onClick={send} disabled={!who.length}>{t("Paylaş")}</Button></Group>
      </Stack>
    </Modal>
  );
}
