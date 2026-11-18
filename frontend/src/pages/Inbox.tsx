import { Button, Card, Group, SegmentedControl, Stack, Text, ThemeIcon } from "@mantine/core";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { IconBellOff } from "@tabler/icons-react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";
import { t } from "../i18n";
import { PageHeader } from "../components/ui";
import { InboxItem, InboxRow } from "../components/Inbox";

export default function InboxPage() {
  const qc = useQueryClient();
  const nav = useNavigate();
  const [filter, setFilter] = useState("all");
  const items = useQuery<InboxItem[]>({ queryKey: ["inbox", filter], queryFn: () => api(`/inbox?limit=200${filter === "unread" ? "&unread=true" : ""}`) });
  const refresh = () => { qc.invalidateQueries({ queryKey: ["inbox"] }); qc.invalidateQueries({ queryKey: ["inbox-count"] }); };
  async function open(n: InboxItem) {
    if (!n.read) await api("/inbox/read", { body: { ids: [n.id] } }).catch(() => undefined);
    refresh();
    if (n.link) nav(n.link);
  }
  return (
    <>
      <PageHeader title={t("Bildirimler")} sub={t("Size atanan bulgular, paylaşımlar, onay istekleri ve anmalar")}
        right={<Group><SegmentedControl size="xs" value={filter} onChange={setFilter} data={[{ value: "all", label: t("Tümü") }, { value: "unread", label: t("Okunmamış") }]} />
          <Button variant="default" size="xs" onClick={async () => { await api("/inbox/read", { body: { all: true } }); refresh(); }}>{t("Tümünü okundu say")}</Button></Group>} />
      <Card withBorder p="xs">
        <Stack gap={4}>
          {(items.data ?? []).map((n) => <InboxRow key={n.id} n={n} onOpen={open} />)}
          {items.data?.length === 0 && (
            <Stack align="center" py={40} gap={6}>
              <ThemeIcon size={48} radius="xl" variant="light" color="gray"><IconBellOff size={24} /></ThemeIcon>
              <Text c="dimmed">{t("Bildirim yok")}</Text>
            </Stack>
          )}
        </Stack>
      </Card>
    </>
  );
}
