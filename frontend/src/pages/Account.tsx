import { Badge, Button, Card, Grid, Group, Paper, PasswordInput, Stack, Table, Text } from "@mantine/core";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { IconBrowser } from "@tabler/icons-react";
import { api, fmtDate } from "../api";
import { fail, ok, PageHeader } from "../components/ui";
import { t } from "../i18n";
import { ThemeSettings } from "../theme";

function Sessions() {
  const qc = useQueryClient();
  const q = useQuery<any[]>({ queryKey: ["my-sessions"], queryFn: () => api("/auth/sessions") });
  async function end(id: number) {
    try { await api(`/auth/sessions/${id}`, { method: "DELETE" }); ok(t("Oturum sonlandırıldı")); qc.invalidateQueries({ queryKey: ["my-sessions"] }); } catch (e) { fail(e); }
  }
  return (
    <Card withBorder p={0}>
      <Text fw={700} p="md" pb={0}>{t("Etkin oturumlarım")}</Text>
      <Text size="xs" c="dimmed" px="md">{t("Tanımadığınız bir cihaz görürseniz oturumu sonlandırın ve parolanızı değiştirin.")}</Text>
      <Table.ScrollContainer minWidth={520}><Table verticalSpacing="sm" mt="xs">
        <Table.Tbody>
          {(q.data ?? []).map((s) => (
            <Table.Tr key={s.id}>
              <Table.Td><Group gap="xs" wrap="nowrap"><IconBrowser size={16} /><div><Text size="sm">{s.device || t("Bilinmiyor")} {s.current && <Badge size="xs" color="green" variant="light">{t("Bu cihaz")}</Badge>}</Text>
                <Text size="xs" c="dimmed" ff="monospace">{s.ip}</Text></div></Group></Table.Td>
              <Table.Td><Text size="xs" c="dimmed">{t("Son etkinlik")}</Text><Text size="sm">{fmtDate(s.last_seen_at)}</Text></Table.Td>
              <Table.Td ta="right">{!s.current && <Button size="xs" variant="subtle" color="red" onClick={() => end(s.id)}>{t("Sonlandır")}</Button>}</Table.Td>
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table></Table.ScrollContainer>
    </Card>
  );
}

export default function Account() {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const nav = useNavigate();
  async function save() {
    try {
      await api("/auth/password", { body: { current, new: next } });
      ok(t("Parola değişti; yeniden giriş yapın"));
      nav("/login");
    } catch (e) { fail(e); }
  }
  return (
    <>
      <PageHeader title={t("Hesabım")} sub={t("Parola ve oturum güvenliği")} />
      <Grid>
        <Grid.Col span={{ base: 12, md: 5 }}>
          <Paper withBorder p="lg">
            <Stack>
              <Text fw={700}>{t("Parola değiştir")}</Text>
              <Text size="xs" c="dimmed">{t("En az 10 karakter; yalnızca harf ya da yalnızca rakam olamaz.")}</Text>
              <PasswordInput label={t("Mevcut parola")} value={current} onChange={(e) => setCurrent(e.currentTarget.value)} />
              <PasswordInput label={t("Yeni parola")} value={next} onChange={(e) => setNext(e.currentTarget.value)} />
              <Button onClick={save} disabled={!current || next.length < 10}>{t("Kaydet")}</Button>
            </Stack>
          </Paper>
          <Paper withBorder p="lg" mt="md"><Text fw={700} mb="sm">{t("Tema")}</Text><ThemeSettings /></Paper>
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 7 }}><Sessions /></Grid.Col>
      </Grid>
    </>
  );
}
