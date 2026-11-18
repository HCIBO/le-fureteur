import { ActionIcon, Anchor, Avatar, Badge, Button, Card, Drawer, Group, Modal, SimpleGrid, Stack, Table, TagsInput, Text, TextInput, Textarea, ThemeIcon } from "@mantine/core";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { IconBuilding, IconFolders, IconMail, IconPencil, IconPlus, IconSearch, IconTrash, IconUsers, IconUsersGroup } from "@tabler/icons-react";
import { Link } from "react-router-dom";
import { api, ROLE_LABEL, User, fmtDay } from "../api";
import { fail, ok, OpenCounts, PageHeader } from "../components/ui";
import { PageIntro } from "../components/PageIntro";
import { DueBadge, fromInput, ProjectStatusBadge } from "../components/ProjectStatus";
import { OrgChart } from "../components/OrgChart";
import { t } from "../i18n";

const EMPTY = { name: "", allowed_domains: [] as string[], notes: "", tags: [] as string[], industry: "", contact_name: "", contact_email: "", contract_end: null as string | null };

function Overview({ id }: { id: number }) {
  const q = useQuery<any>({ queryKey: ["org-overview", id], queryFn: () => api(`/orgs/${id}/overview`) });
  if (!q.data) return null;
  const { org, projects, teams, users } = q.data;
  return (
    <Stack>
      <Card withBorder>
        <Group gap="sm" mb="xs"><ThemeIcon size={40} radius="md" variant="light"><IconBuilding size={22} /></ThemeIcon>
          <div><Text fw={800} size="lg">{org.name}</Text><Text size="xs" c="dimmed">{org.industry || t("Sektör belirtilmedi")} · {t("Müşteri")} {fmtDay(org.created_at)}</Text></div></Group>
        <Group gap={4} mb="sm">{org.tags.map((x: string) => <Badge key={x} variant="light" color="grape" tt="none">{x}</Badge>)}</Group>
        <SimpleGrid cols={2} spacing="xs">
          <div><Text size="xs" c="dimmed">{t("İletişim")}</Text><Text size="sm">{org.contact_name || "—"}</Text>{org.contact_email && <Anchor size="xs" href={`mailto:${org.contact_email}`}>{org.contact_email}</Anchor>}</div>
          <div><Text size="xs" c="dimmed">{t("Sözleşme bitişi")}</Text>{org.contract_end ? <DueBadge due={org.contract_end} /> : <Text size="sm">—</Text>}</div>
          <div><Text size="xs" c="dimmed">{t("İzinli alan adları")}</Text><Group gap={4}>{org.allowed_domains.map((d: string) => <Badge key={d} size="sm" variant="outline" tt="none">{d}</Badge>)}{!org.allowed_domains.length && <Text size="sm">—</Text>}</Group></div>
          <div><Text size="xs" c="dimmed">{t("Açık bulgular")}</Text><OpenCounts open={org.open} /></div>
        </SimpleGrid>
        {org.notes && <Text size="sm" c="dimmed" mt="sm" style={{ whiteSpace: "pre-wrap" }}>{org.notes}</Text>}
      </Card>
      <Card withBorder p={0}>
        <Group p="sm" gap="xs"><IconFolders size={16} /><Text fw={700} size="sm">{t("Projeler")} ({projects.length})</Text></Group>
        <Table verticalSpacing="xs">
          <Table.Tbody>
            {projects.map((p: any) => (
              <Table.Tr key={p.id}>
                <Table.Td><Anchor component={Link} to={`/projects/${p.id}`} size="sm" fw={600}>{p.name}</Anchor></Table.Td>
                <Table.Td><ProjectStatusBadge s={p.status} /></Table.Td>
                <Table.Td><DueBadge due={p.due_date} done={p.status === "done"} /></Table.Td>
                <Table.Td><OpenCounts open={p.open} /></Table.Td>
              </Table.Tr>
            ))}
            {!projects.length && <Table.Tr><Table.Td><Text size="sm" c="dimmed">{t("Proje yok")}</Text></Table.Td></Table.Tr>}
          </Table.Tbody>
        </Table>
      </Card>
      {teams.map((tm: any) => (
        <Card withBorder key={tm.id}>
          <Group justify="space-between" mb="xs"><Group gap="xs"><IconUsersGroup size={16} /><Text fw={700} size="sm">{tm.name}</Text></Group>
            <Anchor component={Link} to={`/teams/${tm.id}`} size="xs">{t("Takımı incele")} →</Anchor></Group>
          <OrgChart members={tm.members} />
        </Card>
      ))}
      <Card withBorder>
        <Group gap="xs" mb="xs"><IconUsers size={16} /><Text fw={700} size="sm">{t("Kullanıcılar")} ({users.length})</Text></Group>
        <Group gap="xs">{users.map((u: any) => <Badge key={u.id} variant="light" color="gray" tt="none" leftSection={<Avatar size={14} radius="xl">{u.email[0].toUpperCase()}</Avatar>}>{u.name || u.email} · {ROLE_LABEL[u.role]}</Badge>)}</Group>
      </Card>
    </Stack>
  );
}

export default function Orgs({ user }: { user: User }) {
  const qc = useQueryClient();
  const orgs = useQuery<any[]>({ queryKey: ["orgs"], queryFn: () => api("/orgs") });
  const [edit, setEdit] = useState<any | null>(null);
  const [view, setView] = useState<number | null>(null);
  const [q, setQ] = useState("");
  const [tag, setTag] = useState<string | null>(null);
  const admin = user.role === "admin";
  async function save() {
    try {
      const { id, name, allowed_domains, notes, tags, industry, contact_name, contact_email, contract_end } = edit;
      const body = { name, allowed_domains, notes, tags, industry, contact_name, contact_email, contract_end };
      if (id) await api(`/orgs/${id}`, { method: "PATCH", body }); else await api("/orgs", { body });
      qc.invalidateQueries({ queryKey: ["orgs"] }); qc.invalidateQueries({ queryKey: ["org-overview"] });
      setEdit(null); ok(t("Kaydedildi"));
    } catch (e) { fail(e); }
  }
  async function remove(o: any) {
    if (!confirm(t("\"{name}\" organizasyonu; tüm projeleri, hedefleri ve bulgularıyla silinsin mi?", { name: o.name }))) return;
    try { await api(`/orgs/${o.id}`, { method: "DELETE" }); qc.invalidateQueries({ queryKey: ["orgs"] }); } catch (e) { fail(e); }
  }
  const all = orgs.data ?? [];
  const tags = [...new Set(all.flatMap((o) => o.tags))].sort();
  const rows = all.filter((o) => (!q || `${o.name} ${o.industry} ${o.contact_name}`.toLocaleLowerCase().includes(q.toLocaleLowerCase())) && (!tag || o.tags.includes(tag)));
  return (
    <>
      <PageHeader title={t("Organizasyonlar")} sub={t("Müşteri kurumlar, iletişim bilgileri ve kapsamları")}
        right={admin && <Button leftSection={<IconPlus size={16} />} onClick={() => setEdit({ ...EMPTY })}>{t("Yeni organizasyon")}</Button>} />
      <PageIntro id="orgs" guide="roles"
        text={t("Her müşteri kurum bir organizasyondur. Müşteri kullanıcıları yalnızca kendi organizasyonlarının projelerini, bulgularını ve takımlarını görür; web taramasını yalnızca izinli alan adlarında başlatabilir.")}
        points={[t("Etiketlerle kurumları gruplayın (ör. Bankacılık, KVKK, Öncelikli) ve listeyi süzün."), t("Satıra tıklayınca projeleri, takım şemasını ve kullanıcıları tek ekranda görürsünüz.")]} />
      <Group mb="md" gap="sm">
        <TextInput placeholder={t("Ara")} leftSection={<IconSearch size={16} />} value={q} onChange={(e) => setQ(e.currentTarget.value)} w={240} />
        {tags.map((x) => <Badge key={x} size="lg" tt="none" variant={tag === x ? "filled" : "light"} color="grape" style={{ cursor: "pointer" }} onClick={() => setTag(tag === x ? null : x)}>{x}</Badge>)}
      </Group>
      <Card withBorder p={0}>
        <Table.ScrollContainer minWidth={820}><Table verticalSpacing="sm" highlightOnHover>
          <Table.Thead><Table.Tr><Table.Th>{t("Ad")}</Table.Th><Table.Th>{t("Etiketler")}</Table.Th><Table.Th>{t("İletişim")}</Table.Th><Table.Th>{t("Proje")}</Table.Th><Table.Th>{t("Açık bulgular")}</Table.Th><Table.Th /></Table.Tr></Table.Thead>
          <Table.Tbody>
            {rows.map((o) => (
              <Table.Tr key={o.id} style={{ cursor: "pointer" }} onClick={() => setView(o.id)}>
                <Table.Td><Text fw={600}>{o.name}</Text><Text size="xs" c="dimmed">{o.industry || "—"} · {t("{n} kullanıcı", { n: o.users })}</Text></Table.Td>
                <Table.Td><Group gap={4}>{o.tags.map((x: string) => <Badge key={x} size="sm" variant="light" color="grape" tt="none">{x}</Badge>)}</Group></Table.Td>
                <Table.Td>{o.contact_name || o.contact_email ? <><Text size="sm">{o.contact_name}</Text><Group gap={4}>{o.contact_email && <IconMail size={12} />}<Text size="xs" c="dimmed">{o.contact_email}</Text></Group></> : <Text size="xs" c="dimmed">—</Text>}</Table.Td>
                <Table.Td>{o.projects}</Table.Td>
                <Table.Td><OpenCounts open={o.open} /></Table.Td>
                <Table.Td ta="right" onClick={(e) => e.stopPropagation()}>{admin && <Group gap={4} justify="flex-end" wrap="nowrap">
                  <ActionIcon variant="subtle" onClick={() => setEdit({ ...EMPTY, ...o })} aria-label={t("Düzenle")}><IconPencil size={16} /></ActionIcon>
                  <ActionIcon variant="subtle" color="red" onClick={() => remove(o)} aria-label={t("Sil")}><IconTrash size={16} /></ActionIcon></Group>}</Table.Td>
              </Table.Tr>
            ))}
            {!rows.length && <Table.Tr><Table.Td colSpan={6}><Text c="dimmed" ta="center" py="lg">{all.length ? t("Filtreye uyan organizasyon yok") : t("Henüz organizasyon yok")}</Text></Table.Td></Table.Tr>}
          </Table.Tbody>
        </Table></Table.ScrollContainer>
      </Card>
      <Drawer opened={view !== null} onClose={() => setView(null)} position="right" size="xl" title={<Text fw={600}>{t("Organizasyon ayrıntısı")}</Text>}>
        {view !== null && <Overview id={view} />}
      </Drawer>
      <Modal opened={edit !== null} onClose={() => setEdit(null)} title={edit?.id ? t("Organizasyonu düzenle") : t("Yeni organizasyon")} size="lg">
        {edit && <Stack>
          <Group grow>
            <TextInput label={t("Ad")} required value={edit.name} onChange={(e) => setEdit({ ...edit, name: e.currentTarget.value })} />
            <TextInput label={t("Sektör")} placeholder={t("ör. Bankacılık")} value={edit.industry} onChange={(e) => setEdit({ ...edit, industry: e.currentTarget.value })} />
          </Group>
          <TagsInput label={t("Etiketler")} description={t("Enter ile ekleyin")} value={edit.tags} onChange={(v) => setEdit({ ...edit, tags: v })} data={tags} maxTags={20} />
          <Group grow>
            <TextInput label={t("İletişim kişisi")} value={edit.contact_name} onChange={(e) => setEdit({ ...edit, contact_name: e.currentTarget.value })} />
            <TextInput label={t("İletişim e-postası")} type="email" value={edit.contact_email} onChange={(e) => setEdit({ ...edit, contact_email: e.currentTarget.value })} />
            <TextInput label={t("Sözleşme bitişi")} type="date" value={edit.contract_end ? edit.contract_end.slice(0, 10) : ""} onChange={(e) => setEdit({ ...edit, contract_end: fromInput(e.currentTarget.value) })} />
          </Group>
          <TagsInput label={t("İzinli alan adları")} description={t("ornek.com veya *.ornek.com (Enter ile ekleyin)")} value={edit.allowed_domains} onChange={(v) => setEdit({ ...edit, allowed_domains: v })} />
          <Textarea label={t("Notlar")} value={edit.notes} onChange={(e) => setEdit({ ...edit, notes: e.currentTarget.value })} autosize minRows={2} />
          <Group justify="flex-end"><Button onClick={save} disabled={!edit.name}>{t("Kaydet")}</Button></Group>
        </Stack>}
      </Modal>
    </>
  );
}
