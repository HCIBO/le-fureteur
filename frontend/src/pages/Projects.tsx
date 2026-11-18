import { Anchor, Button, Card, Chip, SimpleGrid, Group, Modal, Select, Stack, Table, Text, TextInput, Textarea, ThemeIcon } from "@mantine/core";
import { BulkBar, useSelection } from "../components/Bulk";
import { useDisclosure } from "@mantine/hooks";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { IconFolderPlus, IconSearch, IconTags } from "@tabler/icons-react";
import { api, User } from "../api";
import { fail, OpenCounts, PageHeader } from "../components/ui";
import { PageIntro } from "../components/PageIntro";
import { DueBadge, PROJECT_STATUS, ProjectPlanFields, ProjectStatusBadge } from "../components/ProjectStatus";
import { TagBadge, TagManager, TagPicker, tagLabel, useTags } from "../components/Tags";
import { t, LANGS } from "../i18n";

export default function Projects({ user }: { user: User }) {
  const qc = useQueryClient();
  const nav = useNavigate();
  const projects = useQuery<any[]>({ queryKey: ["projects"], queryFn: () => api("/projects") });
  const orgs = useQuery<any[]>({ queryKey: ["orgs"], queryFn: () => api("/orgs") });
  const pick = useSelection();
  const tags = useTags();
  const [opened, { open, close }] = useDisclosure();
  const [tagsOpen, setTagsOpen] = useState(false);
  const [form, setForm] = useState({ organization_id: "", name: "", description: "", report_lang: "tr", tag_ids: [] as number[], plan: { status: "active", due_date: null as string | null, owner_id: null as string | null } });
  const [q, setQ] = useState("");
  const [tagFilter, setTagFilter] = useState<string[]>([]);
  const [stFilter, setStFilter] = useState<string | null>(null);

  async function create() {
    try {
      const { plan, ...rest } = form;
      const p = await api("/projects", { body: { ...rest, organization_id: form.organization_id ? Number(form.organization_id) : null, status: plan.status, due_date: plan.due_date, owner_id: plan.owner_id ? Number(plan.owner_id) : null } });
      qc.invalidateQueries({ queryKey: ["projects"] });
      close();
      nav(`/projects/${p.id}`);
    } catch (e) { fail(e); }
  }
  const rows = (projects.data ?? []).filter((p) =>
    (!q || `${p.name} ${p.description} ${p.organization}`.toLocaleLowerCase().includes(q.toLocaleLowerCase())) &&
    tagFilter.every((id) => p.tags.some((tg: any) => String(tg.id) === id)) &&
    (!stFilter || (stFilter === "late" ? p.status !== "done" && p.due_date && new Date(p.due_date) < new Date() : p.status === stFilter)));
  const all = projects.data ?? [];
  const lateCount = all.filter((p) => p.status !== "done" && p.due_date && new Date(p.due_date) < new Date()).length;
  const usedTags = (tags.data?.items ?? []).filter((tg) => tg.projects > 0);
  const orgId = user.role === "customer" ? user.organization_id : (form.organization_id ? Number(form.organization_id) : null);
  const empty = projects.data?.length === 0;

  return (
    <>
      <PageHeader title={t("Projeler")} sub={t("Her proje bir veya daha fazla hedef (web adresi ya da yüklenen dosya) içerir.")}
        right={<Group><Button variant="default" leftSection={<IconTags size={16} />} onClick={() => setTagsOpen(true)}>{t("Etiketler")}</Button>
          <Button leftSection={<IconFolderPlus size={16} />} onClick={() => { setForm({ organization_id: "", name: "", description: "", report_lang: "tr", tag_ids: [], plan: { status: "active", due_date: null, owner_id: null } }); open(); }}>{t("Yeni proje")}</Button></Group>} />
      <PageIntro id="projects" guide="start"
        text={t("Proje, aynı uygulamaya ait hedefleri bir arada tutar: örneğin bir web sitesi, onun mobil uygulaması ve API'si. Bulgular, raporlar ve CI politikası proje düzeyinde yönetilir.")}
        points={[t("Etiketlerle projeleri ayırın (Web, Mobil, API, Kaynak kod veya kendi etiketleriniz) ve listeyi süzün."), t("Projeye girip \"Hedef ekle\" ile web adresi ya da dosya (kaynak kod, APK, IPA, imaj) ekleyin.")]} />

      {!empty && (
        <SimpleGrid cols={{ base: 2, sm: 5 }} mb="md">
          {[...Object.entries(PROJECT_STATUS).map(([k, v]) => ({ k, label: v.label, color: v.color, n: all.filter((p) => p.status === k).length })),
            { k: "late", label: t("Gecikmiş"), color: "red", n: lateCount }].map((x) => (
            <Card key={x.k} withBorder padding="sm" style={{ cursor: "pointer", borderColor: stFilter === x.k ? `var(--mantine-color-${x.color}-6)` : undefined, borderTop: `3px solid var(--mantine-color-${x.color}-6)` }}
              onClick={() => setStFilter(stFilter === x.k ? null : x.k)}>
              <Text size="xs" c="dimmed">{x.label}</Text><Text fw={800} size="xl" c={x.k === "late" && x.n ? "red" : undefined}>{x.n}</Text>
            </Card>
          ))}
        </SimpleGrid>
      )}
      {!empty && (
        <Group mb="md" align="center" gap="sm">
          <TextInput placeholder={t("Proje ara")} leftSection={<IconSearch size={16} />} value={q} onChange={(e) => setQ(e.currentTarget.value)} w={260} />
          {usedTags.length > 0 && (
            <Chip.Group multiple value={tagFilter} onChange={setTagFilter}>
              <Group gap={6}>{usedTags.map((tg) => <Chip key={tg.id} value={String(tg.id)} size="xs" color={tg.color} variant="light">{tagLabel(tg)} · {tg.projects}</Chip>)}</Group>
            </Chip.Group>
          )}
        </Group>
      )}

      {empty ? (
        <Card withBorder py={48}>
          <Stack align="center" gap="xs">
            <ThemeIcon size={56} radius="xl" variant="light" color="indigo"><IconFolderPlus size={30} /></ThemeIcon>
            <Text fw={600} size="lg">{t("Henüz proje yok")}</Text>
            <Text c="dimmed" size="sm" ta="center" maw={460}>{t("İlk projenizi oluşturun, ardından taranacak web adresini veya dosyaları ekleyin. Tarama birkaç dakika içinde bulguları ve raporu hazırlar.")}</Text>
            <Button mt="sm" leftSection={<IconFolderPlus size={16} />} onClick={open}>{t("İlk projeni oluştur")}</Button>
          </Stack>
        </Card>
      ) : (
        <>
        <BulkBar kind="projects" ids={pick.ids} user={user} onClear={pick.clear} onDone={() => qc.invalidateQueries({ queryKey: ["projects"] })} />
        <Card withBorder p={0}>
          <Table.ScrollContainer minWidth={720}><Table highlightOnHover verticalSpacing="sm">
            <Table.Thead><Table.Tr><Table.Th w={36}>{pick.header(rows.map((p) => p.id))}</Table.Th><Table.Th>{t("Proje")}</Table.Th><Table.Th>{t("Durum")}</Table.Th><Table.Th>{t("Son tarih")}</Table.Th><Table.Th>{t("Etiketler")}</Table.Th><Table.Th>{t("Organizasyon")}</Table.Th><Table.Th>{t("Hedefler")}</Table.Th><Table.Th>{t("Açık bulgular")}</Table.Th></Table.Tr></Table.Thead>
            <Table.Tbody>
              {rows.map((p) => (
                <Table.Tr key={p.id} style={{ cursor: "pointer" }} onClick={() => nav(`/projects/${p.id}`)} bg={pick.sel.has(p.id) ? "var(--mantine-color-indigo-light)" : undefined}>
                  <Table.Td>{pick.cell(p.id)}</Table.Td>
                  <Table.Td><Anchor component={Link} to={`/projects/${p.id}`} fw={600} onClick={(e) => e.stopPropagation()}>{p.name}</Anchor><Text size="xs" c="dimmed" lineClamp={1}>{p.description}</Text></Table.Td>
                  <Table.Td><ProjectStatusBadge s={p.status} />{p.owner && <Text size="xs" c="dimmed" mt={2}>{p.owner.name || p.owner.email}</Text>}</Table.Td>
                  <Table.Td><DueBadge due={p.due_date} done={p.status === "done"} /></Table.Td>
                  <Table.Td><Group gap={4}>{p.tags.map((tg: any) => <TagBadge key={tg.id} tag={tg} size="xs" />)}</Group></Table.Td>
                  <Table.Td>{p.organization}</Table.Td><Table.Td>{p.targets}</Table.Td><Table.Td><OpenCounts open={p.open} /></Table.Td>
                </Table.Tr>
              ))}
              {rows.length === 0 && <Table.Tr><Table.Td colSpan={8}><Text c="dimmed" ta="center" py="lg">{t("Filtreye uyan proje yok")}</Text></Table.Td></Table.Tr>}
            </Table.Tbody>
          </Table></Table.ScrollContainer>
        </Card>
        </>
      )}

      <Modal opened={opened} onClose={close} title={t("Yeni proje")}>
        <Stack>
          {user.role !== "customer" && (
            <Select label={t("Organizasyon")} required data={(orgs.data ?? []).map((o) => ({ value: String(o.id), label: o.name }))} value={form.organization_id} onChange={(v) => setForm({ ...form, organization_id: v ?? "", tag_ids: [] })} />
          )}
          <TextInput label={t("Ad")} required placeholder={t("ör. Müşteri portalı")} value={form.name} onChange={(e) => setForm({ ...form, name: e.currentTarget.value })} />
          <TagPicker value={form.tag_ids} onChange={(v) => setForm({ ...form, tag_ids: v })} orgId={orgId} />
          <ProjectPlanFields orgId={orgId} value={form.plan} onChange={(v) => setForm({ ...form, plan: v })} />
          <Textarea label={t("Açıklama")} value={form.description} onChange={(e) => setForm({ ...form, description: e.currentTarget.value })} />
          <Select label={t("Rapor dili")} data={LANGS} value={form.report_lang} onChange={(v) => setForm({ ...form, report_lang: v ?? "tr" })} />
          <Group justify="flex-end"><Button onClick={create} disabled={!form.name || (user.role !== "customer" && !form.organization_id)}>{t("Oluştur")}</Button></Group>
        </Stack>
      </Modal>
      <TagManager opened={tagsOpen} onClose={() => setTagsOpen(false)} user={user} orgs={orgs.data ?? []} />
    </>
  );
}
