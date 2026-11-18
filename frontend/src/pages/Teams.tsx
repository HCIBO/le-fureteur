import { ActionIcon, Anchor, Avatar, Badge, Button, Card, Group, Modal, SegmentedControl, Select, SimpleGrid, Stack, Table, Text, TextInput, Textarea, ThemeIcon } from "@mantine/core";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { IconArrowRight, IconCrown, IconLayoutGrid, IconPencil, IconPlus, IconSitemap, IconTrash, IconUser, IconUserStar, IconUsersGroup } from "@tabler/icons-react";
import { Link } from "react-router-dom";
import { OrgChart } from "../components/OrgChart";
import { api, User } from "../api";
import { t } from "../i18n";
import { fail, ok, PageHeader } from "../components/ui";
import { PageIntro } from "../components/PageIntro";

const ROLE: Record<string, { label: string; color: string; icon: any }> = {
  manager: { label: t("Yönetici"), color: "red", icon: IconCrown },
  lead: { label: t("Sorumlu"), color: "orange", icon: IconUserStar },
  member: { label: t("Üye"), color: "gray", icon: IconUser },
};

function Person({ m, children }: { m: any; children?: any }) {
  const R = ROLE[m.role];
  return (
    <div>
      <Group gap="xs" wrap="nowrap" py={3}>
        <Avatar size="sm" color={R.color} radius="xl">{(m.user?.email ?? "?")[0].toUpperCase()}</Avatar>
        <div style={{ minWidth: 0 }}><Text size="sm" truncate>{m.user?.name || m.user?.email}</Text>{m.user?.name && <Text size="xs" c="dimmed" truncate>{m.user.email}</Text>}</div>
        <Badge size="xs" variant="light" color={R.color} leftSection={<R.icon size={10} />}>{R.label}</Badge>
      </Group>
      {children && <div style={{ marginLeft: 14, paddingLeft: 12, borderLeft: "2px solid var(--mantine-color-default-border)" }}>{children}</div>}
    </div>
  );
}

function Tree({ team }: { team: any }) {
  const ms = team.members as any[];
  const childrenOf = (uid: number | null) => ms.filter((m) => m.reports_to === uid);
  const shown = new Set<number>();
  const render = (m: any, depth = 0): any => {
    shown.add(m.user.id);
    const kids = depth < 4 ? childrenOf(m.user.id).filter((k) => !shown.has(k.user.id)) : [];
    return <Person key={m.user.id} m={m}>{kids.length ? kids.map((k) => render(k, depth + 1)) : null}</Person>;
  };
  const roots = ms.filter((m) => m.role === "manager" || !m.reports_to || !ms.some((x) => x.user.id === m.reports_to));
  const out = roots.map((m) => render(m));
  const rest = ms.filter((m) => !shown.has(m.user.id));
  return <Stack gap={2}>{out}{rest.map((m) => render(m))}{ms.length === 0 && <Text size="sm" c="dimmed">{t("Henüz üye yok")}</Text>}</Stack>;
}

function TeamEditor({ team, orgs, onClose }: { team: any; orgs: any[]; onClose: () => void }) {
  const qc = useQueryClient();
  const [f, setF] = useState({ name: team?.name ?? "", description: team?.description ?? "", organization_id: team?.organization_id ? String(team.organization_id) : "" });
  const [members, setMembers] = useState<{ user_id: string; role: string; reports_to: string }[]>(
    (team?.members ?? []).map((m: any) => ({ user_id: String(m.user.id), role: m.role, reports_to: m.reports_to ? String(m.reports_to) : "" })));
  const org = f.organization_id || null;
  const people = useQuery<any[]>({ queryKey: ["directory", org], queryFn: () => api(`/directory${org ? `?org_id=${org}` : ""}`) });
  const options = (people.data ?? []).filter((u) => !org ? u.role !== "customer" : true).map((u) => ({ value: String(u.id), label: u.name ? `${u.name} (${u.email})` : u.email }));
  const leaders = members.filter((m) => m.user_id && m.role !== "member").map((m) => ({ value: m.user_id, label: options.find((o) => o.value === m.user_id)?.label ?? m.user_id }));
  async function save() {
    try {
      const body = { name: f.name, description: f.description, organization_id: f.organization_id ? Number(f.organization_id) : null };
      const saved = team?.id ? await api(`/teams/${team.id}`, { method: "PATCH", body }) : await api("/teams", { body });
      await api(`/teams/${saved.id}/members`, { method: "PUT", body: members.filter((m) => m.user_id).map((m) => ({ user_id: Number(m.user_id), role: m.role, reports_to: m.reports_to ? Number(m.reports_to) : null })) });
      qc.invalidateQueries({ queryKey: ["teams"] });
      ok(t("Takım kaydedildi")); onClose();
    } catch (e) { fail(e); }
  }
  return (
    <Stack>
      <Group grow>
        <TextInput label={t("Takım adı")} value={f.name} onChange={(e) => setF({ ...f, name: e.currentTarget.value })} />
        <Select label={t("Organizasyon")} disabled={!!team?.id} data={[{ value: "", label: t("İç takım (danışmanlık)") }, ...orgs.map((o) => ({ value: String(o.id), label: o.name }))]} value={f.organization_id} onChange={(v) => { setF({ ...f, organization_id: v ?? "" }); setMembers([]); }} allowDeselect={false} />
      </Group>
      <Textarea label={t("Açıklama")} value={f.description} onChange={(e) => setF({ ...f, description: e.currentTarget.value })} />
      <Text fw={600} size="sm">{t("Üyeler")}</Text>
      <Table verticalSpacing={4}>
        <Table.Thead><Table.Tr><Table.Th>{t("Kişi")}</Table.Th><Table.Th w={150}>{t("Rol")}</Table.Th><Table.Th>{t("Bağlı olduğu kişi")}</Table.Th><Table.Th w={36} /></Table.Tr></Table.Thead>
        <Table.Tbody>
          {members.map((m, i) => (
            <Table.Tr key={i}>
              <Table.Td><Select size="xs" searchable data={options} value={m.user_id || null} onChange={(v) => setMembers(members.map((x, j) => j === i ? { ...x, user_id: v ?? "" } : x))} /></Table.Td>
              <Table.Td><Select size="xs" data={Object.entries(ROLE).map(([value, r]) => ({ value, label: r.label }))} value={m.role} onChange={(v) => setMembers(members.map((x, j) => j === i ? { ...x, role: v ?? "member", reports_to: v === "manager" ? "" : x.reports_to } : x))} allowDeselect={false} /></Table.Td>
              <Table.Td><Select size="xs" clearable disabled={m.role === "manager"} placeholder="—" data={leaders.filter((l) => l.value !== m.user_id)} value={m.reports_to || null} onChange={(v) => setMembers(members.map((x, j) => j === i ? { ...x, reports_to: v ?? "" } : x))} /></Table.Td>
              <Table.Td><ActionIcon variant="subtle" color="red" onClick={() => setMembers(members.filter((_, j) => j !== i))} aria-label={t("Sil")}><IconTrash size={14} /></ActionIcon></Table.Td>
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
      <Group justify="space-between">
        <Button size="xs" variant="light" leftSection={<IconPlus size={14} />} onClick={() => setMembers([...members, { user_id: "", role: "member", reports_to: "" }])}>{t("Üye ekle")}</Button>
        <Button onClick={save} disabled={!f.name.trim()}>{t("Kaydet")}</Button>
      </Group>
    </Stack>
  );
}

export default function Teams({ user }: { user: User }) {
  const qc = useQueryClient();
  const staff = user.role !== "customer";
  const teams = useQuery<any[]>({ queryKey: ["teams"], queryFn: () => api("/teams") });
  const orgs = useQuery<any[]>({ queryKey: ["orgs"], queryFn: () => api("/orgs") });
  const [edit, setEdit] = useState<any | null | false>(false);
  const [view, setView] = useState<string>(() => { try { return localStorage.getItem("lf_teams_view") ?? "cards"; } catch { return "cards"; } });
  const changeView = (v: string) => { setView(v); try { localStorage.setItem("lf_teams_view", v); } catch {  } };
  async function remove(tm: any) {
    if (!confirm(t("\"{name}\" takımı silinsin mi?", { name: tm.name }))) return;
    try { await api(`/teams/${tm.id}`, { method: "DELETE" }); qc.invalidateQueries({ queryKey: ["teams"] }); } catch (e) { fail(e); }
  }
  return (
    <>
      <PageHeader title={t("Takımlar")} sub={t("Kim kime bağlı, kim onaylar")} right={staff && <Button leftSection={<IconPlus size={16} />} onClick={() => setEdit(null)}>{t("Yeni takım")}</Button>} />
      <PageIntro id="teams" guide="collaboration"
        text={t("Takımlar, bulguların kime atanacağını ve risk kararlarını kimin onaylayacağını belirler. Her takımda yönetici, sorumlular ve onlara bağlı üyeler bulunur.")}
        points={[t("Üyenin onay talepleri bağlı olduğu sorumluya ve takım yöneticisine gider."), t("Takım yöneticileri kararları doğrudan uygulayabilir."), t("Takımları yalnızca yönetici ve analistler düzenleyebilir; böylece kimse kendi kararını kendisi onaylayamaz.")]} />
      {!!teams.data?.length && (
        <Group justify="flex-end" mb="sm">
          <SegmentedControl size="xs" value={view} onChange={changeView} data={[
            { value: "cards", label: <Group gap={4} wrap="nowrap"><IconLayoutGrid size={14} />{t("Kartlar")}</Group> },
            { value: "chart", label: <Group gap={4} wrap="nowrap"><IconSitemap size={14} />{t("Şema")}</Group> }]} />
        </Group>
      )}
      {view === "chart" ? (
        <Stack>
          {(teams.data ?? []).map((tm) => (
            <Card withBorder key={tm.id}>
              <Group justify="space-between" mb="sm">
                <div><Text fw={700}>{tm.name}</Text><Text size="xs" c="dimmed">{tm.organization ?? t("İç takım (danışmanlık)")}</Text></div>
                <Button size="xs" variant="light" component={Link} to={`/teams/${tm.id}`} rightSection={<IconArrowRight size={14} />}>{t("Takımı incele")}</Button>
              </Group>
              <OrgChart members={tm.members} />
            </Card>
          ))}
        </Stack>
      ) : (
      <SimpleGrid cols={{ base: 1, md: 2, xl: 3 }}>
        {(teams.data ?? []).map((tm) => (
          <Card withBorder key={tm.id}>
            <Group justify="space-between" mb="xs" wrap="nowrap">
              <Group gap="xs" wrap="nowrap"><ThemeIcon variant="light" radius="md"><IconUsersGroup size={18} /></ThemeIcon>
                <div><Anchor component={Link} to={`/teams/${tm.id}`} fw={700} c="inherit">{tm.name}</Anchor><Text size="xs" c="dimmed">{tm.organization ?? t("İç takım (danışmanlık)")} · {t("{n} kişi", { n: tm.members.length })}</Text></div></Group>
              {staff && <Group gap={2} wrap="nowrap"><ActionIcon variant="subtle" onClick={() => setEdit(tm)} aria-label={t("Düzenle")}><IconPencil size={16} /></ActionIcon>
                <ActionIcon variant="subtle" color="red" onClick={() => remove(tm)} aria-label={t("Sil")}><IconTrash size={16} /></ActionIcon></Group>}
            </Group>
            {tm.description && <Text size="sm" c="dimmed" mb="xs">{tm.description}</Text>}
            <Tree team={tm} />
            <Anchor component={Link} to={`/teams/${tm.id}`} size="sm" mt="sm" display="block">{t("Takımı incele")} →</Anchor>
          </Card>
        ))}
      </SimpleGrid>
      )}
      {teams.data?.length === 0 && (
        <Card withBorder py={40}><Stack align="center" gap={6}>
          <ThemeIcon size={52} radius="xl" variant="light"><IconUsersGroup size={28} /></ThemeIcon>
          <Text fw={600}>{t("Henüz takım yok")}</Text>
          <Text size="sm" c="dimmed" ta="center" maw={420}>{staff ? t("İlk takımı oluşturun: yöneticiyi, sorumluları ve onlara bağlı üyeleri belirleyin.") : t("Takımlar yöneticiniz tarafından tanımlanır.")}</Text>
          {staff && <Button mt="xs" leftSection={<IconPlus size={16} />} onClick={() => setEdit(null)}>{t("Yeni takım")}</Button>}
        </Stack></Card>
      )}
      <Modal opened={edit !== false} onClose={() => setEdit(false)} title={edit ? t("Takımı düzenle") : t("Yeni takım")} size="xl">
        {edit !== false && <TeamEditor team={edit} orgs={orgs.data ?? []} onClose={() => setEdit(false)} />}
      </Modal>
    </>
  );
}
