import { Anchor, Badge, Button, Card, Group, MultiSelect, Stack, Switch, Table, Tabs, TagsInput, Text, TextInput, Textarea, Select } from "@mantine/core";
import { IconPlayerPlay } from "@tabler/icons-react";
import { BulkBar, useSelection } from "../components/Bulk";
import { TrendCard } from "../components/TrendCard";
import { ProjectQueueCard } from "../components/QueuePanel";
import { ProjectSchedulesCard } from "../components/Schedules";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, fmtDate, User, SEV_LABEL } from "../api";
import { fail, JobBadge, ok, OpenCounts, PageHeader } from "../components/ui";
import { t, LANGS } from "../i18n";
import { DueBadge, ProjectPlanFields, ProjectStatusBadge } from "../components/ProjectStatus";
import { TagBadge, TagPicker } from "../components/Tags";
import { typeOf } from "../components/TargetTypes";

export default function ProjectDetail({ user }: { user: User }) {
  const pick = useSelection();
  const qcBulk = useQueryClient();
  const { id } = useParams();
  const qc = useQueryClient();
  const nav = useNavigate();
  const project = useQuery<any>({ queryKey: ["project", id], queryFn: () => api(`/projects/${id}`) });
  const targets = useQuery<any[]>({ queryKey: ["targets", id], queryFn: () => api(`/projects/${id}/targets`), refetchInterval: 10000 });
  async function remove() {
    if (!confirm(t("\"{name}\" projesi, hedefleri ve bulgularıyla birlikte silinsin mi?", { name: project.data?.name }))) return;
    try {
      await api(`/projects/${id}`, { method: "DELETE" });
      qc.invalidateQueries({ queryKey: ["projects"] });
      nav("/projects");
    } catch (e) { fail(e); }
  }
  if (!project.data) return null;
  const p = project.data;
  return (
    <>
      <PageHeader title={p.name} sub={<><ProjectStatusBadge s={p.status} /> <DueBadge due={p.due_date} done={p.status === "done"} /> {p.tags?.map((tg: any) => <TagBadge key={tg.id} tag={tg} size="xs" />)} {p.organization}{p.owner ? ` · ${p.owner.name || p.owner.email}` : ""} · <Anchor component={Link} to={`/findings?project_id=${p.id}`} size="sm">{t("bulgular")}</Anchor></>}
        right={<Group><Button variant="default" color="red" onClick={remove}>{t("Projeyi sil")}</Button><Button component={Link} to={`/projects/${p.id}/targets/new`}>{t("Hedef ekle")}</Button></Group>} />
      <Tabs defaultValue="targets">
        <Tabs.List mb="md"><Tabs.Tab value="targets">{t("Hedefler")}</Tabs.Tab><Tabs.Tab value="trend">{t("Eğilim ve sürekli tarama")}</Tabs.Tab><Tabs.Tab value="settings">{t("Proje ayarları")}</Tabs.Tab></Tabs.List>
        <Tabs.Panel value="targets">
          <BulkBar kind="targets" ids={pick.ids} user={user} onClear={pick.clear} onDone={() => qcBulk.invalidateQueries({ queryKey: ["targets", id] })}>
            <Button size="xs" leftSection={<IconPlayerPlay size={14} />} onClick={async () => {
              try {
                const r = await api("/scans/batch", { body: { target_ids: pick.ids } });
                ok(t("{n} tarama kuyruğa alındı", { n: r.started.length }) + (r.errors.length ? t(" · {n} başlatılamadı", { n: r.errors.length }) : ""));
                if (r.errors.length) fail(new Error(r.errors[0].error));
                pick.clear(); qcBulk.invalidateQueries({ queryKey: ["targets", id] });
              } catch (e) { fail(e); }
            }}>{t("Seçilenleri tara")}</Button>
          </BulkBar>
          <Card withBorder p={0}>
            <Table.ScrollContainer minWidth={640}><Table highlightOnHover verticalSpacing="sm">
              <Table.Thead><Table.Tr><Table.Th w={36}>{pick.header((targets.data ?? []).map((x) => x.id))}</Table.Th><Table.Th>{t("Hedef")}</Table.Th><Table.Th>{t("Tür")}</Table.Th><Table.Th>{t("Son tarama")}</Table.Th><Table.Th>{t("Açık bulgular")}</Table.Th></Table.Tr></Table.Thead>
              <Table.Tbody>
                {(targets.data ?? []).map((tg) => (
                  <Table.Tr key={tg.id} bg={pick.sel.has(tg.id) ? "var(--mantine-color-indigo-light)" : undefined}>
                    <Table.Td>{pick.cell(tg.id)}</Table.Td>
                    <Table.Td><Anchor component={Link} to={`/targets/${tg.id}`} fw={600}>{tg.name}</Anchor><Text size="xs" c="dimmed">{tg.kind === "web" ? tg.url : t("{n} dosya", { n: tg.files.length })}</Text></Table.Td>
                    <Table.Td>{(() => { const T = typeOf(tg); return <Badge leftSection={<T.icon size={12} />} variant="light" color={T.color} tt="none">{T.title}</Badge>; })()}</Table.Td>
                    <Table.Td>{tg.last_scan ? <Group gap="xs"><JobBadge status={tg.last_scan.job.status} /><Text size="xs">{fmtDate(tg.last_scan.created_at)}</Text></Group> : <Text size="sm" c="dimmed">-</Text>}</Table.Td>
                    <Table.Td><OpenCounts open={tg.open} /></Table.Td>
                  </Table.Tr>
                ))}
                {targets.data?.length === 0 && <Table.Tr><Table.Td colSpan={5}><Text c="dimmed" ta="center" py="lg">{t("Hedef ekleyin: web adresi (blackbox) veya kaynak kod / APK / IPA / imaj yükleme (whitebox)")}</Text></Table.Td></Table.Tr>}
              </Table.Tbody>
            </Table></Table.ScrollContainer>
          </Card>
        </Tabs.Panel>
        <Tabs.Panel value="trend">
          <Stack gap="lg"><TrendCard projectId={p.id} /><ProjectSchedulesCard projectId={p.id} /><ProjectQueueCard project={p} staff={user.role === "admin" || user.role === "analyst"} /></Stack>
        </Tabs.Panel>
        <Tabs.Panel value="settings"><ProjectSettings project={p} user={user} /></Tabs.Panel>
      </Tabs>
    </>
  );
}

function ProjectSettings({ project, user: _user }: { project: any; user: User }) {
  const qc = useQueryClient();
  const jiraList = useQuery<any[]>({ queryKey: ["jira-instances"], queryFn: () => api("/jira/instances") });
  const [f, setF] = useState({ name: "", description: "", report_lang: "tr", allowed: [] as string[], review: [] as string[], denied: [] as string[], jira: "", jiraInst: "", ci: { fail_on: "HIGH", fail_on_kev: true, fail_on_malicious: true, fail_on_license: false, new_only: false }, tags: [] as number[], langs: [] as string[], plan: { status: "active", due_date: null as string | null, owner_id: null as string | null } });
  useEffect(() => {
    const lp = project.license_policy ?? {};
    setF({ name: project.name, description: project.description, report_lang: project.report_lang, allowed: lp.allowed ?? [], review: lp.review ?? [], denied: lp.denied ?? [], jira: project.jira_project_key ?? "", jiraInst: project.jira_instance_id ? String(project.jira_instance_id) : "", ci: { ...project.ci_policy }, tags: (project.tags ?? []).map((x: any) => x.id), langs: (project.report_langs ?? []).filter((x: string) => x !== project.report_lang), plan: { status: project.status, due_date: project.due_date, owner_id: project.owner ? String(project.owner.id) : null } });
  }, [project]);
  async function save() {
    try {
      await api(`/projects/${project.id}`, { method: "PATCH", body: { name: f.name, description: f.description, report_lang: f.report_lang, license_policy: { allowed: f.allowed, review: f.review, denied: f.denied }, jira_project_key: f.jira, ...(f.jiraInst !== (project.jira_instance_id ? String(project.jira_instance_id) : "") ? { jira_instance_id: f.jiraInst ? Number(f.jiraInst) : 0 } : {}), ci_policy: f.ci, tag_ids: f.tags, report_langs: f.langs, status: f.plan.status, due_date: f.plan.due_date, owner_id: f.plan.owner_id ? Number(f.plan.owner_id) : null } });
      qc.invalidateQueries({ queryKey: ["project", String(project.id)] });
      qc.invalidateQueries({ queryKey: ["projects"] });
      qc.invalidateQueries({ queryKey: ["tags"] });
      ok(t("Kaydedildi"));
    } catch (e) { fail(e); }
  }
  return (
    <Card withBorder maw={720}>
      <Stack>
        <TextInput label={t("Ad")} value={f.name} onChange={(e) => setF({ ...f, name: e.currentTarget.value })} />
        <Textarea label={t("Açıklama")} value={f.description} onChange={(e) => setF({ ...f, description: e.currentTarget.value })} />
        <ProjectPlanFields orgId={project.organization_id} value={f.plan} onChange={(v) => setF({ ...f, plan: v })} />
        <Group grow align="flex-start">
          <Select label={t("Ana rapor dili")} data={LANGS} value={f.report_lang} onChange={(v) => setF({ ...f, report_lang: v ?? "tr", langs: f.langs.filter((x) => x !== v) })} allowDeselect={false} />
          <MultiSelect label={t("Ek rapor dilleri")} description={t("Her taramada bu dillerde de HTML, PDF, Word ve CSV üretilir")} data={LANGS.filter((l) => l.value !== f.report_lang)} value={f.langs} onChange={(v) => setF({ ...f, langs: v })} clearable />
        </Group>
        <TagPicker value={f.tags} onChange={(v) => setF({ ...f, tags: v })} orgId={project.organization_id} />
        <Select label={t("Varsayılan Jira bağlantısı")} description={t("Bu projenin bulguları için Jira sorulmadan bu bağlantı kullanılır; otomatik kayıtlar da buraya açılır.")} w={300} clearable
          data={(jiraList.data ?? []).map((i: any) => ({ value: String(i.id), label: i.name }))} value={f.jiraInst || null} onChange={(v) => setF({ ...f, jiraInst: v ?? "" })} placeholder={t("Seçilmedi (kullanıcıya sorulur)")} />
        <TextInput label={t("Jira proje anahtarı")} description={t("Boşsa Jira bağlantısındaki proje kullanılır")} placeholder={t("SEC")} value={f.jira} onChange={(e) => setF({ ...f, jira: e.currentTarget.value.toUpperCase() })} w={240} />
        <Text fw={600} mt="sm">{t("CI politikası")}</Text>
        <Text size="xs" c="dimmed">{t("CI/CD taramasında derlemeyi durduracak koşullar. Pipeline'daki parametreler bunların önüne geçer.")}</Text>
        <Group grow align="flex-end">
          <Select label={t("Şu şiddet ve üzerinde kal")} data={[...["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((v) => ({ value: v, label: SEV_LABEL[v] })), { value: "NONE", label: t("Şiddete bakma") }]} value={f.ci.fail_on} onChange={(v) => setF({ ...f, ci: { ...f.ci, fail_on: v ?? "HIGH" } })} allowDeselect={false} />
        </Group>
        <Group>
          <Switch label={t("KEV bulgusunda kal")} checked={f.ci.fail_on_kev} onChange={(e) => setF({ ...f, ci: { ...f.ci, fail_on_kev: e.currentTarget.checked } })} />
          <Switch label={t("Zararlı pakette kal")} checked={f.ci.fail_on_malicious} onChange={(e) => setF({ ...f, ci: { ...f.ci, fail_on_malicious: e.currentTarget.checked } })} />
          <Switch label={t("Yasaklı lisansta kal")} checked={f.ci.fail_on_license} onChange={(e) => setF({ ...f, ci: { ...f.ci, fail_on_license: e.currentTarget.checked } })} />
          <Switch label={t("Yalnızca yeni bulgular")} checked={f.ci.new_only} onChange={(e) => setF({ ...f, ci: { ...f.ci, new_only: e.currentTarget.checked } })} />
        </Group>
        <Text fw={600} mt="sm">{t("Lisans politikası")}</Text>
        <Text size="xs" c="dimmed">{t("SPDX kimlikleri (ör. MIT, GPL-3.0-only, AGPL-3.0-or-later). Boş bırakılırsa varsayılan politika kullanılır.")}</Text>
        <TagsInput label={t("İzinli")} value={f.allowed} onChange={(v) => setF({ ...f, allowed: v })} />
        <TagsInput label={t("İncelenmeli")} value={f.review} onChange={(v) => setF({ ...f, review: v })} />
        <TagsInput label={t("Yasak")} value={f.denied} onChange={(v) => setF({ ...f, denied: v })} />
        <Group justify="flex-end"><Button onClick={save}>{t("Kaydet")}</Button></Group>
      </Stack>
    </Card>
  );
}
