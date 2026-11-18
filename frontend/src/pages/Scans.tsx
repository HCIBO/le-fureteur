import { Anchor, Badge, Card, Group, Progress, SegmentedControl, Select, SimpleGrid, Stack, Table, Text, TextInput, ThemeIcon, Tooltip } from "@mantine/core";
import { BulkBar, useSelection } from "../components/Bulk";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { IconCopy, IconRadar, IconSearch, IconShieldLock } from "@tabler/icons-react";
import { Link, useNavigate } from "react-router-dom";
import { api, fmtDate, SEV_COLOR, User } from "../api";
import { JobBadge, PageHeader } from "../components/ui";
import { PageIntro } from "../components/PageIntro";
import { QueuePanel } from "../components/QueuePanel";
import { t } from "../i18n";

function duration(s: any) {
  const a = s.job.started_at, b = s.job.finished_at;
  if (!a || !b) return null;
  const sec = Math.max(0, Math.round((new Date(b).getTime() - new Date(a).getTime()) / 1000));
  return sec < 60 ? t("{n} sn", { n: sec }) : t("{m} dk {s} sn", { m: Math.floor(sec / 60), s: sec % 60 });
}

function SevStrip({ sev }: { sev: Record<string, number> }) {
  const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
  const total = order.reduce((n, k) => n + (sev?.[k] ?? 0), 0);
  if (!total) return <Text size="xs" c="dimmed">{t("bulgu yok")}</Text>;
  return (
    <Tooltip label={order.filter((k) => sev[k]).map((k) => `${k}: ${sev[k]}`).join(" · ")}>
      <Progress.Root size={8} w={120}>{order.filter((k) => sev[k]).map((k) => <Progress.Section key={k} value={(sev[k] / total) * 100} color={SEV_COLOR[k]} />)}</Progress.Root>
    </Tooltip>
  );
}

export default function Scans({ user }: { user: User }) {
  const pick = useSelection();
  const qc = useQueryClient();
  const nav = useNavigate();
  const scans = useQuery<any[]>({ queryKey: ["scans"], queryFn: () => api("/scans?limit=300"), refetchInterval: 5000 });
  const projects = useQuery<any[]>({ queryKey: ["projects"], queryFn: () => api("/projects") });
  const [q, setQ] = useState("");
  const [state, setState] = useState("all");
  const [proj, setProj] = useState<string | null>(null);
  const [hideDup, setHideDup] = useState(false);
  const all = scans.data ?? [];
  const rows = all.filter((s) => (!q || `${s.target} ${s.project} #${s.id}`.toLowerCase().includes(q.toLowerCase())) &&
    (state === "all" || (state === "active" ? ["queued", "running"].includes(s.job.status) : s.job.status === state)) &&
    (!proj || String(s.project_id) === proj) && (!hideDup || !s.duplicate_of));
  const counts = { active: all.filter((s) => ["queued", "running"].includes(s.job.status)).length, failed: all.filter((s) => s.job.status === "failed").length, dup: all.filter((s) => s.duplicate_of).length };
  return (
    <>
      <PageHeader title={t("Taramalar")} sub={t("Tüm hedeflerin tarama geçmişi")} />
      <PageIntro id="scans" guide="start"
        text={t("Her satır bir taramadır. Aynı hedefte, bir önceki taramayla birebir aynı sonucu veren taramalar \"aynı sonuç\" olarak işaretlenir; böylece gerçekten değişen taramaları kolayca ayırırsınız.")}
        points={[t("Tarama ayrıntısındaki Bulgular sekmesi, her bulgunun hangi dosya ve satırda olduğunu raporu indirmeden gösterir."), t("Yeni tarama: Projeler → hedef → Taramayı başlat ya da Hedef ekle sihirbazı.")]} />
      <QueuePanel />
      <SimpleGrid cols={{ base: 2, md: 4 }} mb="md">
        {[{ k: "all", l: t("Toplam"), v: all.length, c: "indigo" }, { k: "active", l: t("Sürüyor / sırada"), v: counts.active, c: "blue" },
          { k: "failed", l: t("Başarısız"), v: counts.failed, c: "red" }, { k: "dup", l: t("Aynı sonuç"), v: counts.dup, c: "gray" }].map((x) => (
          <Card key={x.k} withBorder padding="sm" style={{ cursor: "pointer", borderTop: `3px solid var(--mantine-color-${x.c}-6)` }}
            onClick={() => { if (x.k === "dup") setHideDup(!hideDup); else setState(x.k); }}>
            <Text size="xs" c="dimmed">{x.l}{x.k === "dup" && hideDup ? ` · ${t("gizlendi")}` : ""}</Text><Text fw={800} size="xl">{x.v}</Text>
          </Card>
        ))}
      </SimpleGrid>
      <Group mb="md" gap="sm">
        <TextInput leftSection={<IconSearch size={14} />} placeholder={t("hedef, proje veya #numara")} value={q} onChange={(e) => setQ(e.currentTarget.value)} w={240} />
        <Select placeholder={t("Tüm projeler")} clearable data={(projects.data ?? []).map((p) => ({ value: String(p.id), label: p.name }))} value={proj} onChange={setProj} w={220} />
        <SegmentedControl size="xs" value={state} onChange={setState} data={[{ value: "all", label: t("Tümü") }, { value: "active", label: t("Sürüyor") }, { value: "done", label: t("Tamamlandı") }, { value: "failed", label: t("Başarısız") }]} />
      </Group>
      <BulkBar kind="scans" ids={pick.ids} user={user} onClear={pick.clear} onDone={() => qc.invalidateQueries({ queryKey: ["scans"] })} />
      <Card withBorder p={0}>
        <Table.ScrollContainer minWidth={900}><Table highlightOnHover verticalSpacing="sm">
          <Table.Thead><Table.Tr><Table.Th w={36}>{pick.header(rows.filter((s) => !["queued", "running"].includes(s.job.status)).map((s) => s.id))}</Table.Th><Table.Th>#</Table.Th><Table.Th>{t("Hedef")}</Table.Th><Table.Th>{t("Durum")}</Table.Th><Table.Th>{t("Zaman")}</Table.Th><Table.Th>{t("Bileşen")}</Table.Th><Table.Th>{t("Bulgular")}</Table.Th><Table.Th>{t("Değişim")}</Table.Th></Table.Tr></Table.Thead>
          <Table.Tbody>
            {rows.map((s) => {
              const sm = s.summary;
              return (
                <Table.Tr key={s.id} style={{ cursor: "pointer", opacity: s.duplicate_of ? 0.75 : 1 }} onClick={() => nav(`/scans/${s.id}`)} bg={pick.sel.has(s.id) ? "var(--mantine-color-indigo-light)" : undefined}>
                  <Table.Td>{pick.cell(s.id, ["queued", "running"].includes(s.job.status))}</Table.Td>
                  <Table.Td><Text fw={700}>#{s.id}</Text></Table.Td>
                  <Table.Td>
                    <Group gap="xs" wrap="nowrap">
                      <ThemeIcon variant="light" size="md" color="indigo"><IconRadar size={14} /></ThemeIcon>
                      <div><Text size="sm" fw={600}>{s.target}</Text><Text size="xs" c="dimmed">{s.project}</Text></div>
                    </Group>
                  </Table.Td>
                  <Table.Td>
                    <Stack gap={4}>
                      <Group gap={4}><JobBadge status={s.job.status} />
                        {s.duplicate_of && <Tooltip label={s.same_input ? t("Aynı girdi, aynı sonuç") : t("Girdi farklı, sonuç aynı")}><Badge size="sm" variant="outline" color="gray" leftSection={<IconCopy size={10} />} tt="none">{t("= #{n}", { n: s.duplicate_of })}</Badge></Tooltip>}
                        {sm?.waf && <Tooltip label={sm.waf.severe ? t("WAF içeriği engelledi; sonuç eksik — tarama sayfasındaki çözümlere bakın") : t("WAF / bot koruması tespit edildi")}><Badge size="sm" color={sm.waf.severe ? "red" : "orange"} variant={sm.waf.severe ? "filled" : "light"} leftSection={<IconShieldLock size={10} />}>{sm.waf.severe ? t("WAF engeli") : "WAF"}</Badge></Tooltip>}
                      </Group>
                      {s.job.status === "running" && <Progress value={s.job.progress} size="sm" w={120} animated />}
                      {s.job.status === "failed" && <Text size="xs" c="red" lineClamp={1} maw={220}>{t(s.job.error)}</Text>}
                    </Stack>
                  </Table.Td>
                  <Table.Td><Text size="sm">{fmtDate(s.created_at)}</Text>{duration(s) && <Text size="xs" c="dimmed">{duration(s)}</Text>}</Table.Td>
                  <Table.Td><Text size="sm" fw={600}>{sm?.components ?? "—"}</Text></Table.Td>
                  <Table.Td>{sm ? <Group gap="xs" wrap="nowrap"><Text size="sm" fw={600} w={34}>{sm.findings}</Text><SevStrip sev={sm.severity ?? {}} /></Group> : "—"}</Table.Td>
                  <Table.Td>{sm ? <Group gap={4}>
                    {sm.new > 0 && <Badge size="sm" color="red" variant="light">+{sm.new}</Badge>}
                    {sm.fixed > 0 && <Badge size="sm" color="green" variant="light">−{sm.fixed}</Badge>}
                    {sm.reopened > 0 && <Badge size="sm" color="orange" variant="light">↺{sm.reopened}</Badge>}
                    {!sm.new && !sm.fixed && !sm.reopened && <Text size="xs" c="dimmed">{t("değişiklik yok")}</Text>}
                  </Group> : "—"}</Table.Td>
                </Table.Tr>
              );
            })}
            {rows.length === 0 && <Table.Tr><Table.Td colSpan={8}><Text c="dimmed" ta="center" py="lg">{all.length ? t("Filtreye uyan tarama yok") : <>{t("Henüz tarama yok.")} <Anchor component={Link} to="/projects" size="sm">{t("Bir projeye hedef ekleyin")} →</Anchor></>}</Text></Table.Td></Table.Tr>}
          </Table.Tbody>
        </Table></Table.ScrollContainer>
      </Card>
    </>
  );
}
