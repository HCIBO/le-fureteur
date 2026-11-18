import { Badge, Button, Card, Code, Group, MultiSelect, Pagination, Select, SimpleGrid, Table, Text, TextInput, Tooltip } from "@mantine/core";
import { useQuery } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { IconDownload, IconFilterOff, IconSearch } from "@tabler/icons-react";
import { useSearchParams } from "react-router-dom";
import { api, fmtDate } from "../api";
import { PageHeader } from "../components/ui";
import { PageIntro } from "../components/PageIntro";
import { t } from "../i18n";

const SIZE = 100;
const COLOR: [RegExp, string][] = [[/^login\.(failed|sso\.failed|sso\.no_account)/, "red"], [/^login/, "green"], [/delete|revoke/, "red"],
  [/^settings|^user\./, "orange"], [/^tools\./, "grape"], [/create|open/, "teal"]];
const color = (a: string) => COLOR.find(([r]) => r.test(a))?.[1] ?? "gray";

const RANGES: Record<string, number> = { "1h": 1 / 24, "24h": 1, "7d": 7, "30d": 30, "90d": 90 };

export default function Audit() {
  const [sp, setSp] = useSearchParams();
  const [page, setPage] = useState(1);
  const facets = useQuery<any>({ queryKey: ["audit-facets"], queryFn: () => api("/audit/facets") });
  const f = { user: sp.get("user") ?? "", action: sp.get("action") ?? "", object_type: sp.get("object_type") ?? "", ip: sp.get("ip") ?? "", q: sp.get("q") ?? "", range: sp.get("range") ?? "" };
  const [text, setText] = useState(f.q);
  const [ipText, setIpText] = useState(f.ip);
  const set = (k: string, v: string) => { const n = new URLSearchParams(sp); if (v) n.set(k, v); else n.delete(k); setSp(n, { replace: true }); setPage(1); };
  useEffect(() => { const id = window.setTimeout(() => { if (text !== f.q) set("q", text); }, 400); return () => window.clearTimeout(id); }, [text]);
  useEffect(() => { const id = window.setTimeout(() => { if (ipText !== f.ip) set("ip", ipText); }, 400); return () => window.clearTimeout(id); }, [ipText]);
  const params = new URLSearchParams();
  for (const k of ["user", "action", "object_type", "ip", "q"] as const) if (f[k]) params.set(k, f[k]);
  const since = useMemo(() => (f.range && RANGES[f.range] ? new Date(Date.now() - RANGES[f.range] * 86400e3).toISOString() : ""), [f.range]);
  if (since) params.set("date_from", since);
  const data = useQuery<any>({ queryKey: ["audit", params.toString(), page], queryFn: () => api(`/audit?${params}&page=${page}&size=${SIZE}`) });
  const active = Object.values(f).some(Boolean);
  const actions: string[] = facets.data?.actions ?? [];
  const prefixes = [...new Set(actions.map((a) => a.split(".")[0]))];
  const actionData = prefixes.map((p) => ({ group: p, items: [{ value: p, label: t("{p} (tümü)", { p }) }, ...actions.filter((a) => a.startsWith(p + ".")).map((a) => ({ value: a, label: a }))] }));
  return (
    <>
      <PageHeader title={t("Denetim kaydı")} sub={t("Giriş, ayar, hedef, tarama, durum değişikliği ve rapor indirme işlemleri")}
        right={<Button variant="default" leftSection={<IconDownload size={16} />} component="a" href={`/api/audit.csv?${params}`}>{t("CSV indir")}</Button>} />
      <PageIntro id="audit" guide="admin"
        text={t("Uygulamada yapılan her önemli işlem kim, ne zaman, hangi IP'den bilgisiyle burada saklanır. Filtrelerle daraltın, sonucu CSV olarak dışa aktarın.")}
        points={[t("Saklama süresi Ayarlar → Saklama bölümünden belirlenir."), t("CSV dışa aktarımı da denetim kaydına yazılır; hücreler formül enjeksiyonuna karşı korunur.")]} />
      <Card withBorder mb="md">
        <SimpleGrid cols={{ base: 1, sm: 2, lg: 6 }} spacing="sm">
          <TextInput label={t("Ara")} leftSection={<IconSearch size={14} />} placeholder={t("ayrıntıda geçen metin")} value={text} onChange={(e) => setText(e.currentTarget.value)} />
          <Select label={t("Kullanıcı")} searchable clearable data={facets.data?.users ?? []} value={f.user || null} onChange={(v) => set("user", v ?? "")} />
          <MultiSelect label={t("İşlem")} searchable clearable data={actionData} value={f.action ? f.action.split(",") : []} onChange={(v) => set("action", v.join(","))} maxValues={10} />
          <Select label={t("Nesne türü")} clearable data={facets.data?.object_types ?? []} value={f.object_type || null} onChange={(v) => set("object_type", v ?? "")} />
          <TextInput label="IP" placeholder="10.0." value={ipText} onChange={(e) => setIpText(e.currentTarget.value)} />
          <Select label={t("Zaman aralığı")} clearable data={[{ value: "1h", label: t("Son 1 saat") }, { value: "24h", label: t("Son 24 saat") }, { value: "7d", label: t("Son 7 gün") }, { value: "30d", label: t("Son 30 gün") }, { value: "90d", label: t("Son 90 gün") }]} value={f.range || null} onChange={(v) => set("range", v ?? "")} />
        </SimpleGrid>
        <Group justify="space-between" mt="sm">
          <Group gap={6}>
            {[{ l: t("Başarısız girişler"), a: "login.failed,login.sso.failed,login.sso.no_account" }, { l: t("Ayar değişiklikleri"), a: "settings" }, { l: t("Silme işlemleri"), a: "project.delete,org.delete,user.delete,target.delete" }, { l: t("Araç seti"), a: "tools" }].map((x) => (
              <Badge key={x.l} variant={f.action === x.a ? "filled" : "light"} size="lg" tt="none" style={{ cursor: "pointer" }} onClick={() => set("action", f.action === x.a ? "" : x.a)}>{x.l}</Badge>
            ))}
          </Group>
          {active && <Button size="xs" variant="subtle" leftSection={<IconFilterOff size={14} />} onClick={() => { setText(""); setIpText(""); setSp(new URLSearchParams(), { replace: true }); setPage(1); }}>{t("Filtreleri temizle")}</Button>}
        </Group>
      </Card>
      <Card withBorder p={0}>
        <Table.ScrollContainer minWidth={760}><Table striped highlightOnHover verticalSpacing="xs">
          <Table.Thead><Table.Tr><Table.Th>{t("Zaman")}</Table.Th><Table.Th>{t("Kullanıcı")}</Table.Th><Table.Th>{t("İşlem")}</Table.Th><Table.Th>{t("Nesne")}</Table.Th><Table.Th>{t("Ayrıntı")}</Table.Th><Table.Th>{t("IP")}</Table.Th></Table.Tr></Table.Thead>
          <Table.Tbody>
            {(data.data?.items ?? []).map((a: any) => (
              <Table.Tr key={a.id}>
                <Table.Td><Text size="xs" style={{ whiteSpace: "nowrap" }}>{fmtDate(a.at)}</Text></Table.Td>
                <Table.Td>{a.user ? <Text size="xs" c="blue" style={{ cursor: "pointer" }} onClick={() => set("user", a.user)}>{a.user}</Text> : <Text size="xs" c="dimmed">—</Text>}</Table.Td>
                <Table.Td><Code color={`var(--mantine-color-${color(a.action)}-light)`} style={{ cursor: "pointer" }} onClick={() => set("action", a.action)}>{a.action}</Code></Table.Td>
                <Table.Td><Text size="xs">{a.object}</Text></Table.Td>
                <Table.Td><Tooltip label={t(a.detail ?? "")} disabled={!a.detail || a.detail.length < 80} multiline w={420}><Text size="xs" lineClamp={2} maw={420}>{t(a.detail ?? "")}</Text></Tooltip></Table.Td>
                <Table.Td><Text size="xs" ff="monospace" style={{ cursor: "pointer" }} onClick={() => { setIpText(a.ip); }}>{a.ip}</Text></Table.Td>
              </Table.Tr>
            ))}
            {data.data?.items?.length === 0 && <Table.Tr><Table.Td colSpan={6}><Text c="dimmed" ta="center" py="lg">{t("Filtreye uyan kayıt yok")}</Text></Table.Td></Table.Tr>}
          </Table.Tbody>
        </Table></Table.ScrollContainer>
        {data.data && data.data.total > SIZE && <Group justify="center" p="md"><Pagination total={Math.ceil(data.data.total / SIZE)} value={page} onChange={setPage} /></Group>}
      </Card>
      {data.data && <Text size="xs" c="dimmed" mt="xs">{t("{n} kayıt", { n: data.data.total })}</Text>}
    </>
  );
}
