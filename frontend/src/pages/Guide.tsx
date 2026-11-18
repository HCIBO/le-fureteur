import { Alert, Anchor, Badge, Box, Card, Code, Grid, Group, List, NavLink, ScrollArea, Stack, Table, Text, TextInput, Title } from "@mantine/core";
import { useQuery } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { IconInfoCircle, IconSearch } from "@tabler/icons-react";
import { api, User } from "../api";
import { lang, t } from "../i18n";
import { PRODUCT } from "../brand";
import { Block, GuideContent } from "../guide/types";
import tr from "../guide/tr";
import en from "../guide/en";
import fr from "../guide/fr";
import de from "../guide/de";

const CONTENT: Record<string, GuideContent> = { tr, en, fr, de };
const METHOD_COLOR: Record<string, string> = { get: "blue", post: "green", put: "orange", patch: "yellow", delete: "red" };

function blockText(b: Block): string {
  if ("p" in b) return b.p;
  if ("note" in b) return b.note;
  if ("code" in b) return b.code;
  if ("ul" in b) return b.ul.join(" ");
  if ("ol" in b) return b.ol.join(" ");
  return [...b.table.head, ...b.table.rows.flat()].join(" ");
}

function RenderBlock({ b }: { b: Block }) {
  if ("p" in b) return <Text size="sm">{b.p}</Text>;
  if ("note" in b) return <Alert variant="light" color="blue" icon={<IconInfoCircle size={16} />}><Text size="sm">{b.note}</Text></Alert>;
  if ("code" in b) return <Code block>{b.code}</Code>;
  if ("ul" in b) return <List size="sm" spacing={4}>{b.ul.map((x, i) => <List.Item key={i}>{x}</List.Item>)}</List>;
  if ("ol" in b) return <List type="ordered" size="sm" spacing={4}>{b.ol.map((x, i) => <List.Item key={i}>{x}</List.Item>)}</List>;
  return (
    <Table.ScrollContainer minWidth={560}>
      <Table withTableBorder striped verticalSpacing={6}>
        <Table.Thead><Table.Tr>{b.table.head.map((h) => <Table.Th key={h}>{h}</Table.Th>)}</Table.Tr></Table.Thead>
        <Table.Tbody>
          {b.table.rows.map((r, i) => (
            <Table.Tr key={i}>{r.map((c, j) => <Table.Td key={j}><Text size="sm" fw={j === 0 ? 600 : 400}>{c}</Text></Table.Td>)}</Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
    </Table.ScrollContainer>
  );
}

function ApiList() {
  const spec = useQuery<any>({ queryKey: ["openapi"], queryFn: () => api("/openapi.json"), staleTime: Infinity });
  const [q, setQ] = useState("");
  const rows = useMemo(() => {
    const out: { method: string; path: string; summary: string }[] = [];
    for (const [path, ops] of Object.entries<any>(spec.data?.paths ?? {})) {
      for (const [method, op] of Object.entries<any>(ops)) out.push({ method, path, summary: op.summary ?? "" });
    }
    return out.filter((r) => !q || r.path.includes(q.toLowerCase())).sort((a, b) => a.path.localeCompare(b.path));
  }, [spec.data, q]);
  return (
    <>
      <TextInput size="xs" placeholder="/api/findings" value={q} onChange={(e) => setQ(e.currentTarget.value)} mb="xs" w={260} leftSection={<IconSearch size={14} />} />
      <ScrollArea h={360}>
        <Table verticalSpacing={4}>
          <Table.Tbody>
            {rows.map((r) => (
              <Table.Tr key={r.method + r.path}>
                <Table.Td w={80}><Badge size="sm" variant="light" color={METHOD_COLOR[r.method] ?? "gray"}>{r.method.toUpperCase()}</Badge></Table.Td>
                <Table.Td><Text size="sm" ff="monospace">{r.path}</Text></Table.Td>
                <Table.Td><Text size="xs" c="dimmed">{r.summary}</Text></Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </ScrollArea>
      <Text size="xs" c="dimmed" mt={4}>{rows.length} endpoint</Text>
    </>
  );
}

export default function Guide({ user: _user }: { user: User }) {
  const c = CONTENT[lang] ?? CONTENT.tr;
  const [q, setQ] = useState("");
  const needle = q.trim().toLocaleLowerCase();
  const sections = c.sections.filter((s) => !needle || (s.title + " " + s.blocks.map(blockText).join(" ")).toLocaleLowerCase().includes(needle));
  const apiMatch = !needle || (c.api.title + " " + c.api.groups.flat().join(" ") + " " + c.api.fullListNote).toLocaleLowerCase().includes(needle);
  const go = (id: string) => document.getElementById(`g-${id}`)?.scrollIntoView({ behavior: "smooth", block: "start" });
  useEffect(() => {
    const id = window.location.hash.replace("#", "");
    if (id) setTimeout(() => go(id), 150);
  }, []);
  return (
    <>
      <Group justify="space-between" align="flex-end" mb="lg">
        <div>
          <Title order={2}>{t("Rehber")}</Title>
          <Text c="dimmed" size="sm">{PRODUCT} — {t("amaç, özellikler, kullanım ve API")}</Text>
        </div>
        <TextInput placeholder={t("Rehberde ara")} value={q} onChange={(e) => setQ(e.currentTarget.value)} leftSection={<IconSearch size={16} />} w={280} />
      </Group>
      <Grid gutter="lg">
        <Grid.Col span={{ base: 12, md: 3 }} visibleFrom="md">
          <Box style={{ position: "sticky", top: 72 }}>
            <Card withBorder p="xs">
              {sections.map((s) => <NavLink key={s.id} label={s.title} onClick={() => go(s.id)} />)}
              {apiMatch && <NavLink label={c.api.title} onClick={() => go("api")} />}
            </Card>
          </Box>
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 9 }}>
          <Stack>
            {!needle && <Card withBorder bg="var(--mantine-color-indigo-light)"><Text>{c.intro}</Text></Card>}
            {sections.map((s) => (
              <Card withBorder key={s.id} id={`g-${s.id}`} style={{ scrollMarginTop: 72 }}>
                <Title order={3} mb="sm">{s.title}</Title>
                <Stack gap="sm">{s.blocks.map((b, i) => <RenderBlock key={i} b={b} />)}</Stack>
              </Card>
            ))}
            {apiMatch && (
              <Card withBorder id="g-api" style={{ scrollMarginTop: 72 }}>
                <Title order={3} mb="sm">{c.api.title}</Title>
                <Stack gap="sm">
                  <Text size="sm">{c.api.fullListNote}</Text>
                  <Code block>{`# 1) CSRF cookie + login
curl -c j.txt -b j.txt https://HOST/api/health
TOKEN=$(awk '/scakit_csrf/ {print $7}' j.txt)
curl -c j.txt -b j.txt -H "X-CSRF-Token: $TOKEN" -H "Content-Type: application/json" \\
     -d '{"email":"...","password":"..."}' https://HOST/api/auth/login
TOKEN=$(awk '/scakit_csrf/ {print $7}' j.txt)

# 2) open critical findings
curl -b j.txt "https://HOST/api/findings?severity=CRITICAL&status=open"

# 3) start a scan
curl -b j.txt -H "X-CSRF-Token: $TOKEN" -X POST https://HOST/api/targets/12/scans`}</Code>
                  <RenderBlock b={{ table: { head: c.api.groupsHead, rows: c.api.groups } }} />
                  <Text fw={600} mt="sm">{c.api.fullListTitle}</Text>
                  <ApiList />
                  <Anchor size="xs" href="/api/openapi.json" target="_blank" rel="noreferrer">OpenAPI JSON</Anchor>
                </Stack>
              </Card>
            )}
            {sections.length === 0 && !apiMatch && <Text c="dimmed">{t("Sonuç yok")}</Text>}
          </Stack>
        </Grid.Col>
      </Grid>
    </>
  );
}
