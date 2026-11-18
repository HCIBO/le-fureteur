import { ActionIcon, Alert, Anchor, Badge, Button, Card, CopyButton, Grid, Group, NumberInput, Paper, ScrollArea, SegmentedControl, Select, SimpleGrid, Stack, Switch, Table, Tabs, Text, Textarea, TextInput, ThemeIcon, Tooltip, UnstyledButton } from "@mantine/core";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState } from "react";
import { IconArrowsExchange, IconBolt, IconCheck, IconCopy, IconDownload, IconLock, IconNote, IconPin, IconPinnedOff, IconPlus, IconRadar2, IconSearch, IconSend, IconTerminal2, IconTrash, IconTransform, IconWorldWww, IconX } from "@tabler/icons-react";
import { api, fmtDate, fmtSize } from "../api";
import { t } from "../i18n";
import { fail, PageHeader } from "../components/ui";
import { PageIntro } from "../components/PageIntro";

const MONO = { fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: 12.5 };

type Hdr = { k: string; v: string; on: boolean };
const HIST_KEY = "lf_http_history";
const loadHist = (): { method: string; url: string }[] => { try { return JSON.parse(localStorage.getItem(HIST_KEY) ?? "[]"); } catch { return []; } };

function statusColor(s: number) { return s < 300 ? "green" : s < 400 ? "blue" : s < 500 ? "orange" : "red"; }

function curl(method: string, url: string, hdrs: Hdr[], body: string) {
  const q = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;
  return [`curl -i -X ${method} ${q(url)}`, ...hdrs.filter((h) => h.on && h.k).map((h) => `  -H ${q(`${h.k}: ${h.v}`)}`), ...(body ? [`  --data-raw ${q(body)}`] : [])].join(" \\\n");
}

function pretty(body: string, ctype: string) {
  if (/json/i.test(ctype) || /^\s*[[{]/.test(body)) { try { return JSON.stringify(JSON.parse(body), null, 2); } catch {  } }
  return body;
}

function HttpClient({ status }: { status: any }) {
  const [method, setMethod] = useState("GET");
  const [url, setUrl] = useState("https://");
  const [hdrs, setHdrs] = useState<Hdr[]>([{ k: "Accept", v: "*/*", on: true }]);
  const [body, setBody] = useState("");
  const [opts, setOpts] = useState({ follow_redirects: false, verify_tls: true, timeout: 15 });
  const [res, setRes] = useState<any>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [hist, setHist] = useState(loadHist);
  async function send() {
    setBusy(true); setErr(null); setRes(null);
    try {
      const r = await api("/tools/http", { body: { method, url, headers: hdrs.filter((h) => h.on && h.k.trim()).map((h) => [h.k, h.v]), body: ["GET", "HEAD"].includes(method) ? "" : body, ...opts } });
      setRes(r);
      const h = [{ method, url }, ...hist.filter((x) => !(x.method === method && x.url === url))].slice(0, 15);
      setHist(h); try { localStorage.setItem(HIST_KEY, JSON.stringify(h)); } catch {  }
    } catch (e: any) { setErr(e?.message ?? String(e)); } finally { setBusy(false); }
  }
  const raw = res ? `${res.http_version} ${res.status} ${res.reason}\n${res.headers.map(([k, v]: string[]) => `${k}: ${v}`).join("\n")}\n\n${res.body}` : "";
  return (
    <Grid>
      <Grid.Col span={{ base: 12, lg: 9 }}>
        <Card withBorder>
          <Group gap="xs" wrap="nowrap">
            <Select w={120} data={["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]} value={method} onChange={(v) => setMethod(v ?? "GET")} allowDeselect={false} styles={{ input: { fontWeight: 700 } }} />
            <TextInput style={{ flex: 1 }} value={url} onChange={(e) => setUrl(e.currentTarget.value)} placeholder="https://api.ornek.com/v1/health" styles={{ input: MONO }}
              onKeyDown={(e) => { if (e.key === "Enter") send(); }} />
            <Button leftSection={<IconSend size={16} />} onClick={send} loading={busy} disabled={!status?.network || !/^https?:\/\/.+/.test(url)}>{t("Gönder")}</Button>
          </Group>
          <Tabs defaultValue="headers" mt="sm">
            <Tabs.List>
              <Tabs.Tab value="headers">{t("Başlıklar")} <Badge size="xs" variant="light" ml={4}>{hdrs.filter((h) => h.on && h.k).length}</Badge></Tabs.Tab>
              <Tabs.Tab value="body" disabled={["GET", "HEAD"].includes(method)}>{t("Gövde")}</Tabs.Tab>
              <Tabs.Tab value="opts">{t("Seçenekler")}</Tabs.Tab>
              <Tabs.Tab value="curl">cURL</Tabs.Tab>
            </Tabs.List>
            <Tabs.Panel value="headers" pt="sm">
              <Stack gap={6}>
                {hdrs.map((h, i) => (
                  <Group key={i} gap={6} wrap="nowrap">
                    <Switch size="xs" checked={h.on} onChange={(e) => setHdrs(hdrs.map((x, j) => j === i ? { ...x, on: e.currentTarget.checked } : x))} />
                    <TextInput size="xs" w={220} placeholder={t("Başlık")} value={h.k} onChange={(e) => setHdrs(hdrs.map((x, j) => j === i ? { ...x, k: e.currentTarget.value } : x))} styles={{ input: MONO }} />
                    <TextInput size="xs" style={{ flex: 1 }} placeholder={t("Değer")} value={h.v} onChange={(e) => setHdrs(hdrs.map((x, j) => j === i ? { ...x, v: e.currentTarget.value } : x))} styles={{ input: MONO }} />
                    <ActionIcon variant="subtle" color="red" onClick={() => setHdrs(hdrs.filter((_, j) => j !== i))} aria-label={t("Sil")}><IconTrash size={14} /></ActionIcon>
                  </Group>
                ))}
                <Group gap="xs">
                  <Button size="xs" variant="light" leftSection={<IconPlus size={14} />} onClick={() => setHdrs([...hdrs, { k: "", v: "", on: true }])}>{t("Başlık ekle")}</Button>
                  {["Authorization: Bearer ", "Content-Type: application/json", "Cookie: "].map((p) => (
                    <Button key={p} size="xs" variant="default" onClick={() => { const [k, v] = p.split(": "); setHdrs([...hdrs, { k, v, on: true }]); }}>{p.split(":")[0]}</Button>
                  ))}
                </Group>
              </Stack>
            </Tabs.Panel>
            <Tabs.Panel value="body" pt="sm"><Textarea value={body} onChange={(e) => setBody(e.currentTarget.value)} autosize minRows={6} maxRows={18} styles={{ input: MONO }} placeholder='{"ornek": true}' /></Tabs.Panel>
            <Tabs.Panel value="opts" pt="sm">
              <Group>
                <Switch label={t("Yönlendirmeleri izle")} checked={opts.follow_redirects} onChange={(e) => setOpts({ ...opts, follow_redirects: e.currentTarget.checked })} />
                <Switch label={t("TLS sertifikasını doğrula")} checked={opts.verify_tls} onChange={(e) => setOpts({ ...opts, verify_tls: e.currentTarget.checked })} />
                <NumberInput w={160} label={t("Zaman aşımı (sn)")} min={1} max={30} value={opts.timeout} onChange={(v) => setOpts({ ...opts, timeout: Number(v) || 15 })} />
              </Group>
            </Tabs.Panel>
            <Tabs.Panel value="curl" pt="sm"><CodeOut text={curl(method, url, hdrs, ["GET", "HEAD"].includes(method) ? "" : body)} /></Tabs.Panel>
          </Tabs>
        </Card>

        {err && <Alert mt="md" color="red" icon={<IconX size={18} />} title={t("İstek gönderilemedi")}>{err}</Alert>}
        {res && (
          <Card withBorder mt="md">
            <Group justify="space-between" mb="sm">
              <Group gap="xs">
                <Badge size="lg" color={statusColor(res.status)} variant="filled">{res.status} {res.reason}</Badge>
                <Badge variant="light" color="gray" tt="none">{res.elapsed_ms} ms</Badge>
                <Badge variant="light" color="gray" tt="none">{fmtSize(res.size)}{res.truncated ? ` · ${t("kısaltıldı")}` : ""}</Badge>
                {res.ip && <Badge variant="light" color="gray" tt="none">IP {res.ip}</Badge>}
                <Badge variant="outline" color="gray" tt="none">{res.http_version}</Badge>
              </Group>
              {res.redirects.length > 0 && <Badge variant="light" color="blue">{t("{n} yönlendirme", { n: res.redirects.length })}</Badge>}
            </Group>
            <Tabs defaultValue="body">
              <Tabs.List>
                <Tabs.Tab value="body">{t("Gövde")}</Tabs.Tab>
                <Tabs.Tab value="headers">{t("Başlıklar")} <Badge size="xs" variant="light" ml={4}>{res.headers.length}</Badge></Tabs.Tab>
                <Tabs.Tab value="raw">{t("Ham yanıt")}</Tabs.Tab>
                {res.redirects.length > 0 && <Tabs.Tab value="redirects">{t("Yönlendirmeler")}</Tabs.Tab>}
              </Tabs.List>
              <Tabs.Panel value="body" pt="sm">
                {res.binary ? <Alert color="gray">{t("İkili içerik ({type}); ilk 64 KB base64 olarak:", { type: res.content_type || "?" })}<CodeOut text={res.body_b64} /></Alert>
                  : <CodeOut text={pretty(res.body, res.content_type) || t("(boş gövde)")} />}
                <Text size="xs" c="dimmed" mt={4}>{t("Güvenlik için yanıt yalnızca düz metin olarak gösterilir; HTML/JS çalıştırılmaz.")}</Text>
              </Tabs.Panel>
              <Tabs.Panel value="headers" pt="sm">
                <Table striped verticalSpacing={4} style={MONO}><Table.Tbody>
                  {res.headers.map(([k, v]: string[], i: number) => <Table.Tr key={i}><Table.Td fw={600} w={240} style={{ verticalAlign: "top" }}>{k}</Table.Td><Table.Td style={{ wordBreak: "break-all" }}>{v}</Table.Td></Table.Tr>)}
                </Table.Tbody></Table>
              </Tabs.Panel>
              <Tabs.Panel value="raw" pt="sm"><CodeOut text={raw} /></Tabs.Panel>
              <Tabs.Panel value="redirects" pt="sm">
                <Stack gap={4}>{res.redirects.map((h: any, i: number) => <Text key={i} size="sm" style={MONO}><Badge size="xs" color="blue">{h.status}</Badge> {h.url} → {h.location}</Text>)}</Stack>
              </Tabs.Panel>
            </Tabs>
          </Card>
        )}
      </Grid.Col>
      <Grid.Col span={{ base: 12, lg: 3 }}>
        <Card withBorder>
          <Text fw={600} size="sm" mb="xs">{t("Son istekler")}</Text>
          {hist.length === 0 && <Text size="xs" c="dimmed">{t("Gönderdiğiniz istekler burada listelenir (yalnızca bu tarayıcıda, yalnızca yöntem ve adres).")}</Text>}
          <Stack gap={2}>
            {hist.map((h, i) => (
              <UnstyledButton key={i} onClick={() => { setMethod(h.method); setUrl(h.url); }} p={4} style={{ borderRadius: 6 }}>
                <Group gap={6} wrap="nowrap"><Badge size="xs" variant="light" w={52}>{h.method}</Badge><Text size="xs" truncate style={MONO}>{h.url}</Text></Group>
              </UnstyledButton>
            ))}
          </Stack>
          {hist.length > 0 && <Anchor size="xs" mt="xs" display="block" onClick={() => { setHist([]); try { localStorage.removeItem(HIST_KEY); } catch {  } }}>{t("Geçmişi temizle")}</Anchor>}
        </Card>
      </Grid.Col>
    </Grid>
  );
}

function CodeOut({ text }: { text: string }) {
  return (
    <Paper bg="#0d1117" p="sm" radius="md" pos="relative">
      <CopyButton value={text}>{({ copied, copy }) => (
        <ActionIcon pos="absolute" top={6} right={6} variant="subtle" color={copied ? "teal" : "gray"} onClick={copy} aria-label={t("Kopyala")}>{copied ? <IconCheck size={14} /> : <IconCopy size={14} />}</ActionIcon>
      )}</CopyButton>
      <ScrollArea.Autosize mah={460}><pre style={{ ...MONO, margin: 0, color: "#e6edf3", whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{text}</pre></ScrollArea.Autosize>
    </Paper>
  );
}

const te = new TextEncoder();
const td = new TextDecoder("utf-8", { fatal: true });
const b64e = (s: string) => { let bin = ""; te.encode(s).forEach((b) => (bin += String.fromCharCode(b))); return btoa(bin); };
const b64d = (s: string) => { const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/").replace(/\s/g, "") + "===".slice((s.replace(/\s/g, "").length + 3) % 4)); return td.decode(Uint8Array.from(bin, (c) => c.charCodeAt(0))); };
const HTML_ENT: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
const NAMED: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " " };

const OPS: Record<string, { label: string; enc: (s: string) => string; dec?: (s: string) => string }> = {
  base64: { label: "Base64", enc: b64e, dec: b64d },
  base64url: { label: "Base64URL", enc: (s) => b64e(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""), dec: b64d },
  url: { label: "URL", enc: encodeURIComponent, dec: (s) => decodeURIComponent(s.replace(/\+/g, " ")) },
  html: { label: "HTML", enc: (s) => s.replace(/[&<>"']/g, (c) => HTML_ENT[c]),
    dec: (s) => s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e) => e[0] === "#" ? String.fromCodePoint(e[1].toLowerCase() === "x" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10)) : NAMED[e.toLowerCase()] ?? m) },
  hex: { label: "Hex", enc: (s) => Array.from(te.encode(s), (b) => b.toString(16).padStart(2, "0")).join(""),
    dec: (s) => { const h = s.replace(/[^0-9a-f]/gi, ""); if (h.length % 2) throw new Error("hex"); return td.decode(Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16))); } },
  unicode: { label: "Unicode \\u", enc: (s) => Array.from(s, (c) => { const cp = c.codePointAt(0)!; return cp < 128 ? c : cp > 0xffff ? c.split("").map((u) => "\\u" + u.charCodeAt(0).toString(16).padStart(4, "0")).join("") : "\\u" + cp.toString(16).padStart(4, "0"); }).join(""),
    dec: (s) => s.replace(/\\u([0-9a-f]{4})/gi, (_, h) => String.fromCharCode(parseInt(h, 16))) },
};

async function digest(alg: string, s: string) {
  if (!crypto?.subtle) throw new Error(t("Özet hesaplamak için uygulamayı HTTPS üzerinden açın"));
  const buf = await crypto.subtle.digest(alg, te.encode(s));
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
}

function jwt(token: string) {
  const parts = token.trim().split(".");
  if (parts.length < 2) throw new Error(t("Geçerli bir JWT değil"));
  const head = JSON.parse(b64d(parts[0]));
  const payload = JSON.parse(b64d(parts[1]));
  const notes: string[] = [];
  if (head.alg?.toLowerCase() === "none") notes.push(t("⚠ alg=none: imzasız belirteç"));
  for (const k of ["iat", "nbf", "exp"]) if (typeof payload[k] === "number") notes.push(`${k}: ${new Date(payload[k] * 1000).toISOString()}${k === "exp" && payload[k] * 1000 < Date.now() ? ` (${t("süresi dolmuş")})` : ""}`);
  return `// header\n${JSON.stringify(head, null, 2)}\n\n// payload\n${JSON.stringify(payload, null, 2)}${notes.length ? `\n\n// ${notes.join("\n// ")}` : ""}\n\n// ${t("İmza doğrulanmadı — yalnızca içerik çözüldü.")}`;
}

function Codec() {
  const [input, setInput] = useState("");
  const [op, setOp] = useState("base64");
  const [dir, setDir] = useState<"enc" | "dec">("enc");
  const [out, setOut] = useState("");
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    (async () => {
      try {
        setErr(null);
        if (!input) { setOut(""); return; }
        let r: string;
        if (op === "jwt") r = jwt(input);
        else if (op.startsWith("SHA")) r = await digest(op, input);
        else r = dir === "enc" ? OPS[op].enc(input) : OPS[op].dec!(input);
        if (live) setOut(r);
      } catch (e: any) { if (live) { setOut(""); setErr(e?.message && e.message.length < 120 ? e.message : t("Girdi bu biçimde çözülemedi")); } }
    })();
    return () => { live = false; };
  }, [input, op, dir]);
  const oneWay = op === "jwt" || op.startsWith("SHA");
  return (
    <Stack>
      <Group justify="space-between">
        <SegmentedControl value={op} onChange={setOp} data={[...Object.entries(OPS).map(([value, o]) => ({ value, label: o.label })), { value: "jwt", label: "JWT" }, { value: "SHA-256", label: "SHA-256" }, { value: "SHA-1", label: "SHA-1" }, { value: "SHA-512", label: "SHA-512" }]} />
        {!oneWay && <SegmentedControl value={dir} onChange={(v) => setDir(v as any)} data={[{ value: "enc", label: t("Kodla") }, { value: "dec", label: t("Çöz") }]} />}
      </Group>
      <SimpleGrid cols={{ base: 1, md: 2 }}>
        <Stack gap={4}>
          <Text size="sm" fw={600}>{t("Girdi")}</Text>
          <Textarea value={input} onChange={(e) => setInput(e.currentTarget.value)} autosize minRows={12} maxRows={24} styles={{ input: MONO }} placeholder={op === "jwt" ? "eyJhbGciOi..." : t("Metni buraya yapıştırın")} />
          <Text size="xs" c="dimmed">{t("{n} karakter · {b} bayt", { n: input.length, b: te.encode(input).length })}</Text>
        </Stack>
        <Stack gap={4}>
          <Group justify="space-between"><Text size="sm" fw={600}>{t("Çıktı")}</Text>
            {!oneWay && <Button size="compact-xs" variant="subtle" leftSection={<IconArrowsExchange size={12} />} onClick={() => { setInput(out); setDir(dir === "enc" ? "dec" : "enc"); }} disabled={!out}>{t("Çıktıyı girdiye al")}</Button>}</Group>
          {err ? <Alert color="red" icon={<IconX size={16} />}>{err}</Alert> : <CodeOut text={out || " "} />}
        </Stack>
      </SimpleGrid>
      <Group gap={6}><IconLock size={14} /><Text size="xs" c="dimmed">{t("Kodlama ve çözme tamamen tarayıcınızda yapılır; metin sunucuya gönderilmez.")}</Text></Group>
    </Stack>
  );
}

function Ping({ status }: { status: any }) {
  const [host, setHost] = useState("");
  const [port, setPort] = useState<string>("443");
  const [count, setCount] = useState(4);
  const [res, setRes] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  async function run() {
    setBusy(true); setRes(null);
    try { setRes(await api("/tools/ping", { body: { host, port: Number(port), count } })); } catch (e) { fail(e); } finally { setBusy(false); }
  }
  const max = res ? Math.max(1, ...res.results.filter((r: any) => r.ok).map((r: any) => r.ms)) : 1;
  return (
    <Grid>
      <Grid.Col span={{ base: 12, md: 5 }}>
        <Card withBorder>
          <Stack>
            <TextInput label={t("Sunucu")} placeholder="api.ornek.com" value={host} onChange={(e) => setHost(e.currentTarget.value)} styles={{ input: MONO }} onKeyDown={(e) => { if (e.key === "Enter" && host) run(); }} />
            <Group grow>
              <Select label={t("Port")} data={[{ value: "443", label: "443 · HTTPS" }, { value: "80", label: "80 · HTTP" }, { value: "22", label: "22 · SSH" }, { value: "25", label: "25 · SMTP" }, { value: "3389", label: "3389 · RDP" }]} value={port} onChange={(v) => setPort(v ?? "443")} searchable
                onSearchChange={(v) => { if (/^\d{1,5}$/.test(v)) setPort(v); }} />
              <NumberInput label={t("Deneme")} min={1} max={10} value={count} onChange={(v) => setCount(Number(v) || 4)} />
            </Group>
            <Button leftSection={<IconRadar2 size={16} />} onClick={run} loading={busy} disabled={!host.trim() || !status?.network}>{t("Ping at")}</Button>
            <Text size="xs" c="dimmed">{t("ICMP yerine TCP bağlantı süresi ölçülür: güvenlik duvarlarından geçer ve sunucuda yönetici yetkisi gerektirmez. İç ağ adresleri engellenir.")}</Text>
          </Stack>
        </Card>
      </Grid.Col>
      <Grid.Col span={{ base: 12, md: 7 }}>
        {res ? (
          <Card withBorder>
            <Group justify="space-between" mb="sm">
              <div><Text fw={700} style={MONO}>{res.host}:{res.port}</Text><Text size="xs" c="dimmed" style={MONO}>{res.addresses.join(", ")}</Text></div>
              <Badge size="lg" color={res.loss === 0 ? "green" : res.loss < 100 ? "orange" : "red"}>{t("%{n} kayıp", { n: res.loss })}</Badge>
            </Group>
            <Stack gap={6}>
              {res.results.map((r: any) => (
                <Group key={r.seq} gap="sm" wrap="nowrap">
                  <Text size="xs" c="dimmed" w={24}>#{r.seq}</Text>
                  {r.ok ? <><div style={{ flex: 1, height: 10, borderRadius: 5, background: "var(--mantine-color-default-hover)" }}><div style={{ width: `${(r.ms / max) * 100}%`, height: "100%", borderRadius: 5, background: "var(--mantine-color-teal-5)" }} /></div><Text size="xs" w={70} ta="right" style={MONO}>{r.ms} ms</Text></>
                    : <Badge color="red" variant="light">{{ timeout: t("zaman aşımı"), refused: t("bağlantı reddedildi") }[r.error as string] ?? t("hata")}</Badge>}
                </Group>
              ))}
            </Stack>
            {res.avg != null && <SimpleGrid cols={3} mt="md">{[["min", res.min], ["avg", res.avg], ["max", res.max]].map(([k, v]) => <Paper key={k} withBorder p="xs" ta="center"><Text size="xs" c="dimmed">{k}</Text><Text fw={700}>{v} ms</Text></Paper>)}</SimpleGrid>}
          </Card>
        ) : <Card withBorder h="100%"><Stack align="center" justify="center" h="100%" py={40}><ThemeIcon size={48} radius="xl" variant="light"><IconRadar2 size={24} /></ThemeIcon><Text c="dimmed" size="sm">{t("Sonuçlar burada görünür")}</Text></Stack></Card>}
      </Grid.Col>
    </Grid>
  );
}

function Notepad() {
  const qc = useQueryClient();
  const notes = useQuery<any[]>({ queryKey: ["notes"], queryFn: () => api("/tools/notes") });
  const [sel, setSel] = useState<number | null>(null);
  const [draft, setDraft] = useState({ title: "", body: "", pinned: false });
  const [saved, setSaved] = useState(true);
  const [q, setQ] = useState("");
  const timer = useRef<number | undefined>(undefined);
  const cur = notes.data?.find((n) => n.id === sel);
  useEffect(() => { if (cur) { setDraft({ title: cur.title, body: cur.body, pinned: cur.pinned }); setSaved(true); } }, [sel]);
  useEffect(() => { if (!sel && notes.data?.length) setSel(notes.data[0].id); }, [notes.data, sel]);
  function change(d: typeof draft) {
    setDraft(d); setSaved(false);
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(async () => {
      try { await api(`/tools/notes/${sel}`, { method: "PUT", body: d }); setSaved(true); qc.invalidateQueries({ queryKey: ["notes"] }); } catch (e) { fail(e); }
    }, 700);
  }
  async function create() {
    try { const n = await api("/tools/notes", { body: { title: t("Yeni not"), body: "" } }); await qc.invalidateQueries({ queryKey: ["notes"] }); setSel(n.id); } catch (e) { fail(e); }
  }
  async function remove() {
    if (!sel || !confirm(t("Not silinsin mi?"))) return;
    try { await api(`/tools/notes/${sel}`, { method: "DELETE" }); setSel(null); qc.invalidateQueries({ queryKey: ["notes"] }); } catch (e) { fail(e); }
  }
  function download() {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([draft.body], { type: "text/plain;charset=utf-8" }));
    a.download = `${(draft.title || "not").replace(/[^\p{L}\p{N}_-]+/gu, "_").slice(0, 60)}.txt`; a.click(); URL.revokeObjectURL(a.href);
  }
  const list = useMemo(() => (notes.data ?? []).filter((n) => !q || `${n.title} ${n.body}`.toLocaleLowerCase().includes(q.toLocaleLowerCase())), [notes.data, q]);
  return (
    <Grid>
      <Grid.Col span={{ base: 12, md: 4 }}>
        <Card withBorder p="xs">
          <Group gap="xs" mb="xs" wrap="nowrap">
            <TextInput style={{ flex: 1 }} size="xs" leftSection={<IconSearch size={14} />} placeholder={t("Notlarda ara")} value={q} onChange={(e) => setQ(e.currentTarget.value)} />
            <Button size="xs" leftSection={<IconPlus size={14} />} onClick={create}>{t("Yeni")}</Button>
          </Group>
          <ScrollArea h={520} scrollbars="y">
            <Stack gap={2}>
              {list.map((n) => (
                <UnstyledButton key={n.id} onClick={() => setSel(n.id)} p="xs" style={{ display: "block", width: "100%", minWidth: 0, borderRadius: 8, background: sel === n.id ? "var(--mantine-color-indigo-light)" : undefined }}>
                  <Group gap={6} wrap="nowrap">{n.pinned && <IconPin size={12} />}<Text size="sm" fw={600} truncate>{n.title || t("Başlıksız")}</Text></Group>
                  <Text size="xs" c="dimmed" truncate>{n.body.slice(0, 80) || "—"}</Text>
                  <Text size="xs" c="dimmed">{fmtDate(n.updated_at)}</Text>
                </UnstyledButton>
              ))}
              {notes.data?.length === 0 && <Stack align="center" py={40} gap={6}><ThemeIcon size={44} radius="xl" variant="light"><IconNote size={22} /></ThemeIcon><Text size="sm" c="dimmed" ta="center">{t("Payload'lar, komutlar, toplantı notları… İlk notunuzu oluşturun.")}</Text><Button size="xs" onClick={create}>{t("Yeni not")}</Button></Stack>}
            </Stack>
          </ScrollArea>
        </Card>
      </Grid.Col>
      <Grid.Col span={{ base: 12, md: 8 }}>
        {cur ? (
          <Card withBorder>
            <Group justify="space-between" mb="xs" wrap="nowrap">
              <TextInput variant="unstyled" size="lg" fw={700} style={{ flex: 1 }} value={draft.title} onChange={(e) => change({ ...draft, title: e.currentTarget.value })} placeholder={t("Başlık")} maxLength={200} />
              <Group gap={4} wrap="nowrap">
                <Badge variant="light" color={saved ? "green" : "gray"} leftSection={saved ? <IconCheck size={11} /> : null}>{saved ? t("Kaydedildi") : t("Kaydediliyor…")}</Badge>
                <Tooltip label={draft.pinned ? t("Sabitlemeyi kaldır") : t("Sabitle")}><ActionIcon variant="subtle" onClick={() => change({ ...draft, pinned: !draft.pinned })}>{draft.pinned ? <IconPinnedOff size={16} /> : <IconPin size={16} />}</ActionIcon></Tooltip>
                <Tooltip label={t("İndir (.txt)")}><ActionIcon variant="subtle" onClick={download}><IconDownload size={16} /></ActionIcon></Tooltip>
                <Tooltip label={t("Sil")}><ActionIcon variant="subtle" color="red" onClick={remove}><IconTrash size={16} /></ActionIcon></Tooltip>
              </Group>
            </Group>
            <Textarea value={draft.body} onChange={(e) => change({ ...draft, body: e.currentTarget.value })} autosize minRows={22} maxRows={40} styles={{ input: MONO }} placeholder={t("Yazmaya başlayın — otomatik kaydedilir.")} maxLength={100000} />
            <Text size="xs" c="dimmed" mt={4}>{t("Notlar yalnızca size görünür.")} · {t("{n} karakter", { n: draft.body.length })}</Text>
          </Card>
        ) : <Card withBorder h="100%"><Stack align="center" justify="center" py={60}><Text c="dimmed" size="sm">{t("Soldan bir not seçin")}</Text></Stack></Card>}
      </Grid.Col>
    </Grid>
  );
}

export default function Toolset() {
  const status = useQuery<any>({ queryKey: ["tools-status"], queryFn: () => api("/tools/status") });
  const [tab, setTab] = useState<string | null>(() => { try { return localStorage.getItem("lf_tool_tab") ?? "http"; } catch { return "http"; } });
  return (
    <>
      <PageHeader title={t("Araç seti")} sub={t("Günlük işler için küçük, güvenli araçlar")} />
      <PageIntro id="toolset" guide="toolset"
        text={t("HTTP isteği gönderip yanıtı inceleyin, metinleri kodlayıp çözün, bir sunucuya erişimi ölçün ve notlarınızı tutun.")}
        points={[t("Ağ araçları iç ağ adreslerine (127.0.0.1, 10.x, 169.254.169.254 vb.) hiçbir koşulda bağlanmaz; yönlendirmeler de denetlenir."), t("Oturum çereziniz hedefe gönderilmez; yalnızca sizin eklediğiniz başlıklar gider. Her istek denetim kaydına yazılır."), t("Kodlayıcı tamamen tarayıcıda çalışır; not defteri yalnızca size görünür.")]} />
      {status.data && !status.data.network && <Alert mb="md" color="yellow" icon={<IconBolt size={18} />}>{t("Ağ araçları kullanılamıyor:")} {status.data.reason}</Alert>}
      {status.data?.allowed_domains && <Alert mb="md" color="blue" icon={<IconWorldWww size={18} />}>{t("Yalnızca organizasyonunuzun izinli alan adlarına istek gönderebilirsiniz:")} {status.data.allowed_domains.join(", ") || "—"}</Alert>}
      <Tabs value={tab} onChange={(v) => { setTab(v); try { localStorage.setItem("lf_tool_tab", v ?? "http"); } catch {  } }} keepMounted>
        <Tabs.List mb="md">
          <Tabs.Tab value="http" leftSection={<IconTerminal2 size={16} />}>{t("HTTP istemcisi")}</Tabs.Tab>
          <Tabs.Tab value="codec" leftSection={<IconTransform size={16} />}>{t("Kodlayıcı / çözücü")}</Tabs.Tab>
          <Tabs.Tab value="ping" leftSection={<IconRadar2 size={16} />}>Ping</Tabs.Tab>
          <Tabs.Tab value="notes" leftSection={<IconNote size={16} />}>{t("Not defteri")}</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="http"><HttpClient status={status.data} /></Tabs.Panel>
        <Tabs.Panel value="codec"><Card withBorder><Codec /></Card></Tabs.Panel>
        <Tabs.Panel value="ping"><Ping status={status.data} /></Tabs.Panel>
        <Tabs.Panel value="notes"><Notepad /></Tabs.Panel>
      </Tabs>
    </>
  );
}
