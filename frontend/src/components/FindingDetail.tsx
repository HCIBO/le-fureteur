import { Anchor, Avatar, Badge, Blockquote, Button, Card, Code, Group, Loader, Paper, RingProgress, Select, SimpleGrid, Stack, Tabs, Text, Textarea, ThemeIcon, Timeline, Tooltip } from "@mantine/core";
import { useJiraPicker } from "./JiraInstances";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { IconAlertTriangle, IconArrowRight, IconBolt, IconBrandGithub, IconCheck, IconFile, IconGavel, IconHistory, IconInfoCircle,
  IconAlarm, IconLink, IconMail, IconMessage2, IconRefresh, IconSend, IconShare, IconTicket, IconTool, IconUserCheck, IconX } from "@tabler/icons-react";
import { api, fmtDate, SEV_COLOR, SEV_LABEL, STATUS_LABEL, fmtDay, fmtPct } from "../api";
import { t } from "../i18n";
import { fail, ok, SevBadge, StatusBadge } from "./ui";
import { AssignModal, ShareModal } from "./Assign";
import { CodeBlock } from "./CodeBlock";
import { DisputeList } from "./Dispute";
import { ComposeModal, ReminderModal } from "./Messaging";

const METHOD: Record<string, string> = {
  lockfile: t("Lock dosyası"), manifest: t("Manifest"), "command-output": t("Komut çıktısı"), pkgdb: t("Paket veritabanı"),
  "jar-meta": t("JAR meta verisi"), signature: t("JS / CSS imzası"), sourcemap: "Source map", "cdn-url": t("CDN adresi"),
  "exposed-file": t("Açık dosya"), header: t("HTTP başlığı"), "binary-strings": t("İkili dosya"), "dex-strings": "DEX",
  properties: t("Sürüm dosyası"), sbom: "SBOM", "image-config": t("İmaj yapılandırması"), "pe-version": t("PE sürüm bilgisi"),
  "installed-package": t("Kurulu paket"), "error-page": t("Hata sayfası"), "cms-version": "CMS",
};

function fixRecipe(x: any): { lang: string; file: string; code: string } | null {
  const v = x.upgrade_to;
  if (!v) return null;
  const n = x.component as string;
  switch (x.ecosystem.split(":")[0]) {
    case "npm": return { lang: "bash", file: "npm", code: `npm install ${n}@${v}\n# yarn add ${n}@${v}  ·  pnpm add ${n}@${v}` };
    case "PyPI": return { lang: "bash", file: "pip", code: `pip install "${n}==${v}"\n# requirements.txt → ${n}==${v}` };
    case "Maven": {
      const [g, a] = n.includes(":") ? n.split(":") : ["", n];
      return { lang: "yaml", file: "pom.xml / build.gradle", code: `<dependency>\n  <groupId>${g}</groupId>\n  <artifactId>${a}</artifactId>\n  <version>${v}</version>\n</dependency>\n\n# Gradle: implementation("${g}:${a}:${v}")` };
    }
    case "Go": return { lang: "bash", file: "go", code: `go get ${n}@${v.startsWith("v") ? v : "v" + v}\ngo mod tidy` };
    case "NuGet": return { lang: "bash", file: "dotnet", code: `dotnet add package ${n} --version ${v}` };
    case "Packagist": return { lang: "bash", file: "composer", code: `composer require ${n}:${v}` };
    case "crates.io": return { lang: "bash", file: "cargo", code: `cargo update -p ${n} --precise ${v}` };
    case "RubyGems": return { lang: "bash", file: "bundler", code: `bundle update ${n}\n# Gemfile → gem "${n}", ">= ${v}"` };
    case "Pub": return { lang: "bash", file: "pubspec.yaml", code: `dart pub upgrade ${n}\n# pubspec.yaml → ${n}: ^${v}` };
    case "Debian": case "Ubuntu": return { lang: "bash", file: "apt", code: `apt-get update && apt-get install --only-upgrade ${n}\n# hedef sürüm: ${v} (temel imajı güncellemek genellikle yeterlidir)` };
    case "Alpine": return { lang: "bash", file: "apk", code: `apk update && apk upgrade ${n}\n# hedef sürüm: ${v}` };
    default: return { lang: "bash", file: "", code: `# ${n} → ${v}` };
  }
}

function Score({ label, value, sub, color, pct }: { label: string; value: string; sub?: string; color: string; pct?: number }) {
  return (
    <Card withBorder padding="sm">
      <Group gap="sm" wrap="nowrap">
        {pct !== undefined && <RingProgress size={52} thickness={5} roundCaps sections={[{ value: Math.max(2, pct), color }]} />}
        <div><Text size="xs" c="dimmed">{label}</Text><Text fw={700} size="lg" lh={1.2}>{value}</Text>{sub && <Text size="xs" c="dimmed">{sub}</Text>}</div>
      </Group>
    </Card>
  );
}

function EvidenceTab({ x }: { x: any }) {
  if (!x.evidence.length) return <Text c="dimmed" size="sm">—</Text>;
  return (
    <Stack>
      <Text size="sm" c="dimmed">{t("Bileşenin tespit edildiği yerler. Satır numarası, dosyayı açtığınızda doğrudan ilgili satıra gitmenizi sağlar.")}</Text>
      {x.evidence.map((e: any, i: number) => {
        const parts = String(e.location).split(/!\/|\//).filter(Boolean);
        const isUrl = String(e.location).includes("://");
        return (
          <Card withBorder key={i} padding="sm">
            <Group justify="space-between" wrap="nowrap" mb={6}>
              <Group gap="xs" wrap="nowrap" style={{ minWidth: 0 }}>
                <ThemeIcon variant="light" size="md">{isUrl ? <IconLink size={14} /> : <IconFile size={14} />}</ThemeIcon>
                {isUrl ? <Anchor href={e.location} target="_blank" rel="noreferrer noopener" size="sm" style={{ wordBreak: "break-all" }}>{e.location}</Anchor>
                  : <Text size="sm" ff="monospace" style={{ wordBreak: "break-all" }}>{parts.slice(0, -1).map((p: string, j: number) => <Text key={j} span c="dimmed">{p}/</Text>)}<b>{parts[parts.length - 1]}</b></Text>}
              </Group>
              <Group gap={6} wrap="nowrap">
                {e.line && <Badge variant="filled" color="dark" size="sm">{t("satır {n}", { n: e.line })}</Badge>}
                <Badge variant="light" size="sm" tt="none">{METHOD[e.method] ?? e.method}</Badge>
              </Group>
            </Group>
            {e.snippet && (
              <Paper bg="#0d1117" p={8} radius="sm" style={{ fontFamily: "ui-monospace, monospace", fontSize: 12.5, color: "#e6edf3", overflowX: "auto" }}>
                <span style={{ color: "#484f58", marginRight: 12 }}>{e.line}</span>{e.snippet}
              </Paper>
            )}
            {e.detail && e.detail !== e.snippet && <Text size="xs" c="dimmed" mt={6}>{e.detail}</Text>}
          </Card>
        );
      })}
    </Stack>
  );
}

function HistoryTab({ x, id }: { x: any; id: number }) {
  const qc = useQueryClient();
  const [comment, setComment] = useState("");
  async function add() {
    try { await api(`/findings/${id}/comments`, { body: { text: comment } }); setComment(""); qc.invalidateQueries({ queryKey: ["finding", id] }); } catch (e) { fail(e); }
  }
  const who = (c: any) => c.user_name || c.user || t("Sistem");
  const item = (c: any) => {
    const m = c.meta ?? {};
    switch (c.kind) {
      case "status": return { icon: IconRefresh, color: "blue", text: <>{t("{who} durumu değiştirdi", { who: who(c) })}: <StatusBadge status={m.from} /> <IconArrowRight size={12} /> <StatusBadge status={m.to} /></>, quote: m.reason };
      case "approval_request": return { icon: IconSend, color: "orange", text: <>{t("{who} onay istedi", { who: who(c) })}: <StatusBadge status={m.to} /></>, quote: m.reason };
      case "approval_decided": return m.approved
        ? { icon: IconCheck, color: "green", text: <>{t("{who} talebi onayladı", { who: who(c) })}: <StatusBadge status={m.to} /></>, quote: m.note }
        : { icon: IconX, color: "red", text: <>{t("{who} talebi reddetti", { who: who(c) })} ({STATUS_LABEL[m.to]})</>, quote: m.note };
      case "assigned": return { icon: IconUserCheck, color: "indigo", text: <>{t("{who} bulguyu {to} kişisine atadı", { who: who(c), to: m.to_name || m.to })}{m.due ? ` · ${t("son tarih")} ${fmtDay(m.due)}` : ""}</>, quote: m.note };
      case "shared": return { icon: IconShare, color: "teal", text: t("{who} bulguyu paylaştı: {to}", { who: who(c), to: (m.to ?? []).join(", ") }), quote: m.message };
      case "jira": return { icon: IconTicket, color: "blue", text: <>{t("{who} Jira kaydı açtı", { who: who(c) })}: {m.url ? <Anchor href={m.url} target="_blank" rel="noreferrer">{m.key}</Anchor> : m.key}</> };
      case "scan_fixed": return { icon: IconCheck, color: "green", text: t("Tarama #{n}: bileşen artık görülmüyor, bulgu kapandı", { n: m.scan }) };
      case "scan_reopened": return { icon: IconAlertTriangle, color: "red", text: t("Tarama #{n}: bulgu yeniden görüldü ve açıldı", { n: m.scan }) };
      case "dispute": return { icon: IconGavel, color: "grape", text: m.event === "resolved" ? t("Tartışma sonuçlandı: {title}", { title: m.title }) : t("{who} tartışma açtı: {title}", { who: who(c), title: m.title }), quote: m.resolution };
      default: return null;
    }
  };
  return (
    <Stack>
      <Timeline bulletSize={26} lineWidth={2}>
        {x.comments.map((c: any) => {
          const it = item(c);
          if (!it) {
            return (
              <Timeline.Item key={c.id} bullet={<Avatar size={24} radius="xl" color="indigo">{(c.user || "?")[0].toUpperCase()}</Avatar>}
                title={<Group gap={6}><Text size="sm" fw={600}>{who(c)}</Text><Text size="xs" c="dimmed">{fmtDate(c.at)}</Text></Group>}>
                <Paper withBorder p="sm" radius="md" mt={4} bg="var(--mantine-color-default-hover)"><Text size="sm" style={{ whiteSpace: "pre-wrap" }}>{c.text}</Text></Paper>
              </Timeline.Item>
            );
          }
          return (
            <Timeline.Item key={c.id} bullet={<it.icon size={13} />} color={it.color}
              title={<Group gap={6} wrap="wrap"><Text size="sm" component="div" style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>{it.text}</Text><Text size="xs" c="dimmed">{fmtDate(c.at)}</Text></Group>}>
              {it.quote && <Blockquote p="xs" mt={6} color={it.color} icon={null}><Text size="sm">{it.quote}</Text></Blockquote>}
            </Timeline.Item>
          );
        })}
      </Timeline>
      {x.comments.length === 0 && <Text size="sm" c="dimmed">{t("Henüz kayıt yok")}</Text>}
      <Textarea placeholder={t("Yorum ekle — birini anmak için @eposta yazın")} value={comment} onChange={(e) => setComment(e.currentTarget.value)} autosize minRows={2} />
      <Group justify="flex-end"><Button size="xs" leftSection={<IconMessage2 size={14} />} onClick={add} disabled={!comment.trim()}>{t("Yorum ekle")}</Button></Group>
    </Stack>
  );
}

export function FindingDetail({ id }: { id: number }) {
  const qc = useQueryClient();
  const f = useQuery<any>({ queryKey: ["finding", id], queryFn: () => api(`/findings/${id}`) });
  const [status, setStatus] = useState<string | null>(null);
  const [reason, setReason] = useState("");
  const [assign, setAssign] = useState(false);
  const [share, setShare] = useState(false);
  const [pushing, setPushing] = useState(false);
  const [msg, setMsg] = useState(false);
  const [remind, setRemind] = useState(false);
  const jira = useJiraPicker();
  if (!f.data) return <Loader />;
  const x = f.data;
  const needReason = ["accepted_risk", "false_positive", "not_affected"].includes(status ?? "");
  const recipe = fixRecipe(x);
  async function saveStatus() {
    try {
      const r = await api(`/findings/${id}`, { method: "PATCH", body: { status, reason } });
      if (r.approval) ok(t("Onaya gönderildi: {who}", { who: r.approval.approvers.map((a: any) => a.email).join(", ") }));
      else ok(t("Durum güncellendi"));
      setStatus(null); setReason("");
      qc.invalidateQueries({ queryKey: ["finding", id] }); qc.invalidateQueries({ queryKey: ["findings"] }); qc.invalidateQueries({ queryKey: ["approvals-count"] });
    } catch (e) { fail(e); }
  }
  async function toJira() {
    setPushing(true);
    try {
      let r;
      try { r = await api(`/findings/${id}/jira`, { method: "POST" }); }
      catch (e: any) {
        if (!String(e?.message ?? "").includes("seçin")) throw e;
        const inst = await jira.choose();
        if (inst === undefined) return;
        r = await api(`/findings/${id}/jira`, { body: { instance_id: inst } });
      }
      ok(t("Jira kaydı: {key}", { key: r.key })); qc.invalidateQueries({ queryKey: ["finding", id] });
    } catch (e) { fail(e); } finally { setPushing(false); }
  }
  const cve = x.aliases.find((a: string) => a.startsWith("CVE-"));
  const ghsa = [x.vuln_id, ...x.aliases].find((a: string) => a.startsWith("GHSA-"));
  return (
    <Stack>
      {jira.modal}
      <Card withBorder padding="md" style={{ borderLeft: `4px solid ${SEV_COLOR[x.severity] ?? "#999"}` }}>
        <Group justify="space-between" align="flex-start" wrap="nowrap">
          <div style={{ minWidth: 0 }}>
            <Group gap="xs" mb={4}><SevBadge sev={x.severity} /><StatusBadge status={x.status} />{x.kev && <Badge color="red" variant="filled" leftSection={<IconBolt size={12} />}>{t("Aktif sömürülüyor")}</Badge>}{x.malicious && <Badge color="dark">{t("Zararlı")}</Badge>}</Group>
            <Text fw={800} size="xl" lh={1.2}>{cve ?? x.vuln_id}</Text>
            <Text size="xs" c="dimmed">{[x.vuln_id, ...x.aliases].filter((a: string) => a !== cve).join(" · ")}</Text>
            <Text mt={6}>{x.summary}</Text>
          </div>
        </Group>
        <Group gap="xs" mt="sm">
          <Badge variant="light" size="lg" tt="none">{x.component} <b>{x.version}</b></Badge>
          <Badge variant="outline" size="lg" tt="none">{x.ecosystem}</Badge>
          <Badge variant="outline" size="lg" tt="none">{x.target}</Badge>
        </Group>
      </Card>

      <Tabs defaultValue="summary" keepMounted={false}>
        <Tabs.List grow mb="md">
          <Tabs.Tab value="summary" leftSection={<IconInfoCircle size={14} />}>{t("Özet")}</Tabs.Tab>
          <Tabs.Tab value="evidence" leftSection={<IconFile size={14} />}>{t("Kanıt")} <Badge size="xs" variant="light" ml={4}>{x.evidence.length}</Badge></Tabs.Tab>
          <Tabs.Tab value="history" leftSection={<IconHistory size={14} />}>{t("Geçmiş")} <Badge size="xs" variant="light" ml={4}>{x.comments.length}</Badge></Tabs.Tab>
          <Tabs.Tab value="dispute" leftSection={<IconGavel size={14} />}>{t("Tartışma")}</Tabs.Tab>
        </Tabs.List>

        <Tabs.Panel value="summary">
          <Stack>
            <SimpleGrid cols={{ base: 2, sm: 4 }}>
              <Score label={t("Şiddet")} value={SEV_LABEL[x.severity] ?? x.severity} color={SEV_COLOR[x.severity] ?? "gray"} pct={{ CRITICAL: 100, HIGH: 75, MEDIUM: 50, LOW: 25 }[x.severity as string] ?? 10} />
              <Score label="CVSS" value={x.cvss != null ? String(x.cvss) : "—"} color="orange" pct={x.cvss != null ? x.cvss * 10 : 0} />
              <Score label="EPSS" value={x.epss != null ? fmtPct(x.epss) : "—"} sub={t("30 gün içinde istismar olasılığı")} color="grape" pct={x.epss != null ? x.epss * 100 : 0} />
              <Score label="KEV" value={x.kev ? t("Evet") : t("Hayır")} sub={t("CISA aktif istismar listesi")} color={x.kev ? "red" : "gray"} pct={x.kev ? 100 : 0} />
            </SimpleGrid>

            <Card withBorder>
              <Group gap="xs" mb="xs"><ThemeIcon variant="light" color="green"><IconTool size={16} /></ThemeIcon><Text fw={700}>{t("Ne yapmalı?")}</Text></Group>
              {recipe ? (
                <Stack gap="xs">
                  <Text size="sm">{t("{c} bileşenini {v} sürümüne yükseltin; bu sürüm bilinen tüm açıkları kapatır.", { c: x.component, v: x.upgrade_to })}</Text>
                  <CodeBlock code={recipe.code} filename={recipe.file} lang={recipe.lang} />
                  {x.fixed_versions.length > 1 && <Text size="xs" c="dimmed">{t("Düzeltilmiş sürümler")}: {x.fixed_versions.join(", ")}</Text>}
                </Stack>
              ) : (
                <Text size="sm">{t("Henüz düzeltilmiş sürüm yayımlanmadı. Geçici önlem: etkilenen özelliği devre dışı bırakın, erişimi kısıtlayın veya WAF kuralı ekleyin; yeni sürüm çıktığında tekrar tarayın.")}</Text>
              )}
            </Card>

            <Card withBorder>
              <Group justify="space-between">
                <div>
                  <Text fw={600} size="sm">{t("Atanan")}</Text>
                  {x.assignee ? <Group gap="xs" mt={4}><Avatar size="sm" radius="xl" color="indigo">{x.assignee.email[0].toUpperCase()}</Avatar><Text size="sm">{x.assignee.name || x.assignee.email}</Text>
                    {x.due_date && <Badge size="sm" variant="light" color={new Date(x.due_date) < new Date() ? "red" : "gray"}>{t("Son tarih")}: {fmtDay(x.due_date)}</Badge>}</Group>
                    : <Text size="sm" c="dimmed">{t("Kimseye atanmadı")}</Text>}
                </div>
                <Group gap="xs">
                  <Button size="xs" variant="light" leftSection={<IconUserCheck size={14} />} onClick={() => setAssign(true)}>{x.assignee ? t("Değiştir") : t("Ata")}</Button>
                  <Button size="xs" variant="default" leftSection={<IconShare size={14} />} onClick={() => setShare(true)}>{t("Paylaş")}</Button>
                  <Button size="xs" variant="default" leftSection={<IconMail size={14} />} onClick={() => setMsg(true)}>{t("Mesaj")}</Button>
                  <Button size="xs" variant="default" leftSection={<IconAlarm size={14} />} onClick={() => setRemind(true)}>{t("Hatırlat")}</Button>
                  {x.jira_key ? <Button component="a" href={x.jira_url} target="_blank" rel="noreferrer" size="xs" variant="light" color="blue" leftSection={<IconTicket size={14} />}>{x.jira_key}</Button>
                    : <Button size="xs" variant="default" leftSection={<IconTicket size={14} />} onClick={toJira} loading={pushing}>{t("Jira'ya ekle")}</Button>}
                </Group>
              </Group>
              <AssignModal opened={assign} onClose={() => setAssign(false)} findingId={id} current={x} />
              <ShareModal opened={share} onClose={() => setShare(false)} findingId={id} />
              <ComposeModal opened={msg} onClose={() => setMsg(false)} findingId={id} subject={`${cve ?? x.vuln_id} — ${x.component} ${x.version}`} />
              <ReminderModal opened={remind} onClose={() => setRemind(false)} link={`/findings?open=${id}`} text={`${cve ?? x.vuln_id} — ${x.component} ${x.version}`} />
            </Card>

            <Card withBorder>
              <Text fw={600} size="sm" mb="xs">{t("Durumu değiştir")}</Text>
              <Group align="flex-end" wrap="nowrap">
                <Select style={{ flex: 1 }} data={Object.entries(STATUS_LABEL).filter(([k]) => k !== "fixed").map(([value, label]) => ({ value, label }))} value={status} onChange={setStatus} placeholder={t("Yeni durum")} />
                <Button onClick={saveStatus} disabled={!status || (needReason && !reason.trim())}>{t("Kaydet")}</Button>
              </Group>
              {status && <Textarea mt="xs" placeholder={needReason ? t("Gerekçe (zorunlu; raporda görünür)") : t("Not (isteğe bağlı)")} value={reason} onChange={(e) => setReason(e.currentTarget.value)} autosize minRows={2} />}
              <Text size="xs" c="dimmed" mt={6}>{t("\"Düzeltildi\" durumu yalnızca yeniden taramada bileşen artık görülmediğinde otomatik atanır.")}</Text>
            </Card>

            <Card withBorder>
              <Text fw={600} size="sm" mb="xs">{t("Kaynaklar")}</Text>
              <Group gap="xs">
                {cve && <Button component="a" href={`https://nvd.nist.gov/vuln/detail/${cve}`} target="_blank" rel="noreferrer" size="xs" variant="default" leftSection={<IconLink size={14} />}>NVD</Button>}
                <Button component="a" href={`https://osv.dev/vulnerability/${encodeURIComponent(x.vuln_id)}`} target="_blank" rel="noreferrer" size="xs" variant="default" leftSection={<IconLink size={14} />}>OSV</Button>
                {ghsa && <Button component="a" href={`https://github.com/advisories/${ghsa}`} target="_blank" rel="noreferrer" size="xs" variant="default" leftSection={<IconBrandGithub size={14} />}>GitHub</Button>}
                {x.purl && <Tooltip label={x.purl}><Code>{x.purl.length > 48 ? x.purl.slice(0, 48) + "…" : x.purl}</Code></Tooltip>}
              </Group>
              <Text size="xs" c="dimmed" mt="xs">{t("İlk görülme")}: {fmtDate(x.first_seen_at)} · {t("Son görülme")}: {fmtDate(x.last_seen_at)} · {t("Güven")}: {x.confidence}</Text>
            </Card>
          </Stack>
        </Tabs.Panel>
        <Tabs.Panel value="evidence"><EvidenceTab x={x} /></Tabs.Panel>
        <Tabs.Panel value="history"><HistoryTab x={x} id={id} /></Tabs.Panel>
        <Tabs.Panel value="dispute"><DisputeList findingId={id} /></Tabs.Panel>
      </Tabs>
    </Stack>
  );
}
