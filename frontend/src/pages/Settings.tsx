import { Anchor, Alert, Badge, Button, Card, Code, Grid, Group, Loader, NumberInput, Paper, PasswordInput, ScrollArea, Select, SimpleGrid, Stack, Switch, Table, Tabs, Text, Textarea, TextInput, ThemeIcon, UnstyledButton } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconAdjustments, IconArchive, IconCheck, IconDatabase, IconInfoCircle, IconKey, IconLock, IconMail, IconPlugConnected, IconRadar, IconSettings, IconRouteAltLeft, IconShieldLock, IconStack2, IconTicket, IconTool, IconX } from "@tabler/icons-react";
import { CodeBlock } from "../components/CodeBlock";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, fmtDate, SEV_LABEL, User } from "../api";
import { fail, JobBadge, ok, PageHeader } from "../components/ui";
import { SchedulesCard } from "../components/Schedules";
import { JiraInstances } from "../components/JiraInstances";
import { t, LANGS } from "../i18n";

const notifyFail = (m: string) => notifications.show({ color: "red", title: t("Hata"), message: m });

export default function Settings({ user }: { user: User }) {
  const admin = user.role === "admin";
  return (
    <>
      <PageHeader title={t("Ayarlar & zafiyet veritabanı")} sub={t("Uygulamanın davranışı, entegrasyonlar ve zafiyet verisi")} />
      <Tabs defaultValue={admin ? "app" : "vulndb"}>
        <Tabs.List mb="md">
          {admin && <Tabs.Tab value="app" leftSection={<IconSettings size={16} />}>{t("Uygulama ayarları")}</Tabs.Tab>}
          <Tabs.Tab value="vulndb" leftSection={<IconDatabase size={16} />}>{t("Zafiyet veritabanı")}</Tabs.Tab>
        </Tabs.List>
        {admin && <Tabs.Panel value="app"><AppSettings /></Tabs.Panel>}
        <Tabs.Panel value="vulndb">
          <SimpleGrid cols={{ base: 1, lg: 2 }}>
            <VulnDb admin={admin} />
            {admin && <SchedulesCard kind="db_update" title={t("Zamanlanmış veritabanı güncellemesi")}
              help={t("Yeni yayımlanan zafiyetlerin görünmesi için önerilen: her gün bir kez. İnternetsiz kurulumda kullanmayın.")} />}
          </SimpleGrid>
        </Tabs.Panel>
      </Tabs>
    </>
  );
}

function VulnDb({ admin }: { admin: boolean }) {
  const qc = useQueryClient();
  const st = useQuery<any>({ queryKey: ["vulndb"], queryFn: () => api("/vulndb"), refetchInterval: (q) => (q.state.data?.last_job && ["queued", "running"].includes(q.state.data.last_job.status) ? 3000 : false) });
  const [fromDir, setFromDir] = useState("");
  const [noNvd, setNoNvd] = useState(false);
  const jobId = st.data?.last_job?.id;
  const job = useQuery<any>({ queryKey: ["job", jobId], queryFn: () => api(`/jobs/${jobId}`), enabled: !!jobId, refetchInterval: 3000 });
  async function update() {
    try { await api("/vulndb/update", { body: { from_dir: fromDir || null, no_nvd: noNvd } }); ok(t("Güncelleme kuyruğa alındı")); qc.invalidateQueries({ queryKey: ["vulndb"] }); } catch (e) { fail(e); }
  }
  const s = st.data;
  return (
    <Card withBorder>
      <Text fw={600} mb="xs">{t("Zafiyet veritabanı")}</Text>
      {st.isLoading && <Loader size="sm" />}
      {s && <>
        <Text size="xs" c="dimmed" mb="sm" ff="monospace">{s.path}</Text>
        <Table mb="sm">
          <Table.Tbody>
            {[[t("OSV kayıt"), s.stats.vulns], ["EPSS skoru", s.stats.epss], ["KEV", s.stats.kev],
              ...Object.entries(s.stats.by_ecosystem ?? {}).sort((x: any, y: any) => y[1] - x[1]).slice(0, 8).map(([e, n]) => [`  ${e}`, n])].map(([k, v]) => (
              <Table.Tr key={k as string}><Table.Td>{k}</Table.Td><Table.Td ta="right" fw={600}>{v ?? 0}</Table.Td></Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
        <Text size="xs" c="dimmed">{t("Kaynakların güncelliği için: Sistem durumu sayfası")}</Text>
      </>}
      {admin && (
        <Stack mt="md" gap="xs">
          <Alert variant="light" color="blue">
            {t("İnternetten güncelleme OSV, EPSS, KEV ve (anahtar varsa) NVD verilerini indirir. Kapalı ağ kurulumunda verileri başka bir makinede")}<Code>{t("scakit db download klasör")}</Code> {t("ile indirip sunucuya kopyalayın ve aşağıya klasör yolunu yazın.")} <Anchor component={Link} to="/scakit" size="sm">{t("scakit nedir, nasıl kurulur? →")}</Anchor></Alert>
          <TextInput label={t("Klasörden içe aktar (isteğe bağlı)")} placeholder={t("/data/vulndb-offline")} value={fromDir} onChange={(e) => setFromDir(e.currentTarget.value)} />
          <Switch label={t("NVD verilerini atla")} checked={noNvd} onChange={(e) => setNoNvd(e.currentTarget.checked)} />
          <Group justify="flex-end"><Button onClick={update} disabled={!!s?.last_job && ["queued", "running"].includes(s.last_job.status)}>{t("Veritabanını güncelle")}</Button></Group>
        </Stack>
      )}
      {job.data && (
        <Card withBorder mt="md" p="xs">
          <Group gap="xs" mb="xs"><Text size="sm">{t("Son güncelleme işi")}</Text><JobBadge status={job.data.status} /><Text size="xs" c="dimmed">{fmtDate(job.data.created_at)}</Text></Group>
          {job.data.log && <ScrollArea h={200}><Code block>{job.data.log}</Code></ScrollArea>}
        </Card>
      )}
    </Card>
  );
}

const SELECTS: Record<string, { value: string; label: string }[]> = {
  smtp_security: [{ value: "starttls", label: t("STARTTLS (587)") }, { value: "ssl", label: t("SSL/TLS (465)") }, { value: "none", label: t("Şifresiz (önerilmez)") }],
  jira_auth: [{ value: "cloud", label: t("Jira Cloud (e-posta + API token)") }, { value: "server", label: t("Jira Server / Data Center (kişisel erişim token'ı)") }],
  jira_auto_min_severity: [{ value: "", label: t("Kapalı (yalnızca elle)") }, ...["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((v) => ({ value: v, label: t("{sev} ve üzeri", { sev: SEV_LABEL[v] }) }))],
  default_report_lang: LANGS,
};
const SWITCHES = new Set(["allow_internal_targets", "jira_comment_on_fix", "approval_required", "oidc_enabled", "maintenance_mode", "toolset_enabled", "toolset_customers"]);
const NUMBERS: Record<string, [number, number, number?]> = {
  web_default_max_pages: [1, 200], job_timeout_minutes: [5, 1440], job_memory_mb: [256, 131072], retention_scans_per_target: [0, 10000],
  retention_scan_days: [0, 3650], audit_retention_days: [0, 3650], smtp_port: [1, 65535], login_max_failures: [1, 100], login_window_minutes: [1, 1440],
  api_rate_per_minute: [0, 100000], toolset_rate_per_minute: [1, 600], web_default_delay: [0.2, 10, 1],
  queue_concurrency: [0, 32], queue_gap_seconds: [0, 3600],
};
const SUFFIX: Record<string, string> = { web_default_delay: t("sn"), job_timeout_minutes: t("dk"), job_memory_mb: "MB", retention_scan_days: t("gün"), audit_retention_days: t("gün"), login_window_minutes: t("dk"), queue_gap_seconds: t("sn") };

const SECTIONS: { id: string; icon: any; title: string; desc: string; keys: string[]; test?: "smtp" | "jira" | "oidc" }[] = [
  { id: "general", icon: IconAdjustments, title: t("Genel"), desc: t("Adres, saat dilimi, rapor dili ve onay süreci"), keys: ["public_url", "timezone", "default_report_lang", "approval_required"] },
  { id: "scan", icon: IconRadar, title: t("Tarama"), desc: t("Web taraması, iş sınırları, zafiyet verisi"), keys: ["web_default_delay", "web_default_max_pages", "allow_internal_targets", "job_timeout_minutes", "job_memory_mb", "vulndb_path", "nvd_api_key"] },
  { id: "security", icon: IconShieldLock, title: t("Güvenlik ve erişim"), desc: t("Bakım modu, giriş denemesi ve API hız sınırları"), keys: ["maintenance_mode", "maintenance_message", "login_max_failures", "login_window_minutes", "api_rate_per_minute"] },
  { id: "retention", icon: IconArchive, title: t("Saklama"), desc: t("Eski taramalar ve denetim kaydı ne kadar tutulur"), keys: ["retention_scans_per_target", "retention_scan_days", "audit_retention_days"] },
  { id: "smtp", icon: IconMail, title: t("E-posta (SMTP)"), desc: t("E-posta bildirimleri bu sunucu üzerinden gider"), keys: ["smtp_host", "smtp_port", "smtp_security", "smtp_user", "smtp_password", "smtp_from"], test: "smtp" },
  { id: "jira", icon: IconTicket, title: "Jira", desc: t("Birden fazla Jira ve kimlerin kullanabileceği"), keys: [] },
  { id: "sso", icon: IconKey, title: t("Kurumsal giriş (SSO)"), desc: t("OpenID Connect: Entra ID, Okta, Keycloak, Google…"), keys: ["oidc_enabled", "oidc_issuer", "oidc_client_id", "oidc_client_secret", "oidc_button_label"], test: "oidc" },
  { id: "queue", icon: IconStack2, title: t("Tarama kuyruğu"), desc: t("Aynı anda kaç tarama, aralarında ne kadar bekleme"), keys: ["queue_concurrency", "queue_gap_seconds"] },
  { id: "egress", icon: IconRouteAltLeft, title: t("Çıkış noktaları"), desc: t("Coğrafi engel ve IP izin listesi için proxy'ler"), keys: ["egress_proxies"] },
  { id: "toolset", icon: IconTool, title: t("Araç seti"), desc: t("HTTP istemcisi ve ping kullanımı"), keys: ["toolset_enabled", "toolset_customers", "toolset_rate_per_minute"] },
];
const HELP: Record<string, string> = {
  general: t("Arayüz adresi bildirim e-postalarındaki ve Jira kayıtlarındaki bağlantılar için kullanılır."),
  scan: t("Bu değerler yeni web hedefleri için varsayılandır; her hedef kendi ayarıyla değiştirebilir."),
  security: t("Bakım modunu Sistem durumu sayfasından da açıp kapatabilirsiniz. Hız sınırları sunucu süreci başına uygulanır."),
  retention: t("Bulgular hiçbir zaman silinmez; yalnızca eski tarama klasörleri ve kayıtlar temizlenir. 0 = sınırsız."),
  smtp: t("Kaydettikten sonra \"Deneme e-postası gönder\" ile ayarları doğrulayın; ileti sizin adresinize gider."),
  jira: t("Her müşteri veya ekip için ayrı Jira bağlantısı ekleyin ve kimlerin kullanabileceğini belirleyin. Kullanıcı \"Jira'ya ekle\" dediğinde, yetkili olduğu birden fazla bağlantı varsa hangisi olduğu sorulur; projeye varsayılan Jira atanırsa sorulmaz. Aynı bulgu için ikinci kayıt açılmaz."),
  sso: t("Kimlik sağlayıcıda uygulama oluştururken aşağıdaki yönlendirme adresini girin. Yalnızca Le Fureteur'de hesabı olan kullanıcılar giriş yapabilir."),
  queue: t("Sıradaki taramaların sırasını Taramalar sayfasındaki kuyruk panelinden değiştirebilirsiniz (en öne al, sona at). Eşzamanlılık her worker için geçerlidir; 0 = worker başlatılırken verilen değer."),
  egress: t("Hedef bir ülke veya IP izin listesiyle kısıtlıysa, izinli konumdaki bir proxy'yi burada tanımlayın (HTTP veya SOCKS5). Hedefler Otomatik modda engel görünce bunları sırayla dener ya da hedef ayarından biri sabitlenir. Değer şifreli saklanır; kullanıcılar yalnızca adları görür."),
  toolset: t("Ağ araçları iç ağ adreslerine hiçbir koşulda bağlanmaz. Müşteriler açılırsa yalnızca izinli alan adlarına istek atabilir."),
};
const LABEL: Record<string, string> = { smtp_security: t("Bağlantı güvenliği"), jira_auth: t("Kimlik doğrulama türü"), jira_auto_min_severity: t("Taramada otomatik Jira kaydı") };
const clean = (d: string) => t(d).replace(/\s*\(1\/0\)\s*$/, "");

function AppSettings() {
  const qc = useQueryClient();
  const settings = useQuery<any[]>({ queryKey: ["settings"], queryFn: () => api("/settings") });
  const [sec, setSec] = useState<string>(() => {
    const g = new URLSearchParams(window.location.search).get("group");
    if (g) return g;
    try { return localStorage.getItem("lf_settings_sec") ?? "general"; } catch { return "general"; }
  });
  const [vals, setVals] = useState<Record<string, string>>({});
  const [errs, setErrs] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<any>(null);
  const byKey = Object.fromEntries((settings.data ?? []).map((s) => [s.key, s]));
  const reset = () => { if (settings.data) setVals(Object.fromEntries(settings.data.filter((s) => !s.secret).map((s) => [s.key, s.value]))); };
  useEffect(reset, [settings.data]);
  const section = SECTIONS.find((x) => x.id === sec) ?? SECTIONS[0];
  const known = new Set(SECTIONS.flatMap((x) => x.keys));
  const other = (settings.data ?? []).filter((s) => !known.has(s.key)).map((s) => s.key);
  const keys = [...section.keys, ...(section.id === "general" ? other : [])].filter((k) => byKey[k]);
  const dirty = keys.some((k) => byKey[k].secret ? !!vals[k] : (vals[k] ?? "") !== byKey[k].value);
  function pick(id: string) { setSec(id); setErrs({}); setTestResult(null); try { localStorage.setItem("lf_settings_sec", id); } catch {  } }
  async function save(silent = false): Promise<boolean> {
    setBusy("save"); setErrs({});
    try {
      const body = Object.fromEntries(keys.filter((k) => !byKey[k].secret || vals[k]).map((k) => [k, vals[k] ?? ""]));
      await api("/settings", { method: "PUT", body });
      ["settings", "vulndb", "jira-status", "public-status", "tools-status"].forEach((q) => qc.invalidateQueries({ queryKey: [q] }));
      setVals((v) => Object.fromEntries(Object.entries(v).filter(([k]) => !byKey[k]?.secret)));
      if (!silent) ok(t("Ayarlar kaydedildi"));
      return true;
    } catch (e: any) {
      if (e?.detail?.fields) { setErrs(e.detail.fields); notifyFail(t("Bazı ayarlar geçersiz; işaretli alanları düzeltin")); } else fail(e);
      return false;
    } finally { setBusy(null); }
  }
  async function runTest() {
    if (dirty && !(await save(true))) return;
    setBusy("test"); setTestResult(null);
    try {
      if (section.test === "smtp") { const r = await api("/settings/smtp/test", { method: "POST" }); setTestResult({ ok: true, text: t("Deneme e-postası gönderildi: {to}", { to: r.to }) }); }
      if (section.test === "jira") { const r = await api("/jira/test", { method: "POST" }); setTestResult({ ok: true, text: t("Jira bağlantısı tamam: {user}", { user: r.user }) + (r.project ? ` · ${r.project}` : "") }); }
      if (section.test === "oidc") { const r = await api("/settings/oidc/test", { method: "POST" }); setTestResult({ ok: true, text: t("Kimlik sağlayıcıya ulaşıldı: {n} imza anahtarı", { n: r.keys }), extra: r }); }
    } catch (e: any) { setTestResult({ ok: false, text: t(e?.message ?? String(e)) }); } finally { setBusy(null); }
  }
  async function clearSecret(key: string) {
    if (!confirm(t("Kayıtlı gizli değer silinsin mi?"))) return;
    try { await api("/settings", { method: "PUT", body: { [key]: "", _clear: [key] } }); qc.invalidateQueries({ queryKey: ["settings"] }); } catch (e) { fail(e); }
  }
  function field(k: string) {
    const s = byKey[k];
    const err = errs[k] ? t(errs[k]) : undefined;
    const label = LABEL[k] ?? clean(s.description);
    if (s.secret) return (
      <div key={k}>
        <PasswordInput label={label} error={err} placeholder={s.is_set ? t("•••••••• (ayarlı — değiştirmek için yazın)") : t("ayarlı değil")} value={vals[k] ?? ""} onChange={(e) => setVals({ ...vals, [k]: e.currentTarget.value })} autoComplete="new-password" />
        <Group gap="xs" mt={4}>{s.is_set ? <Badge color="green" variant="light" size="sm" leftSection={<IconLock size={10} />}>{t("Ayarlı (şifreli saklanır)")}</Badge> : <Badge color="gray" variant="light" size="sm">{t("Ayarlı değil")}</Badge>}
          {s.is_set && <Button size="compact-xs" variant="subtle" color="red" onClick={() => clearSecret(k)}>{t("Kaldır")}</Button>}</Group>
      </div>
    );
    if (SWITCHES.has(k)) return (
      <Paper key={k} withBorder p="sm" radius="md">
        <Switch label={label} checked={vals[k] === "1"} onChange={(e) => setVals({ ...vals, [k]: e.currentTarget.checked ? "1" : "0" })} error={err}
          description={k === "allow_internal_targets" ? t("Açıkken yalnızca yönetici / analist iç ağ adresi ekleyebilir; müşteriler yine izinli alan adlarıyla sınırlıdır.") : k === "maintenance_mode" ? t("Açıkken yönetici dışındaki herkes engellenir.") : undefined} />
      </Paper>
    );
    if (SELECTS[k]) return <Select key={k} label={label} error={err} data={SELECTS[k]} value={vals[k] ?? ""} onChange={(v) => setVals({ ...vals, [k]: v ?? "" })} allowDeselect={false} />;
    if (NUMBERS[k]) { const [min, max, dec] = NUMBERS[k]; return <NumberInput key={k} label={label} error={err} min={min} max={max} decimalScale={dec ?? 0} step={dec ? 0.5 : 1} rightSection={SUFFIX[k] ? <Text size="xs" c="dimmed" pr={28}>{SUFFIX[k]}</Text> : undefined} rightSectionWidth={SUFFIX[k] ? 60 : undefined} value={vals[k] === "" ? "" : Number(vals[k] ?? 0)} onChange={(v) => setVals({ ...vals, [k]: String(v) })} description={t("{min} – {max}", { min, max })} />; }
    if (k === "maintenance_message") return <Textarea key={k} label={label} error={err} value={vals[k] ?? ""} onChange={(e) => setVals({ ...vals, [k]: e.currentTarget.value })} autosize minRows={2} maxLength={500} />;
    return <TextInput key={k} label={label} error={err} value={vals[k] ?? ""} onChange={(e) => setVals({ ...vals, [k]: e.currentTarget.value })} />;
  }
  if (settings.isLoading) return <Loader size="sm" />;
  return (
    <Grid>
      <Grid.Col span={{ base: 12, md: 4 }}>
        <Stack gap={6}>
          {SECTIONS.map((x) => (
            <UnstyledButton key={x.id} onClick={() => pick(x.id)} p="sm" style={{ borderRadius: 10, border: "1px solid var(--mantine-color-default-border)", background: sec === x.id ? "var(--mantine-primary-color-light)" : "var(--mantine-color-body)" }}>
              <Group wrap="nowrap" gap="sm">
                <ThemeIcon variant={sec === x.id ? "filled" : "light"} size={36} radius="md"><x.icon size={18} /></ThemeIcon>
                <div style={{ minWidth: 0 }}><Text size="sm" fw={700}>{x.title}</Text><Text size="xs" c="dimmed" lineClamp={1}>{x.desc}</Text></div>
              </Group>
            </UnstyledButton>
          ))}
        </Stack>
      </Grid.Col>
      <Grid.Col span={{ base: 12, md: 8 }}>
        <Card withBorder>
          <Group gap="sm" mb="xs"><ThemeIcon size={40} radius="md" variant="light"><section.icon size={22} /></ThemeIcon><div><Text fw={800} size="lg">{section.title}</Text><Text size="sm" c="dimmed">{section.desc}</Text></div></Group>
          {HELP[section.id] && <Alert variant="light" color="blue" icon={<IconInfoCircle size={16} />} my="sm">{HELP[section.id]}</Alert>}
          {section.id === "sso" && <CodeBlock code={`${(byKey.public_url?.value || window.location.origin).replace(/\/$/, "")}/api/auth/oidc/callback`} filename={t("Yönlendirme (redirect) adresi")} lang="bash" />}
          {section.id === "jira" ? <div style={{ marginTop: "var(--mantine-spacing-md)" }}><JiraInstances /></div> : <>
          <Stack mt="md">{keys.map(field)}</Stack>
          {testResult && <Alert mt="md" color={testResult.ok ? "green" : "red"} icon={testResult.ok ? <IconCheck size={16} /> : <IconX size={16} />}>{testResult.text}</Alert>}
          <Group justify="space-between" mt="lg">
            <Text size="xs" c={dirty ? "orange" : "dimmed"}>{dirty ? t("Kaydedilmemiş değişiklikler var") : t("Tüm değişiklikler kaydedildi")}</Text>
            <Group>
              {dirty && <Button variant="subtle" color="gray" onClick={() => { reset(); setErrs({}); }}>{t("Vazgeç")}</Button>}
              {section.test && <Button variant="default" leftSection={<IconPlugConnected size={16} />} onClick={runTest} loading={busy === "test"}>{{ smtp: t("Deneme e-postası gönder"), jira: t("Bağlantıyı test et"), oidc: t("Bağlantıyı test et") }[section.test]}</Button>}
              <Button onClick={() => save()} loading={busy === "save"} disabled={!dirty}>{t("Kaydet")}</Button>
            </Group>
          </Group>
          </>}
        </Card>
      </Grid.Col>
    </Grid>
  );
}
