import { ActionIcon, Alert, Anchor, Badge, Button, Card, CopyButton, Group, Loader, Progress, SegmentedControl, SimpleGrid, Switch, Table, Tabs, Text, ThemeIcon, Tooltip } from "@mantine/core";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { IconAlertTriangle, IconCheck, IconCircleCheck, IconCircleX, IconCopy, IconDatabase, IconInfoCircle, IconListCheck, IconPackage, IconRefresh, IconServer, IconShieldSearch, IconTool, IconWorldDownload } from "@tabler/icons-react";
import { CodeBlock } from "../components/CodeBlock";
import { Link } from "react-router-dom";
import { api, fmtDate, fmtSize, User } from "../api";
import { fail, JobBadge, ok, PageHeader, SevBadge } from "../components/ui";
import { MaintenanceCard } from "../components/Maintenance";
import { t } from "../i18n";
import { PRODUCT } from "../brand";

const LEVEL: Record<string, { color: string; label: string; icon: any }> = {
  crit: { color: "red", label: t("Kritik"), icon: IconCircleX },
  warn: { color: "orange", label: t("Uyarı"), icon: IconAlertTriangle },
  info: { color: "blue", label: t("Öneri"), icon: IconInfoCircle },
  ok: { color: "green", label: t("Güncel"), icon: IconCircleCheck },
};
const BUMP: Record<string, { color: string; label: string }> = {
  major: { color: "red", label: t("Ana sürüm") }, minor: { color: "orange", label: t("Ara sürüm") }, patch: { color: "yellow", label: t("Yama") },
  current: { color: "green", label: t("Güncel") }, error: { color: "gray", label: t("Sorgulanamadı") },
};

function Level({ level }: { level: string }) {
  const L = LEVEL[level];
  return <Badge miw="fit-content" styles={{ label: { overflow: "visible" } }} color={L.color} variant="light" leftSection={<L.icon size={12} />}>{L.label}</Badge>;
}

function checkText(c: any): { title: string; detail: string; action: string } {
  const p = c.params ?? {};
  const T: Record<string, [string, string, string]> = {
    vulndb_empty: [t("Zafiyet veritabanı boş"), t("Bulgu üretilemez."), t("Ayarlar → Veritabanını güncelle")],
    vulndb_stale: [t("Zafiyet verisi eski: {source}", { source: p.source }), p.hours != null ? t("Son güncelleme {age} önce", { age: ageText(p.hours) }) : t("Hiç güncellenmemiş"), t("Ayarlar → Veritabanını güncelle")],
    no_db_schedule: [t("Otomatik veritabanı güncellemesi yok"), t("Yeni yayımlanan zafiyetler ancak veritabanı güncellenince görünür."), t("Ayarlar → Zamanlanmış veritabanı güncellemesi ekleyin (ör. her gün 02:00)")],
    no_worker: [t("Çalışan worker yok"), t("Taramalar ve güncellemeler kuyrukta bekler."), "Docker: docker compose up -d worker · scakit server worker"],
    failed_jobs: [t("Son 24 saatte {n} iş başarısız", { n: p.n }), "", t("Taramalar sayfasında günlüğe bakın")],
    cookie_insecure: [t("Oturum çerezi Secure değil"), t("Arayüz HTTPS olmadan kullanılıyorsa parolalar ve oturum ağda açık gider."), t("Önüne TLS'li ters vekil (nginx / Caddy) koyup SCAKIT_COOKIE_SECURE=1 yapın")],
    secret_file: [t("Gizli anahtar dosyadan okunuyor"), p.path ?? "", t("Yedekleme planına bu dosyayı ekleyin (şifreli ayarlar bu anahtarla çözülür)")],
    sqlite: [t("Veritabanı SQLite"), t("Tek kullanıcı / deneme için uygundur."), t("Çok kullanıcılı kurulumda Docker compose'daki PostgreSQL'i kullanın")],
    internal_allowed: [t("İç ağ taraması açık"), t("Yönetici ve analistler özel IP adreslerini tarayabilir."), t("Gerekmiyorsa Ayarlar'dan kapatın")],
    default_admin: [t("Varsayılan yönetici e-postası kullanılıyor"), "admin@localhost", t("Gerçek bir e-posta ile yönetici oluşturup bu hesabı kapatın")],
    single_admin: [t("Tek yönetici hesabı"), t("Hesap kilitlenirse erişim kaybolur."), t("İkinci bir yönetici tanımlayın")],
    disk_low: [c.level === "crit" ? t("Disk dolmak üzere") : t("Disk alanı azalıyor"), t("Boş alan %{pct}", { pct: p.pct }), c.level === "crit" ? t("Eski taramaları / yüklemeleri temizleyin") : ""],
    tool_missing: [t("{tool} kurulu değil", { tool: p.tool }), t(c.detail), t(c.action)],
    frontend_missing: [t("Arayüz derlenmemiş"), "", "cd frontend && npm ci && npm run build"],
    python_old: [t("Python {version} destek dışı", { version: p.version }), "", t("Python 3.11+ kullanın")],
    no_channels: [t("Bildirim kanalı yok"), t("Tarama sonuçları ve yeni kritik bulgular kimseye bildirilmiyor."), t("Bildirimler sayfasından Slack / Teams / e-posta kanalı ekleyin")],
    no_public_url: [t("Arayüz adresi (public_url) tanımlı değil"), t("Bildirim ve Jira kayıtlarında bağlantı olmaz."), t("Ayarlar → Genel → Arayüzün adresi")],
    no_nvd_key: [t("NVD API anahtarı yok"), t("NVD indirmesi yavaş olur; CPE tabanlı (ürün) eşleştirme sınırlı kalır."), t("nvd.nist.gov/developers adresinden ücretsiz anahtar alıp Ayarlar'a girin")],
  };
  const v = T[c.id];
  return v ? { title: v[0], detail: v[1], action: v[2] } : { title: c.title, detail: c.detail, action: c.action };
}

function ageText(h: number | null) {
  if (h === null || h === undefined) return t("hiç");
  if (h < 1) return "1 saatten az";
  if (h < 48) return `${Math.round(h)} saat`;
  return t("{n} gün", { n: Math.round(h / 24) });
}

function PathText({ path }: { path: string }) {
  const short = path.length > 48 ? `${path.slice(0, 18)}…${path.slice(-26)}` : path;
  return (
    <Group gap={4} wrap="nowrap" style={{ minWidth: 0, flex: 1 }}>
      <Tooltip label={path} multiline maw={520}><Text size="sm" ff="monospace" truncate>{short}</Text></Tooltip>
      <CopyButton value={path}>{({ copied, copy }) => <ActionIcon size="sm" variant="subtle" color={copied ? "teal" : "gray"} onClick={copy} aria-label={t("Kopyala")}>{copied ? <IconCheck size={12} /> : <IconCopy size={12} />}</ActionIcon>}</CopyButton>
    </Group>
  );
}

export default function SystemPage({ user }: { user: User }) {
  const qc = useQueryClient();
  const admin = user.role === "admin";
  const info = useQuery<any>({ queryKey: ["system"], queryFn: () => api("/system"), refetchInterval: (q) => (q.state.data?.selfscan_job && ["queued", "running"].includes(q.state.data.selfscan_job.status) ? 3000 : 30000) });
  const self = useQuery<any>({ queryKey: ["selfscan"], queryFn: () => api("/system/selfscan") });
  const [latest, setLatest] = useState<any>(null);
  const [checking, setChecking] = useState(false);
  const [tab, setTab] = useState<string>(() => { try { return localStorage.getItem("lf_sys_tab") ?? "checks"; } catch { return "checks"; } });
  const d = info.data;
  const ssJob = d?.selfscan_job;
  const ssDone = ssJob?.status === "done" ? ssJob.id : 0;
  useEffect(() => { if (ssDone) qc.invalidateQueries({ queryKey: ["selfscan"] }); }, [ssDone, qc]);
  async function startSelfscan() {
    try { await api("/system/selfscan", { method: "POST" }); ok(t("Öz tarama başladı")); qc.invalidateQueries({ queryKey: ["system"] }); } catch (e) { fail(e); }
  }
  async function runMaintenance() {
    try { const r = await api("/system/maintenance", { method: "POST" }); ok(t("Bakım tamamlandı: {n} tarama temizlendi", { n: r.stats.scans })); qc.invalidateQueries({ queryKey: ["system"] }); } catch (e) { fail(e); }
  }
  async function checkLatest() {
    setChecking(true);
    try { setLatest(await api("/system/check-latest", { method: "POST" })); } catch (e) { fail(e); } finally { setChecking(false); }
  }
  if (info.isLoading || !d) return <Loader />;
  const lat = latest ?? d.latest;
  const latestBy: Record<string, any> = Object.fromEntries((lat?.items ?? []).map((r: any) => [`${r.layer}|${r.name.toLowerCase()}`, r]));
  const crit = d.checks.filter((c: any) => c.level === "crit").length;
  const warn = d.checks.filter((c: any) => c.level === "warn").length;
  const overall = crit ? "crit" : warn ? "warn" : "ok";
  const alive = d.workers.filter((w: any) => w.alive).length;
  return (
    <>
      <PageHeader title={t("Sistem durumu")} sub={t("Le Fureteur'ün kendi bileşenleri, sağlığı ve güncelleme önerileri")}
        right={<Button variant="default" leftSection={<IconRefresh size={16} />} onClick={() => { qc.invalidateQueries({ queryKey: ["system"] }); qc.invalidateQueries({ queryKey: ["selfscan"] }); }}>{t("Yenile")}</Button>} />

      <SimpleGrid cols={{ base: 2, md: 4 }} mb="lg">
        <Card withBorder>
          <Text size="sm" c="dimmed">{t("Genel durum")}</Text>
          <Group gap="xs" mt={6}><ThemeIcon color={LEVEL[overall].color} variant="light" size="lg">{(() => { const I = LEVEL[overall].icon; return <I size={20} />; })()}</ThemeIcon>
            <div><Text fw={700}>{overall === "ok" ? t("Sağlıklı") : overall === "warn" ? t("Dikkat gerekli") : t("Müdahale gerekli")}</Text><Text size="xs" c="dimmed">{crit} {t("kritik ·")} {warn} {t("uyarı")}</Text></div></Group>
        </Card>
        <Card withBorder><Text size="sm" c="dimmed">{PRODUCT}</Text><Text fz={24} fw={700}>{d.scakit.version}</Text><Text size="xs" c="dimmed">{t("Python")} {d.scakit.python}</Text></Card>
        <Card withBorder><Text size="sm" c="dimmed">{t("Worker")}</Text><Text fz={24} fw={700} c={alive ? undefined : "red"}>{alive}</Text><Text size="xs" c="dimmed">{alive ? t("çalışıyor") : t("çalışan worker yok — taramalar bekler")}</Text></Card>
        <Card withBorder><Text size="sm" c="dimmed">{t("İş kuyruğu")}</Text><Text fz={24} fw={700}>{d.queue.running} / {d.queue.queued}</Text><Text size="xs" c="dimmed">{t("çalışan / bekleyen · 24 sa. başarısız")} {d.queue.failed_24h}</Text></Card>
      </SimpleGrid>

      <Tabs value={tab} onChange={(v) => { setTab(v ?? "checks"); try { localStorage.setItem("lf_sys_tab", v ?? "checks"); } catch {  } }} keepMounted={false}>
        <Tabs.List mb="md">
          <Tabs.Tab value="checks" leftSection={<IconListCheck size={16} />} rightSection={crit + warn ? <Badge size="xs" color={crit ? "red" : "orange"} circle>{crit + warn}</Badge> : null}>{t("Kontroller")}</Tabs.Tab>
          <Tabs.Tab value="server" leftSection={<IconServer size={16} />}>{t("Sunucu ve depolama")}</Tabs.Tab>
          <Tabs.Tab value="maint" leftSection={<IconTool size={16} />}>{t("Bakım")}</Tabs.Tab>
          <Tabs.Tab value="selfscan" leftSection={<IconShieldSearch size={16} />}>{t("Güvenlik öz taraması")}</Tabs.Tab>
          <Tabs.Tab value="deps" leftSection={<IconPackage size={16} />}>{t("Bileşenler")}</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="checks">
      <Card withBorder mb="lg" p={0}>
        <Text fw={600} p="md" pb="xs">{t("Kontroller ve öneriler")}</Text>
        {d.checks.length === 0 ? <Group p="md" pt={0}><Level level="ok" /><Text size="sm">{t("Her şey yolunda.")}</Text></Group> : (
          <Table.ScrollContainer minWidth={700}>
            <Table verticalSpacing="sm">
              <Table.Tbody>
                {d.checks.map((c: any, i: number) => (
                  <Table.Tr key={i}>
                    <Table.Td w={1} style={{ whiteSpace: "nowrap" }}><Level level={c.level} /></Table.Td>
                    <Table.Td><Text size="sm" fw={600}>{checkText(c).title}</Text>{checkText(c).detail && <Text size="xs" c="dimmed">{checkText(c).detail}</Text>}</Table.Td>
                    <Table.Td><Text size="sm">{checkText(c).action}</Text></Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
      </Card>

        </Tabs.Panel>
        <Tabs.Panel value="server">
      <SimpleGrid cols={{ base: 1, lg: 2 }} mb="lg">
        <Card withBorder p={0}>
          <Group justify="space-between" p="md" pb="xs"><Text fw={600}>{t("Zafiyet veritabanı güncelliği")}</Text><Anchor component={Link} to="/settings" size="sm">{t("Güncelle →")}</Anchor></Group>
          <Table.ScrollContainer minWidth={460}>
            <Table verticalSpacing="xs">
              <Table.Thead><Table.Tr><Table.Th>{t("Kaynak")}</Table.Th><Table.Th ta="right">{t("Kayıt")}</Table.Th><Table.Th>{t("Son güncelleme")}</Table.Th><Table.Th>{t("Durum")}</Table.Th></Table.Tr></Table.Thead>
              <Table.Tbody>
                {d.vulndb.sources.map((s: any) => (
                  <Table.Tr key={s.name}>
                    <Table.Td><Tooltip label={s.detail || s.name} disabled={!s.detail} multiline w={320}><Text size="sm" fw={500}>{s.name}</Text></Tooltip></Table.Td>
                    <Table.Td ta="right"><Text size="sm">{s.count ? s.count.toLocaleString("tr-TR") : "-"}</Text></Table.Td>
                    <Table.Td><Text size="sm">{t("{age} önce", { age: ageText(s.age_hours) })}</Text><Text size="xs" c="dimmed">{fmtDate(s.updated)}</Text></Table.Td>
                    <Table.Td><Level level={s.level} /></Table.Td>
                  </Table.Tr>
                ))}
                {d.vulndb.sources.length === 0 && <Table.Tr><Table.Td colSpan={4}><Text c="dimmed" size="sm">{t("Veritabanı boş")}</Text></Table.Td></Table.Tr>}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
          <Group p="md" pt="xs" gap="xs" wrap="nowrap"><IconDatabase size={16} /><PathText path={d.vulndb.path} /><Badge variant="light" color="gray" style={{ flexShrink: 0 }}>{fmtSize(d.vulndb.size)}</Badge></Group>
        </Card>
        <Card withBorder>
          <Text fw={600} mb="xs">{t("Sunucu")}</Text>
          <Table verticalSpacing={4} withRowBorders={false}>
            <Table.Tbody>
              {[[t("İşletim sistemi"), `${d.os.name}${d.os.container ? " (Docker)" : ""}`],
                [t("Uygulama veritabanı"), `${d.database.engine === "postgresql" ? "PostgreSQL" : "SQLite"} ${d.database.version}${d.database.size ? ` · ${fmtSize(d.database.size)}` : ""}`],
                [t("Veri klasörü"), <PathText path={d.disk.path} />],
                [t("Disk"), t("{free} boş / {total}", { free: fmtSize(d.disk.free), total: fmtSize(d.disk.total) })],
                [t("Yüklenen dosyalar"), fmtSize(d.disk.uploads)], [t("Tarama çıktıları"), fmtSize(d.disk.scans)],
                [t("Arayüz derlemesi"), d.frontend.built ? fmtDate(d.frontend.built_at) : t("derlenmemiş")]].map(([k, v]) => (
                <Table.Tr key={k as string}><Table.Td w={170} style={{ whiteSpace: "nowrap" }}><Text size="sm" c="dimmed">{k}</Text></Table.Td><Table.Td>{typeof v === "string" ? <Text size="sm">{v}</Text> : v}</Table.Td></Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
          {d.disk.total > 0 && <Progress mt="xs" value={100 - (d.disk.free / d.disk.total) * 100} color={d.disk.free / d.disk.total < 0.1 ? "red" : "indigo"} size="sm" />}
          <Text fw={600} mt="md" mb="xs">{t("Harici araçlar")}</Text>
          {d.tools.map((tg: any) => (
            <Group key={tg.name} gap="xs" mb={4} wrap="nowrap"><div style={{ flexShrink: 0 }}><Level level={tg.ok ? "ok" : "info"} /></div><div><Text size="sm">{tg.name} {tg.version && <Text span size="xs" c="dimmed">{tg.version}</Text>}</Text><Text size="xs" c="dimmed">{tg.ok ? t(tg.purpose) : `${t(tg.purpose)} — ${t(tg.fix)}`}</Text></div></Group>
          ))}
          <Text fw={600} mt="md" mb="xs">{t("Worker'lar")}</Text>
          {d.workers.filter((w: any) => w.alive).length === 0 ? <Text size="sm" c="red">{t("Çalışan worker yok — taramalar kuyrukta bekler. Sunucuda worker sürecini başlatın.")}</Text> : d.workers.filter((w: any) => w.alive).map((w: any) => (
            <Group key={w.worker} gap="xs" mb={4}><Level level="ok" /><Text size="sm" ff="monospace">{w.worker}</Text>
              <Text size="xs" c="dimmed">{w.current_job ? t("iş #{n}", { n: w.current_job }) : t("boşta")}</Text></Group>
          ))}
          {d.workers.some((w: any) => !w.alive) && <Text size="xs" c="dimmed" mt={4}>{t("Son bir saatte duran {n} worker kaydı (yeniden başlatmalar) gizlendi; bir saat sonra kendiliğinden silinir.", { n: d.workers.filter((w: any) => !w.alive).length })}</Text>}
        </Card>
      </SimpleGrid>

        </Tabs.Panel>
        <Tabs.Panel value="maint">
      {admin && <div style={{ marginBottom: "var(--mantine-spacing-lg)" }}><MaintenanceCard /></div>}
      <Card withBorder mb="lg">
        <Group justify="space-between" align="flex-start">
          <div>
            <Text fw={600}>{t("Bakım ve saklama")}</Text>
            <Text size="xs" c="dimmed">{t("Eski taramalar, iş kayıtları, denetim kaydı ve sahipsiz dosyalar günde bir kez otomatik temizlenir. Bulgular silinmez.")}</Text>
            <Text size="sm" mt={6}>{d.maintenance ? t("Son bakım: {date} — {scans} tarama, {audit} denetim kaydı, {dirs} sahipsiz klasör temizlendi", { date: fmtDate(d.maintenance.at), scans: d.maintenance.scans, audit: d.maintenance.audit, dirs: d.maintenance.orphan_dirs }) : t("Henüz bakım çalışmadı")}</Text>
          </div>
          {admin && <Button size="xs" variant="light" onClick={runMaintenance}>{t("Bakımı şimdi çalıştır")}</Button>}
        </Group>
      </Card>

      <Card withBorder mb="lg">
        <Text fw={600}>{t("Yedekleme")}</Text>
        <Text size="xs" c="dimmed" mb="xs">{t("Veritabanı, yüklenen dosyalar ve tarama çıktıları tek komutla, isteğe bağlı şifreli olarak yedeklenir. Geri yükleme yalnızca boş bir kuruluma yapılır.")}</Text>
        <CodeBlock code={"# şifreli yedek (parola sorulur; otomasyonda SCAKIT_BACKUP_PASSPHRASE)\nscakit server backup /yedek/lefureteur-$(date +%F).tar.gz.enc --encrypt\n\n# geri yükleme (boş kurulumda)\nscakit server restore /yedek/lefureteur-2026-11-17.tar.gz.enc --encrypt"} filename={t("Sunucuda")} lang="bash" />
      </Card>
        </Tabs.Panel>
        <Tabs.Panel value="selfscan">
      <SelfScan data={self.data} job={ssJob} onStart={startSelfscan} />
        </Tabs.Panel>
        <Tabs.Panel value="deps">

      <Card withBorder p={0}>
        <Group justify="space-between" p="md" pb="xs" align="flex-start">
          <div>
            <Text fw={600}>{t("Bileşenler")}</Text>
            <Text size="xs" c="dimmed">{t("Le Fureteur'ün çalışırken kullandığı paketler. \"Güncel sürüm\" sütunu çevrimiçi kontrolle dolar.")}</Text>
          </div>
          {admin && (
            <Tooltip multiline w={340} label={t("Yalnızca Le Fureteur'ün kendi doğrudan bağımlılıklarının adları PyPI ve npm kayıtlarına sorulur. Müşteri verisi, hedef veya bulgu gönderilmez.")}>
              <Button size="xs" variant="light" leftSection={<IconWorldDownload size={16} />} onClick={checkLatest} loading={checking}>{t("Güncel sürümleri internetten kontrol et")}</Button>
            </Tooltip>
          )}
        </Group>
        {lat && <Text size="xs" c="dimmed" px="md">{t("Son kontrol:")} {fmtDate(lat.checked_at)} · {lat.outdated} {t("paketin yeni sürümü var")}</Text>}
        <Tabs defaultValue="python" mt="xs">
          <Tabs.List px="md"><Tabs.Tab value="python">{t("Python (")}{d.python_packages.length})</Tabs.Tab><Tabs.Tab value="npm">{t("Arayüz (")}{d.frontend.packages.length})</Tabs.Tab></Tabs.List>
          <Tabs.Panel value="python"><PkgTable rows={d.python_packages.map((p: any) => ({ ...p, latest: latestBy[`Python|${p.name.toLowerCase()}`] }))} showRequired /></Tabs.Panel>
          <Tabs.Panel value="npm"><PkgTable rows={d.frontend.packages.map((p: any) => ({ ...p, latest: latestBy[`Arayüz (npm)|${p.name.toLowerCase()}`] }))} /></Tabs.Panel>
        </Tabs>
      </Card>
        </Tabs.Panel>
      </Tabs>
    </>
  );
}

function PkgTable({ rows, showRequired }: { rows: any[]; showRequired?: boolean }) {
  const [all, setAll] = useState(false);
  const shown = all ? rows : rows.filter((r) => r.direct);
  return (
    <>
      <Group px="md" py="xs"><Switch size="xs" label={t("Dolaylı bağımlılıkları da göster ({n})", { n: rows.length - rows.filter((r) => r.direct).length })} checked={all} onChange={(e) => setAll(e.currentTarget.checked)} /></Group>
      <Table.ScrollContainer minWidth={620}>
        <Table verticalSpacing={6} striped>
          <Table.Thead><Table.Tr><Table.Th>{t("Paket")}</Table.Th><Table.Th>{t("Kurulu")}</Table.Th>{showRequired && <Table.Th>{t("Gereken")}</Table.Th>}<Table.Th>{t("Güncel sürüm")}</Table.Th><Table.Th>{t("Öneri")}</Table.Th></Table.Tr></Table.Thead>
          <Table.Tbody>
            {shown.map((r) => {
              const l = r.latest;
              return (
                <Table.Tr key={r.name}>
                  <Table.Td><Text size="sm" fw={r.direct ? 600 : 400}>{r.name}</Text>{!r.direct && <Text size="xs" c="dimmed">{t("dolaylı")}</Text>}</Table.Td>
                  <Table.Td><Text size="sm" ff="monospace">{r.version ?? t("kurulu değil")}</Text></Table.Td>
                  {showRequired && <Table.Td><Text size="xs" ff="monospace" c="dimmed">{r.required || "-"}</Text></Table.Td>}
                  <Table.Td>{l ? <Text size="sm" ff="monospace">{l.latest ?? "-"}</Text> : <Text size="xs" c="dimmed">-</Text>}</Table.Td>
                  <Table.Td>{l && <Badge size="sm" variant="light" color={BUMP[l.bump].color}>{BUMP[l.bump].label}</Badge>}</Table.Td>
                </Table.Tr>
              );
            })}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>
    </>
  );
}

function SelfScan({ data, job, onStart }: { data: any; job: any; onStart: () => void }) {
  const [layer, setLayer] = useState("all");
  const [fixable, setFixable] = useState(true);
  const running = job && ["queued", "running"].includes(job.status);
  const items = (data?.items ?? []).filter((g: any) => (layer === "all" || g.layer === layer) && (!fixable || g.upgrade_to));
  return (
    <Card withBorder p={0}>
      <Group justify="space-between" p="md" pb="xs" align="flex-start">
        <div>
          <Group gap="xs"><IconShieldSearch size={18} /><Text fw={600}>{t("Güvenlik öz taraması")}</Text></Group>
          <Text size="xs" c="dimmed">{t("Le Fureteur kendi Python, arayüz ve işletim sistemi paketlerini kendi zafiyet veritabanıyla tarar (çevrimdışı).")}</Text>
        </div>
        <Group gap="xs">{job && <JobBadge status={job.status} />}<Button size="xs" onClick={onStart} loading={running}>{t("Öz taramayı başlat")}</Button></Group>
      </Group>
      {!data ? <Text size="sm" c="dimmed" p="md" pt={0}>{t("Henüz öz tarama yapılmadı.")}</Text> : (
        <>
          <Group px="md" gap="lg" mb="xs">
            <Text size="sm">{t("Taranan: Python")} {data.components.python} {t("· arayüz")} {data.components.frontend} {t("· işletim sistemi")} {data.components.os}</Text>
            <Text size="sm">{t("Zafiyetli bileşen:")} <b>{data.vulnerable}</b> {t("(güncellemeyle düzelen")} {data.fixable})</Text>
            <Text size="xs" c="dimmed">{fmtDate(data.scanned_at)}</Text>
          </Group>
          {data.vulnerable === 0 && <Alert color="green" variant="light" mx="md" mb="md" icon={<IconCircleCheck size={16} />}>{t("Bilinen zafiyetli bileşen yok.")}</Alert>}
          {data.vulnerable > 0 && <>
            <Group px="md" mb="xs">
              <SegmentedControl size="xs" value={layer} onChange={setLayer} data={[{ value: "all", label: t("Tümü") }, ...Object.entries(data.by_layer).map(([k, n]) => ({ value: k, label: `${t(k)} (${n})` }))]} />
              <Switch size="xs" label={t("Yalnızca güncellemeyle düzelenler")} checked={fixable} onChange={(e) => setFixable(e.currentTarget.checked)} />
            </Group>
            <Table.ScrollContainer minWidth={760}>
              <Table verticalSpacing={6}>
                <Table.Thead><Table.Tr><Table.Th>{t("Katman")}</Table.Th><Table.Th>{t("Bileşen")}</Table.Th><Table.Th>{t("En yüksek")}</Table.Th><Table.Th ta="right">{t("Zafiyet")}</Table.Th><Table.Th>{t("Güncelleme önerisi")}</Table.Th></Table.Tr></Table.Thead>
                <Table.Tbody>
                  {items.slice(0, 150).map((g: any) => (
                    <Table.Tr key={g.layer + g.component + g.version}>
                      <Table.Td><Text size="xs">{t(g.layer)}</Text></Table.Td>
                      <Table.Td><Text size="sm" fw={500}>{g.component}</Text><Text size="xs" ff="monospace" c="dimmed">{g.version}</Text></Table.Td>
                      <Table.Td><Group gap={4}><SevBadge sev={g.max_severity} />{g.kev && <Badge size="xs" color="red" variant="outline">{t("KEV")}</Badge>}</Group></Table.Td>
                      <Table.Td ta="right"><Tooltip multiline w={420} label={g.vulns.map((v: any) => `${v.cves[0] ?? v.id}: ${v.summary}`).join("\n")}><Text size="sm" style={{ cursor: "help" }}>{g.count}</Text></Tooltip></Table.Td>
                      <Table.Td>{g.upgrade_to ? <Text size="sm"><Text span ff="monospace">{g.version}</Text> → <Text span ff="monospace" fw={600}>{g.upgrade_to}</Text></Text> : <Text size="xs" c="dimmed">{t("henüz düzeltme yok")}</Text>}</Table.Td>
                    </Table.Tr>
                  ))}
                  {items.length === 0 && <Table.Tr><Table.Td colSpan={5}><Text size="sm" c="dimmed" ta="center" py="sm">{t("Filtreye uyan bileşen yok")}</Text></Table.Td></Table.Tr>}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
            <Text size="xs" c="dimmed" p="md" pt="xs">{t("Nasıl güncellenir: Docker kurulumunda yeni Le Fureteur imajını oluşturup")} <code>{t("docker compose up -d --build")}</code>{t("; işletim sistemi paketleri için temel imaj yeniden çekilir. Docker'sız kurulumda")} <code>{t("pip install -U paket")}</code> / <code>{t("apt upgrade")}</code>.</Text>
          </>}
        </>
      )}
    </Card>
  );
}
