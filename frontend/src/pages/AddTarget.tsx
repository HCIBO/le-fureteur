import { Accordion, Alert, Anchor, Badge, Button, Card, Group, NumberInput, Select, SimpleGrid, Stack, Stepper, Switch, Text, Textarea, TextInput, ThemeIcon, UnstyledButton } from "@mantine/core";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { IconArrowLeft, IconArrowRight, IconCheck, IconInfoCircle, IconPlayerPlay, IconStack2 } from "@tabler/icons-react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { api, User } from "../api";
import { t } from "../i18n";
import { fail, ok, PageHeader } from "../components/ui";
import { CodeBlock } from "../components/CodeBlock";
import { QueueHint, QueueOptions, QueuePolicy, ruleText } from "../components/QueuePanel";
import { EgressSelect, HttpClientSelect } from "../components/HttpClientSelect";
import { Dropzone, Pending, uploadAll } from "../components/Dropzone";
import { TARGET_TYPES, TargetType } from "../components/TargetTypes";

const OSES = ["Debian:12", "Debian:11", "Ubuntu:24.04", "Ubuntu:22.04", "Ubuntu:20.04", "Alpine:3.20", "Alpine:3.19", "RedHat:9", "Rocky:9", "AlmaLinux:9"];

function TypeCard({ tt, selected, onClick }: { tt: TargetType; selected: boolean; onClick: () => void }) {
  return (
    <UnstyledButton onClick={onClick} style={{ height: "100%" }}>
      <Card withBorder h="100%" padding="md" style={{ borderColor: selected ? `var(--mantine-color-${tt.color}-6)` : undefined, borderWidth: selected ? 2 : 1, transition: "transform .12s", background: selected ? `var(--mantine-color-${tt.color}-light)` : undefined }}>
        <Group justify="space-between" align="flex-start">
          <ThemeIcon size={42} radius="md" variant="light" color={tt.color}><tt.icon size={24} /></ThemeIcon>
          {selected && <ThemeIcon size={22} radius="xl" color={tt.color}><IconCheck size={14} /></ThemeIcon>}
        </Group>
        <Text fw={700} mt="sm">{tt.title}</Text>
        <Text size="xs" c="dimmed" mt={4}>{tt.desc}</Text>
        <Group gap={4} mt="sm">{tt.formats.slice(0, 5).map((f) => <Badge key={f} size="xs" variant="outline" color="gray" tt="none">{f}</Badge>)}</Group>
      </Card>
    </UnstyledButton>
  );
}

export default function AddTarget({ user }: { user: User }) {
  const { id } = useParams();
  const nav = useNavigate();
  const qc = useQueryClient();
  const project = useQuery<any>({ queryKey: ["project", id], queryFn: () => api(`/projects/${id}`) });
  const meta = useQuery<any>({ queryKey: ["meta"], queryFn: () => api("/meta") });
  const [sp] = useSearchParams();
  const pre = TARGET_TYPES.find((x) => x.id === sp.get("type")) ?? null;
  const DRAFT = `lf_addtarget_${id}`;
  const draft = (() => { try { return JSON.parse(sessionStorage.getItem(DRAFT) ?? "null"); } catch { return null; } })();
  const [step, setStep] = useState(pre ? 1 : draft?.step ?? 0);
  const [type, setType] = useState<TargetType | null>(pre ?? TARGET_TYPES.find((x) => x.id === draft?.type) ?? null);
  const [urls, setUrls] = useState<string>(draft?.urls ?? "");
  const [web, setWeb] = useState(draft?.web ?? { delay: 1, max_pages: 30, probe: true, verify_tls: true, user_agent: "", waf_assist: true, browser_tls: "", external_assets: true, egress: "" });
  const [up, setUp] = useState(draft?.up ?? { name: "", os: "", dev: false });
  const [queue, setQueue] = useState<QueuePolicy | null>(draft?.queue ?? null);
  const [saveQueue, setSaveQueue] = useState(false);
  const staff = user.role === "admin" || user.role === "analyst";
  const projQueue: QueuePolicy | undefined = project.data?.queue_policy;
  const q = queue ?? projQueue ?? { priority: "normal", parallel: 0, gap: 0 };
  const queueChanged = !!projQueue && JSON.stringify(q) !== JSON.stringify(projQueue);
  useEffect(() => {
    try { sessionStorage.setItem(DRAFT, JSON.stringify({ step: Math.min(step, 2), type: type?.id, urls, web, up, queue })); } catch {  }
  }, [step, type, urls, web, up, queue]);
  const [files, setFiles] = useState<Pending[]>([]);
  const [scanNow, setScanNow] = useState(true);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ targets: any[]; errors: any[] } | null>(null);
  const urlList = urls.split(/[\n,]+/).map((u) => u.trim()).filter(Boolean);
  const isWeb = type?.kind === "web";
  const maxMb = meta.data?.max_upload_mb ?? 2048;
  const maxFiles = meta.data?.max_files_per_target ?? 20;

  const canNext = step === 0 ? !!type : step === 1 ? (isWeb ? urlList.length > 0 && urlList.length <= 50 : !!up.name.trim() && (type?.id !== "packages" || !!up.os)) : isWeb || files.length > 0;

  async function finish() {
    if (!type) return;
    setBusy(true);
    try {
      let targets: any[] = [];
      let errors: any[] = [];
      let uploaded = 0;
      if (isWeb) {
        const opts: any = { delay: web.delay, max_pages: web.max_pages, probe: web.probe, verify_tls: web.verify_tls, waf_assist: web.waf_assist };
        if (web.user_agent.trim()) opts.user_agent = web.user_agent.trim();
        if (web.browser_tls) opts.browser_tls = web.browser_tls;
        opts.external_assets = web.external_assets;
        if (web.egress) opts.egress = web.egress;
        const r = await api(`/projects/${id}/targets/bulk`, { body: { urls: urlList, options: opts } });
        targets = r.created; errors = r.errors;
      } else {
        const opts: any = { type: type.id, dev: up.dev };
        if (up.os) opts.os = up.os;
        const tg = await api(`/projects/${id}/targets`, { body: { name: up.name.trim(), kind: "upload", options: opts } });
        const n = await uploadAll(tg.id, files, setFiles);
        uploaded = n;
        if (n === 0) { errors = [{ url: up.name, error: t("Dosyalar yüklenemedi; hedef sayfasından tekrar deneyin") }]; }
        targets = [tg];
      }
      if (scanNow) {
        const ids = targets.filter((tg) => !(tg.kind === "upload" && uploaded === 0)).map((tg) => tg.id);
        if (ids.length) {
          const r = await api("/scans/batch", { body: { target_ids: ids, ...(queueChanged || saveQueue ? { queue: q, save_default: saveQueue } : {}) } });
          r.errors.forEach((e: any) => errors.push({ url: e.name, error: e.error }));
        }
      }
      try { sessionStorage.removeItem(DRAFT); } catch {  }
      qc.invalidateQueries({ queryKey: ["targets", id] });
      setResult({ targets, errors });
      setStep(3);
      if (targets.length) ok(t("{n} hedef eklendi", { n: targets.length }));
    } catch (e) { fail(e); } finally { setBusy(false); }
  }

  return (
    <>
      <Anchor component={Link} to={`/projects/${id}`} size="sm"><Group gap={4}><IconArrowLeft size={14} />{project.data?.name ?? t("Proje")}</Group></Anchor>
      <PageHeader title={t("Hedef ekle")} sub={t("Ne taramak istediğinizi seçin; her tür için neyin gerektiği adım adım anlatılır.")} />
      <Stepper active={step} onStepClick={(s) => s < step && step < 3 && setStep(s)} mb="xl" allowNextStepsSelect={false}>
        <Stepper.Step label={t("Tür")} description={type?.title ?? t("Ne taranacak?")} />
        <Stepper.Step label={t("Ayrıntılar")} description={isWeb ? t("Adresler") : t("Ad ve seçenekler")} />
        <Stepper.Step label={isWeb ? t("Gözden geçir") : t("Dosyalar")} description={isWeb ? t("Onay") : t("Yükleme")} />
        <Stepper.Completed>{null}</Stepper.Completed>
      </Stepper>

      {step === 0 && (
        <SimpleGrid cols={{ base: 1, sm: 2, lg: 4 }}>
          {TARGET_TYPES.map((tt) => <TypeCard key={tt.id} tt={tt} selected={type?.id === tt.id} onClick={() => { setType(tt); setStep(1); }} />)}
        </SimpleGrid>
      )}

      {step === 1 && type && (
        <SimpleGrid cols={{ base: 1, lg: 2 }}>
          <Card withBorder>
            <Group gap="sm" mb="md"><ThemeIcon size={36} radius="md" variant="light" color={type.color}><type.icon size={20} /></ThemeIcon><Text fw={700}>{type.title}</Text></Group>
            {isWeb ? (
              <Stack>
                <Textarea label={t("Adresler")} description={t("Her satıra bir adres. https:// yazmazsanız eklenir. En fazla 50 adres; her biri ayrı hedef olur.")} autosize minRows={5} maxRows={14}
                  placeholder={"https://portal.ornek.com\napi.ornek.com\nhttps://ornek.com/magaza"} value={urls} onChange={(e) => setUrls(e.currentTarget.value)} styles={{ input: { fontFamily: "ui-monospace, monospace" } }} />
                <Text size="xs" c={urlList.length > 50 ? "red" : "dimmed"}>{t("{n} adres", { n: urlList.length })}{user.role === "customer" ? ` · ${t("Yalnızca organizasyonunuzun izinli alan adları eklenebilir.")}` : ""}</Text>
                <Group grow>
                  <NumberInput label={t("İstekler arası bekleme (sn)")} min={0.2} max={10} step={0.5} decimalScale={1} value={web.delay} onChange={(v) => setWeb({ ...web, delay: Number(v) })} />
                  <NumberInput label={t("En fazla sayfa")} min={1} max={200} value={web.max_pages} onChange={(v) => setWeb({ ...web, max_pages: Number(v) })} />
                </Group>
                <Switch label={t("Bilinen dosya yollarını yokla (sürüm ifşası, lisans dosyaları)")} checked={web.probe} onChange={(e) => setWeb({ ...web, probe: e.currentTarget.checked })} />
                <Switch label={t("TLS sertifikasını doğrula")} checked={web.verify_tls} onChange={(e) => setWeb({ ...web, verify_tls: e.currentTarget.checked })} />
                <Switch label={t("WAF / bot korumasına takılırsa tarayıcı yardımcısıyla tamamla")} description={t("Tarama engellenirse size bildirim gelir; yardımcıyı tek komutla başlatırsınız.")} checked={web.waf_assist} onChange={(e) => setWeb({ ...web, waf_assist: e.currentTarget.checked })} />
                <Switch label={t("Başka sunuculardaki (CDN) betik ve stil dosyalarını da incele")} description={t("Sayfaların yüklediği JS / CSS dosyaları ayrı bir alan adındaysa (ör. static.site-cdn.com) yalnızca o dosyalar indirilir; izleme betikleri atlanır.")} checked={web.external_assets} onChange={(e) => setWeb({ ...web, external_assets: e.currentTarget.checked })} />
                <EgressSelect value={web.egress} onChange={(v) => setWeb({ ...web, egress: v })} names={meta.data?.egress ?? []} />
                <HttpClientSelect value={web.browser_tls} onChange={(v) => setWeb({ ...web, browser_tls: v })} available={!!meta.data?.browser_tls} />
                <Accordion variant="contained">
                  <Accordion.Item value="adv">
                    <Accordion.Control>{t("Gelişmiş: WAF izin listesi için User-Agent")}</Accordion.Control>
                    <Accordion.Panel>
                      <TextInput label="User-Agent" placeholder="LeFureteur-Scan/1.0 (+guvenlik@ornek.com)" value={web.user_agent} onChange={(e) => setWeb({ ...web, user_agent: e.currentTarget.value })} maxLength={300} />
                      <Text size="xs" c="dimmed" mt={4}>{t("Hedefin önünde Cloudflare gibi bir WAF varsa, sistem sahibi bu değeri (veya hedef sayfasında tanımlayacağınız gizli bir başlığı) WAF'ta izin listesine ekleyebilir. Le Fureteur WAF atlatma tekniği kullanmaz.")}</Text>
                    </Accordion.Panel>
                  </Accordion.Item>
                </Accordion>
              </Stack>
            ) : (
              <Stack>
                <TextInput label={t("Hedef adı")} required placeholder={type.id === "traffic" ? t("ör. medium.com (tarayıcı kaydı)") : type.id === "mobile" ? t("ör. Mobil bankacılık 5.2 (Android)") : type.id === "image" ? t("ör. api-gateway:1.4") : t("ör. Müşteri portalı — backend")} value={up.name} onChange={(e) => setUp({ ...up, name: e.currentTarget.value })} maxLength={200} />
                {(type.id === "packages" || type.id === "image") && (
                  <Select label={t("İşletim sistemi / dağıtım")} description={type.id === "packages" ? t("Paket sürümleri bu dağıtımın güvenlik bültenleriyle eşleştirilir.") : t("Boş bırakılırsa imajdan otomatik algılanır.")}
                    required={type.id === "packages"} searchable clearable data={OSES} value={up.os || null} onChange={(v) => setUp({ ...up, os: v ?? "" })} />
                )}
                {type.id === "source" && <Switch label={t("Geliştirme bağımlılıklarını da dahil et (test, derleme araçları)")} checked={up.dev} onChange={(e) => setUp({ ...up, dev: e.currentTarget.checked })} />}
              </Stack>
            )}
          </Card>
          <Stack>
          <Card withBorder>
            <Group gap="xs" mb="sm"><IconInfoCircle size={18} /><Text fw={700}>{t("Nasıl hazırlanır?")}</Text></Group>
            <Text size="sm">{type.desc}</Text>
            <Group gap={4} mt="sm">{type.formats.map((f) => <Badge key={f} variant="light" color={type.color} tt="none">{f}</Badge>)}</Group>
            {type.how && <Stack gap="xs" mt="md">{type.how.map((h) => <CodeBlock key={h.label} code={h.code} filename={h.label} lang="bash" />)}</Stack>}
            {type.tips && <Stack gap={4} mt="md">{type.tips.map((x) => <Text key={x} size="xs" c="dimmed">• {x}</Text>)}</Stack>}
          </Card>
          <Card withBorder>
            <Group gap="xs" mb={4} justify="space-between"><Group gap="xs"><IconStack2 size={18} /><Text fw={700}>{t("Kuyruk (bu taramalar için)")}</Text></Group>
              {queueChanged && <Badge size="xs" color="grape" variant="light">{t("projeden farklı")}</Badge>}</Group>
            <Text size="xs" c="dimmed" mb="sm">{t("Varsayılan, projenin kuyruk kuralıdır. Burada değiştirirseniz yalnızca bu taramalara uygulanır.")}</Text>
            <QueueOptions value={q} onChange={setQueue} staff={staff} />
            <Switch size="xs" mt="sm" label={t("Bu kuralı projenin varsayılanı yap")} checked={saveQueue} onChange={(e) => setSaveQueue(e.currentTarget.checked)} />
            <div style={{ marginTop: 10 }}><QueueHint count={isWeb ? Math.max(1, urlList.length) : 1} /></div>
          </Card>
          </Stack>
        </SimpleGrid>
      )}

      {step === 2 && type && (
        <SimpleGrid cols={{ base: 1, lg: isWeb ? 1 : 2 }}>
          {isWeb ? (
            <Card withBorder>
              <Text fw={700} mb="sm">{t("{n} web hedefi oluşturulacak", { n: urlList.length })}</Text>
              <Stack gap={4}>{urlList.map((u) => <Text key={u} size="sm" ff="monospace">• {u.includes("://") ? u : `https://${u}`}</Text>)}</Stack>
              <Text size="xs" c="dimmed" mt="sm">{t("Bekleme {d} sn · en fazla {p} sayfa", { d: web.delay, p: web.max_pages })}{web.user_agent ? ` · UA: ${web.user_agent}` : ""}</Text>
            </Card>
          ) : (
            <>
              <Dropzone files={files} onChange={setFiles} accept={type.accept} maxFiles={maxFiles} maxMb={maxMb} disabled={busy} />
              <Card withBorder>
                <Text fw={700} mb="xs">{up.name}</Text>
                <Text size="sm" c="dimmed">{type.title}{up.os ? ` · ${up.os}` : ""}</Text>
                <Text size="sm" mt="sm">{t("{n} dosya seçildi", { n: files.length })}</Text>
                <Text size="xs" c="dimmed" mt="sm">{t("Dosyalar yalnızca bu sunucuda saklanır, SHA-256 özetleri kayda geçer. Hedef sayfasından dosya ekleyip silebilirsiniz.")}</Text>
              </Card>
            </>
          )}
          <Switch mt="xs" label={t("Eklendikten sonra taramayı hemen başlat")} checked={scanNow} onChange={(e) => setScanNow(e.currentTarget.checked)} />
          {scanNow && <Text size="xs" c="dimmed">{t("Kuyruk:")} {{ high: t("Öne al"), normal: t("Normal"), low: t("Sona ekle") }[q.priority]} · {ruleText(q)}</Text>}
          {scanNow && <QueueHint count={isWeb ? Math.max(1, urlList.length) : 1} />}
        </SimpleGrid>
      )}

      {step === 3 && result && (
        <Card withBorder maw={760}>
          <Group gap="sm" mb="md"><ThemeIcon size={44} radius="xl" color={result.targets.length ? "green" : "red"} variant="light"><IconCheck size={24} /></ThemeIcon>
            <div><Text fw={700} size="lg">{result.targets.length ? t("{n} hedef eklendi", { n: result.targets.length }) : t("Hedef eklenemedi")}</Text>
              {scanNow && result.targets.length > 0 && <Text size="sm" c="dimmed">{t("Taramalar kuyruğa alındı; ilerlemeyi hedef sayfasından izleyebilirsiniz.")}</Text>}</div></Group>
          <Stack gap={4}>{result.targets.map((tg) => <Anchor key={tg.id} component={Link} to={`/targets/${tg.id}`} size="sm">→ {tg.name}</Anchor>)}</Stack>
          {result.errors.length > 0 && (
            <Alert mt="md" color="orange" title={t("Eklenemeyenler")}>
              <Stack gap={2}>{result.errors.map((e, i) => <Text key={i} size="sm"><b>{e.url}</b>: {t(e.error)}</Text>)}</Stack>
            </Alert>
          )}
          <Group mt="lg">
            <Button variant="default" onClick={() => { setStep(0); setType(null); setUrls(""); setFiles([]); setResult(null); setUp({ name: "", os: "", dev: false }); }}>{t("Başka hedef ekle")}</Button>
            <Button onClick={() => nav(result.targets.length === 1 ? `/targets/${result.targets[0].id}` : `/projects/${id}`)}>{result.targets.length === 1 ? t("Hedefe git") : t("Projeye dön")}</Button>
          </Group>
        </Card>
      )}

      {step > 0 && step < 3 && (
        <Group justify="space-between" mt="xl">
          <Button variant="default" leftSection={<IconArrowLeft size={16} />} onClick={() => setStep(step - 1)} disabled={busy}>{t("Geri")}</Button>
          {step === 1 ? <Button rightSection={<IconArrowRight size={16} />} onClick={() => setStep(2)} disabled={!canNext}>{t("Devam")}</Button>
            : <Button leftSection={scanNow ? <IconPlayerPlay size={16} /> : <IconCheck size={16} />} onClick={finish} loading={busy} disabled={!canNext}>{scanNow ? t("Ekle ve tara") : t("Ekle")}</Button>}
        </Group>
      )}
    </>
  );
}
