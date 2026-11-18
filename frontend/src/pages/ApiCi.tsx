import { ActionIcon, Alert, Badge, Button, Card, Checkbox, Code, CopyButton, Group, List, Modal, NumberInput, Select, SimpleGrid, Stack, Stepper, Table, Tabs, Text, TextInput, ThemeIcon, Title, Tooltip, UnstyledButton } from "@mantine/core";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ReactNode, useMemo, useState } from "react";
import { IconArrowRight, IconBrandAzure, IconBrandGithub, IconBrandGitlab, IconCheck, IconCircleCheck, IconCopy, IconGitPullRequest, IconKey, IconPlayerPlay, IconRobot, IconShieldCheck, IconTerminal2, IconTrash } from "@tabler/icons-react";
import { Link } from "react-router-dom";
import { api, fmtDate, SEV_LABEL, User } from "../api";
import { t } from "../i18n";
import { fail, ok, PageHeader } from "../components/ui";
import { CodeBlock } from "../components/CodeBlock";
import { PageIntro } from "../components/PageIntro";

type Platform = "github" | "gitlab" | "jenkins" | "azure" | "cli";
const PLATFORMS: { id: Platform; name: string; icon: ReactNode; color: string }[] = [
  { id: "github", name: "GitHub Actions", icon: <IconBrandGithub size={28} />, color: "dark" },
  { id: "gitlab", name: "GitLab CI", icon: <IconBrandGitlab size={28} />, color: "orange" },
  { id: "jenkins", name: "Jenkins", icon: <IconRobot size={28} />, color: "red" },
  { id: "azure", name: "Azure DevOps", icon: <IconBrandAzure size={28} />, color: "blue" },
  { id: "cli", name: t("Komut satırı"), icon: <IconTerminal2 size={28} />, color: "gray" },
];

function templates(url: string, pid: string) {
  return {
    github: {
      file: ".github/workflows/le-fureteur.yml", lang: "yaml",
      code: `name: Le Fureteur SCA

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write   # sonuçlar Security → Code scanning'de görünür

jobs:
  sca:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Le Fureteur taraması
        env:
          LF_URL: ${url}
          LF_PROJECT: "${pid}"
          LF_TOKEN: \${{ secrets.LF_TOKEN }}
        run: |
          curl -fsS -H "Authorization: Bearer $LF_TOKEN" "$LF_URL/api/ci/client.py" -o lf_ci.py
          python3 lf_ci.py --target "\${{ github.event.repository.name }}" --sarif le-fureteur.sarif

      - name: Sonuçları GitHub'a yükle
        if: always() && hashFiles('le-fureteur.sarif') != ''
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: le-fureteur.sarif
          category: le-fureteur
`,
      steps: [
        t("Depoda Settings → Secrets and variables → Actions → New repository secret: adı LF_TOKEN, değeri 2. adımdaki token."),
        t("Aşağıdaki dosyayı depoya .github/workflows/le-fureteur.yml olarak ekleyin (İndir düğmesiyle hazır gelir)."),
        t("Commit + push yapın. Tarama Actions sekmesinde çalışır; bulgular Security → Code scanning'de listelenir."),
      ],
    },
    gitlab: {
      file: ".gitlab-ci.yml", lang: "yaml",
      code: `le-fureteur:
  stage: test
  image: python:3.12-slim
  variables:
    LF_URL: "${url}"
    LF_PROJECT: "${pid}"
  script:
    - python3 -c "import urllib.request,os;r=urllib.request.Request(os.environ['LF_URL']+'/api/ci/client.py',headers={'Authorization':'Bearer '+os.environ['LF_TOKEN']});open('lf_ci.py','wb').write(urllib.request.urlopen(r).read())"
    - python3 lf_ci.py --target "$CI_PROJECT_NAME" --sarif gl-le-fureteur.sarif
  artifacts:
    when: always
    paths: [gl-le-fureteur.sarif]
`,
      steps: [
        t("Projede Settings → CI/CD → Variables: LF_TOKEN ekleyin (Masked ve Protected işaretli)."),
        t("Aşağıdaki işi .gitlab-ci.yml dosyanıza ekleyin."),
        t("Pipeline çalışınca sonuç işin günlüğünde ve SARIF eki olarak görünür."),
      ],
    },
    jenkins: {
      file: "Jenkinsfile", lang: "groovy",
      code: `pipeline {
  agent any
  environment {
    LF_URL = '${url}'
    LF_PROJECT = '${pid}'
  }
  stages {
    stage('Le Fureteur SCA') {
      steps {
        withCredentials([string(credentialsId: 'lf-token', variable: 'LF_TOKEN')]) {
          sh '''
            curl -fsS -H "Authorization: Bearer $LF_TOKEN" "$LF_URL/api/ci/client.py" -o lf_ci.py
            python3 lf_ci.py --target "$JOB_NAME" --sarif le-fureteur.sarif
          '''
        }
      }
    }
  }
}
`,
      steps: [
        t("Manage Jenkins → Credentials: \"Secret text\" türünde, kimliği lf-token olan bir kayıt oluşturun."),
        t("Aşağıdaki aşamayı Jenkinsfile'ınıza ekleyin."),
        t("Derleme, politika kapısından kalırsa başarısız olarak işaretlenir."),
      ],
    },
    azure: {
      file: "azure-pipelines.yml", lang: "yaml",
      code: `trigger: [main]

pool:
  vmImage: ubuntu-latest

steps:
  - script: |
      curl -fsS -H "Authorization: Bearer $(LF_TOKEN)" "${url}/api/ci/client.py" -o lf_ci.py
      python3 lf_ci.py --url "${url}" --token "$(LF_TOKEN)" --project ${pid} \\
        --target "$(Build.Repository.Name)" --sarif $(Build.ArtifactStagingDirectory)/le-fureteur.sarif
    displayName: Le Fureteur SCA
`,
      steps: [
        t("Pipeline → Edit → Variables: LF_TOKEN ekleyin (\"Keep this value secret\" işaretli)."),
        t("Aşağıdaki adımı azure-pipelines.yml dosyanıza ekleyin."),
        t("Sonuçlar derleme günlüğünde görünür; SARIF dosyası derleme çıktısına eklenir."),
      ],
    },
    cli: {
      file: "terminal", lang: "bash",
      code: `export LF_URL=${url}
export LF_PROJECT=${pid}
export LF_TOKEN=lf_...            # 2. adımdaki token

curl -fsS -H "Authorization: Bearer $LF_TOKEN" "$LF_URL/api/ci/client.py" -o lf_ci.py

python3 lf_ci.py                          # bulunduğunuz klasörü tara
python3 lf_ci.py --file sbom.cdx.json     # hazır SBOM yükle (CycloneDX / SPDX)
python3 lf_ci.py --fail-on CRITICAL       # yalnızca kritik bulguda dur
python3 lf_ci.py --new-only               # yalnızca yeni çıkan bulgularda dur
`,
      steps: [
        t("Yalnızca Python 3 gerekir; ek kurulum yoktur."),
        t("Çıkış kodu: 0 = geçti, 1 = politika kapısından kaldı, 2 = hata."),
      ],
    },
  } as Record<Platform, { file: string; lang: string; code: string; steps: string[] }>;
}

function Flow() {
  const items = [
    { icon: <IconKey size={22} />, title: t("Token"), text: t("Projeye özel, yalnızca tarama yetkili anahtar") },
    { icon: <IconGitPullRequest size={22} />, title: t("Her değişiklikte"), text: t("Push / pull request otomatik taranır") },
    { icon: <IconShieldCheck size={22} />, title: t("Politika kapısı"), text: t("Kritik açık varsa derleme durur") },
    { icon: <IconCircleCheck size={22} />, title: t("Sonuç"), text: t("Bulgular Le Fureteur'de ve kod platformunda") },
  ];
  return (
    <Card withBorder mb="lg">
      <Text fw={600} mb="md">{t("Nasıl çalışır?")}</Text>
      <Group wrap="nowrap" align="stretch" gap="xs" style={{ overflowX: "auto" }}>
        {items.map((it, i) => (
          <Group key={i} wrap="nowrap" gap="xs" align="stretch" style={{ flex: 1, minWidth: 180 }}>
            <Card withBorder padding="sm" style={{ flex: 1, height: "100%" }}>
              <ThemeIcon variant="light" color="indigo" size={40} radius="md" mb={8}>{it.icon}</ThemeIcon>
              <Text fw={600} size="sm">{i + 1}. {it.title}</Text>
              <Text size="xs" c="dimmed">{it.text}</Text>
            </Card>
            {i < items.length - 1 && <IconArrowRight size={18} color="var(--mantine-color-dimmed)" style={{ flexShrink: 0, alignSelf: "center" }} />}
          </Group>
        ))}
      </Group>
    </Card>
  );
}

function PolicySummary({ project }: { project: any }) {
  if (!project) return null;
  const p = project.ci_policy ?? {};
  const rules = [
    p.fail_on && p.fail_on !== "NONE" ? t("{sev} ve üzeri bulgu", { sev: SEV_LABEL[p.fail_on] }) : null,
    p.fail_on_kev ? t("aktif sömürülen (KEV) açık") : null,
    p.fail_on_malicious ? t("zararlı paket") : null,
    p.fail_on_license ? t("yasaklı lisans") : null,
  ].filter(Boolean) as string[];
  return (
    <Alert variant="light" color="indigo" icon={<IconShieldCheck size={18} />} mt="sm">
      <Text size="sm">{t("Bu projede derleme şu durumlarda durur:")} {rules.length ? rules.map((r) => <Badge key={r} variant="white" mx={2}>{r}</Badge>) : <b>{t("hiçbir durumda (yalnızca rapor)")}</b>}
        {p.new_only && <Badge variant="white" color="orange" mx={2}>{t("yalnızca yeni bulgular")}</Badge>}</Text>
      <Text size="xs" mt={4}><Link to={`/projects/${project.id}`}>{t("Politikayı değiştir: proje → Proje ayarları → CI politikası")}</Link></Text>
    </Alert>
  );
}

function SetupWizard({ user, onToken }: { user: User; onToken: () => void }) {
  const projects = useQuery<any[]>({ queryKey: ["projects"], queryFn: () => api("/projects") });
  const meta = useQuery<any>({ queryKey: ["meta"], queryFn: () => api("/meta") });
  const [active, setActive] = useState(0);
  const [pid, setPid] = useState<string | null>(null);
  const [token, setToken] = useState<string>("");
  const [platform, setPlatform] = useState<Platform>("github");
  const url = (meta.data?.public_url || window.location.origin).replace(/\/$/, "");
  const local = /localhost|127\.0\.0\.1/.test(url);
  const project = projects.data?.find((p) => String(p.id) === pid);
  const tpl = useMemo(() => templates(url, pid ?? "<proje-no>")[platform], [url, pid, platform]);

  async function makeToken() {
    try {
      const r = await api("/tokens", { body: { name: `ci-${platform}-${project?.name ?? pid}`.slice(0, 200), scopes: ["scan"], project_id: Number(pid), expires_days: 365 } });
      setToken(r.token);
      onToken();
    } catch (e) { fail(e); }
  }
  return (
    <Card withBorder>
      <Stepper active={active} onStepClick={setActive} allowNextStepsSelect={false} size="sm">
        <Stepper.Step label={t("Proje")} description={t("Hangi proje taransın?")}>
          <Stack mt="md" maw={520}>
            <Select label={t("Proje")} placeholder={t("Seçin")} data={(projects.data ?? []).map((p) => ({ value: String(p.id), label: `${p.name} — ${p.organization}` }))} value={pid} onChange={setPid} searchable />
            <PolicySummary project={project} />
            <Group><Button disabled={!pid} onClick={() => setActive(1)} rightSection={<IconArrowRight size={16} />}>{t("Devam")}</Button></Group>
          </Stack>
        </Stepper.Step>
        <Stepper.Step label={t("Token")} description={t("Pipeline'ın anahtarı")}>
          <Stack mt="md" maw={620}>
            <Text size="sm">{t("Bu projeye özel, yalnızca dosya yükleme ve tarama yetkisi olan bir token oluşturulur. Token bir kez gösterilir; pipeline'ınızın gizli değişkenine kaydedin.")}</Text>
            {!token ? (
              <Group><Button leftSection={<IconKey size={16} />} onClick={makeToken}>{t("Token oluştur")}</Button>
                <Button variant="subtle" onClick={() => setActive(2)}>{t("Zaten token'ım var")}</Button></Group>
            ) : (
              <Alert color="green" icon={<IconCheck size={18} />} title={t("Token hazır — şimdi kopyalayın, bir daha gösterilmeyecek")}>
                <Group gap="xs" wrap="nowrap"><Code style={{ wordBreak: "break-all" }}>{token}</Code>
                  <CopyButton value={token}>{({ copied, copy }) => <ActionIcon variant="subtle" color={copied ? "teal" : "gray"} onClick={copy}>{copied ? <IconCheck size={16} /> : <IconCopy size={16} />}</ActionIcon>}</CopyButton></Group>
              </Alert>
            )}
            {token && <Group><Button onClick={() => setActive(2)} rightSection={<IconArrowRight size={16} />}>{t("Devam")}</Button></Group>}
            {user.role === "customer" && <Text size="xs" c="dimmed">{t("Token'larınızı \"Token yönetimi\" sekmesinden görebilir ve iptal edebilirsiniz.")}</Text>}
          </Stack>
        </Stepper.Step>
        <Stepper.Step label={t("Platform")} description={t("CI aracınız")}>
          <SimpleGrid cols={{ base: 2, sm: 3, md: 5 }} mt="md">
            {PLATFORMS.map((p) => (
              <UnstyledButton key={p.id} onClick={() => { setPlatform(p.id); setActive(3); }}>
                <Card withBorder padding="lg" style={{ textAlign: "center", borderColor: platform === p.id ? "var(--mantine-color-indigo-5)" : undefined, borderWidth: platform === p.id ? 2 : 1 }}>
                  <ThemeIcon variant="light" color={p.color} size={52} radius="xl" mx="auto" mb={8}>{p.icon}</ThemeIcon>
                  <Text fw={600} size="sm">{p.name}</Text>
                </Card>
              </UnstyledButton>
            ))}
          </SimpleGrid>
        </Stepper.Step>
        <Stepper.Step label={t("Kurulum")} description={PLATFORMS.find((p) => p.id === platform)?.name}>
          <Stack mt="md">
            {local && <Alert color="yellow" variant="light">{t("Adres olarak {url} görünüyor; CI sunucunuz buna ulaşamayabilir. Yönetici, Ayarlar → Genel → \"Arayüzün adresi\" alanına dışarıdan erişilen adresi girmeli.", { url })}</Alert>}
            <List type="ordered" spacing="sm" size="sm">
              {tpl.steps.map((s, i) => <List.Item key={i}>{s}</List.Item>)}
            </List>
            <CodeBlock code={tpl.code} filename={tpl.file} lang={tpl.lang} download={tpl.file === "terminal" ? "lf-ci.sh" : tpl.file.split("/").pop()} />
            <Group justify="space-between">
              <Button variant="default" onClick={() => setActive(2)}>{t("Başka platform")}</Button>
              <Button component={Link} to="/scans" variant="light" leftSection={<IconPlayerPlay size={16} />}>{t("Sonuçlar: Taramalar sayfası")}</Button>
            </Group>
          </Stack>
        </Stepper.Step>
      </Stepper>
    </Card>
  );
}

function TokenAdmin({ user }: { user: User }) {
  const qc = useQueryClient();
  const tokens = useQuery<any[]>({ queryKey: ["tokens"], queryFn: () => api("/tokens") });
  const projects = useQuery<any[]>({ queryKey: ["projects"], queryFn: () => api("/projects") });
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({ name: "", project_id: "", read: false, scan: true, days: 365 as number | string });
  const [created, setCreated] = useState("");
  async function create() {
    try {
      const scopes = [form.read && "read", form.scan && "scan"].filter(Boolean);
      const r = await api("/tokens", { body: { name: form.name, scopes, project_id: form.project_id ? Number(form.project_id) : null, expires_days: Number(form.days) || null } });
      setCreated(r.token); setOpen(false);
      qc.invalidateQueries({ queryKey: ["tokens"] });
    } catch (e) { fail(e); }
  }
  async function revoke(tk: any) {
    if (!confirm(t("\"{name}\" token'ı iptal edilsin mi? Bu token'ı kullanan pipeline'lar çalışmayı durdurur.", { name: tk.name }))) return;
    try { await api(`/tokens/${tk.id}`, { method: "DELETE" }); ok(t("Token iptal edildi")); qc.invalidateQueries({ queryKey: ["tokens"] }); } catch (e) { fail(e); }
  }
  return (
    <>
      {created && (
        <Alert color="green" mb="md" withCloseButton onClose={() => setCreated("")} title={t("Token oluşturuldu — şimdi kopyalayın, bir daha gösterilmeyecek")}>
          <Group gap="xs" wrap="nowrap"><Code style={{ wordBreak: "break-all" }}>{created}</Code>
            <CopyButton value={created}>{({ copied, copy }) => <ActionIcon variant="subtle" color={copied ? "teal" : "gray"} onClick={copy}>{copied ? <IconCheck size={16} /> : <IconCopy size={16} />}</ActionIcon>}</CopyButton></Group>
        </Alert>
      )}
      <Card withBorder p={0}>
        <Group justify="space-between" p="md" pb="xs">
          <div><Text fw={600}>{t("API token'ları")}</Text><Text size="xs" c="dimmed">{t("Token, sahibinin rolü ve organizasyonuyla sınırlıdır; kullanıcı, ayar ve token yönetimine erişemez.")}</Text></div>
          <Button size="xs" leftSection={<IconKey size={14} />} onClick={() => { setForm({ name: "", project_id: "", read: false, scan: true, days: 365 }); setOpen(true); }}>{t("Yeni token")}</Button>
        </Group>
        <Table.ScrollContainer minWidth={760}>
          <Table verticalSpacing="sm">
            <Table.Thead><Table.Tr><Table.Th>{t("Ad")}</Table.Th><Table.Th>{t("Yetki")}</Table.Th><Table.Th>{t("Proje")}</Table.Th><Table.Th>{t("Son kullanım")}</Table.Th><Table.Th>{t("Bitiş")}</Table.Th><Table.Th /></Table.Tr></Table.Thead>
            <Table.Tbody>
              {(tokens.data ?? []).map((tk) => (
                <Table.Tr key={tk.id} style={{ opacity: tk.revoked ? 0.45 : 1 }}>
                  <Table.Td><Text size="sm" fw={600}>{tk.name}</Text><Text size="xs" c="dimmed" ff="monospace">{tk.prefix}…{user.role === "admin" && tk.owner !== user.email ? ` · ${tk.owner}` : ""}</Text></Table.Td>
                  <Table.Td><Group gap={4}>{tk.scopes.map((s: string) => <Badge key={s} size="sm" variant="light">{s === "scan" ? t("tarama") : t("okuma")}</Badge>)}{tk.revoked && <Badge size="sm" color="red" variant="light">{t("iptal edildi")}</Badge>}</Group></Table.Td>
                  <Table.Td><Text size="sm">{tk.project ?? t("Tüm projeler (rol kapsamında)")}</Text></Table.Td>
                  <Table.Td><Text size="sm">{fmtDate(tk.last_used_at)}</Text><Text size="xs" c="dimmed">{tk.last_used_ip}</Text></Table.Td>
                  <Table.Td><Text size="sm">{tk.expires_at ? fmtDate(tk.expires_at) : t("süresiz")}</Text></Table.Td>
                  <Table.Td ta="right">{!tk.revoked && <Tooltip label={t("İptal et")}><ActionIcon variant="subtle" color="red" onClick={() => revoke(tk)} aria-label={t("İptal et")}><IconTrash size={16} /></ActionIcon></Tooltip>}</Table.Td>
                </Table.Tr>
              ))}
              {tokens.data?.length === 0 && <Table.Tr><Table.Td colSpan={6}><Stack align="center" py="lg" gap={4}><IconKey size={28} color="var(--mantine-color-dimmed)" /><Text c="dimmed" size="sm">{t("Henüz token yok — kurulum sihirbazı sizin için oluşturur.")}</Text></Stack></Table.Td></Table.Tr>}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      </Card>
      <Modal opened={open} onClose={() => setOpen(false)} title={t("Yeni API token'ı")}>
        <Stack>
          <TextInput label={t("Ad")} placeholder="github-actions portal" value={form.name} onChange={(e) => setForm({ ...form, name: e.currentTarget.value })} />
          <Select label={t("Proje")} description={user.role === "customer" ? t("Müşteri token'ı bir projeyle sınırlı olmalı") : t("Önerilen: token'ı tek projeyle sınırlayın")}
            clearable={user.role !== "customer"} data={(projects.data ?? []).map((p) => ({ value: String(p.id), label: p.name }))}
            value={form.project_id || null} onChange={(v) => setForm({ ...form, project_id: v ?? "" })} placeholder={t("Tüm projeler (rol kapsamında)")} />
          <Checkbox label={t("Tarama — dosya yükleme, tarama başlatma, CI")} checked={form.scan} onChange={(e) => setForm({ ...form, scan: e.currentTarget.checked })} />
          <Checkbox label={t("Okuma — proje, tarama ve bulguları görüntüleme (raporlama araçları için)")} checked={form.read} onChange={(e) => setForm({ ...form, read: e.currentTarget.checked })} />
          <NumberInput label={t("Geçerlilik (gün)")} min={1} max={3650} value={form.days} onChange={(v) => setForm({ ...form, days: v })} />
          <Group justify="flex-end"><Button onClick={create} disabled={!form.name || (!form.read && !form.scan) || (user.role === "customer" && !form.project_id)}>{t("Oluştur")}</Button></Group>
        </Stack>
      </Modal>
    </>
  );
}

export default function ApiCi({ user }: { user: User }) {
  const qc = useQueryClient();
  return (
    <>
      <PageHeader title={t("API & CI/CD")} sub={t("Bağımlılık taramasını yazılım geliştirme sürecinize ekleyin")} />
      <PageIntro id="api-ci" guide="automation"
        text={t("Her kod değişikliğinde bağımlılıklarınız otomatik taranır. Kritik bir açık ya da yasaklı lisans bulunursa derleme durur; geliştirici sorunu canlıya çıkmadan görür.")}
        points={[t("Kurulum 3 dakika: proje seçin, token oluşturun, platformunuzu seçip hazır dosyayı ekleyin."), t("Derlemenin hangi durumda duracağını proje ayarlarındaki CI politikası belirler."), t("Sonuçlar Le Fureteur'de ve (destekleyen platformlarda) kod tarama sekmesinde görünür.")]} />
      <Flow />
      <Tabs defaultValue="setup">
        <Tabs.List mb="md">
          <Tabs.Tab value="setup" leftSection={<IconPlayerPlay size={14} />}>{t("Kurulum sihirbazı")}</Tabs.Tab>
          <Tabs.Tab value="tokens" leftSection={<IconKey size={14} />}>{t("Token yönetimi")}</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="setup"><SetupWizard user={user} onToken={() => qc.invalidateQueries({ queryKey: ["tokens"] })} /></Tabs.Panel>
        <Tabs.Panel value="tokens"><TokenAdmin user={user} /></Tabs.Panel>
      </Tabs>
      <Title order={6} c="dimmed" mt="lg" fw={400} size="xs">{t("Tüm seçenekler ve Azure / Jenkins şablonları: Rehber → API ve sunucudaki deploy/ci klasörü.")}</Title>
    </>
  );
}
