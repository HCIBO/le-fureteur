import { usePublicStatus } from "../components/Maintenance";
import { Alert, Box, Button, Divider, Group, Paper, PasswordInput, Select, Stack, Text, TextInput, ThemeIcon, Title } from "@mantine/core";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { IconBarrierBlock, IconBuildingSkyscraper, IconLanguage, IconLock, IconRadar2, IconShieldCheck, IconTopologyStar3 } from "@tabler/icons-react";
import { api } from "../api";
import { t, LANGS, lang, Lang, switchLang } from "../i18n";
import { PRODUCT } from "../brand";

function NetworkBackground() {
  const svgRef = useRef<SVGSVGElement>(null);
  const { nodes, links } = useMemo(() => {
    let seed = 7;
    const rnd = () => ((seed = (seed * 16807) % 2147483647) / 2147483647);
    const nodes = Array.from({ length: 52 }, (_, i) => ({ id: i, x: rnd() * 1600, y: rnd() * 1000, r: 2 + rnd() * 3.5, bad: rnd() < 0.13, d: rnd() * 6 }));
    const links: [number, number][] = [];
    nodes.forEach((a) => {
      nodes.map((b) => ({ b, dist: Math.hypot(a.x - b.x, a.y - b.y) })).filter((o) => o.b.id > a.id && o.dist < 250)
        .sort((p, q) => p.dist - q.dist).slice(0, 3).forEach((o) => links.push([a.id, o.b.id]));
    });
    return { nodes, links };
  }, []);
  useEffect(() => {
    const svg = svgRef.current;
    if (!svg || window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) return;
    const circles = Array.from(svg.querySelectorAll<SVGCircleElement>("circle[data-n]"));
    const lines = Array.from(svg.querySelectorAll<SVGLineElement>("line[data-a]"));
    const pos = nodes.map((n) => ({ x: n.x, y: n.y }));
    const mouse = { x: -9999, y: -9999 };
    const onMove = (e: PointerEvent) => {
      const m = svg.getScreenCTM();
      if (!m) return;
      const pt = new DOMPoint(e.clientX, e.clientY).matrixTransform(m.inverse());
      mouse.x = pt.x; mouse.y = pt.y;
    };
    const onLeave = () => { mouse.x = mouse.y = -9999; };
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerleave", onLeave);
    let raf = 0;
    const tick = (time: number) => {
      const t = time / 1000;
      nodes.forEach((n, i) => {
        const hx = n.x + Math.sin(t * 0.35 + n.d) * 9, hy = n.y + Math.cos(t * 0.3 + n.d) * 7;
        const dx = hx - mouse.x, dy = hy - mouse.y, dist = Math.hypot(dx, dy);
        const push = dist < 190 ? (1 - dist / 190) * 55 : 0;
        const tx = hx + (dist > 0 ? (dx / dist) * push : 0), ty = hy + (dist > 0 ? (dy / dist) * push : 0);
        pos[i].x += (tx - pos[i].x) * 0.12;
        pos[i].y += (ty - pos[i].y) * 0.12;
      });
      circles.forEach((c) => { const p = pos[Number(c.dataset.n)]; c.setAttribute("cx", p.x.toFixed(1)); c.setAttribute("cy", p.y.toFixed(1)); });
      lines.forEach((l) => {
        const a = pos[Number(l.dataset.a)], b = pos[Number(l.dataset.b)];
        l.setAttribute("x1", a.x.toFixed(1)); l.setAttribute("y1", a.y.toFixed(1)); l.setAttribute("x2", b.x.toFixed(1)); l.setAttribute("y2", b.y.toFixed(1));
      });
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => { cancelAnimationFrame(raf); window.removeEventListener("pointermove", onMove); window.removeEventListener("pointerleave", onLeave); };
  }, [nodes]);
  return (
    <Box style={{ position: "absolute", inset: 0, overflow: "hidden" }} aria-hidden>
      <style>{`
        .lf-bg{background:radial-gradient(1200px 700px at 15% 20%,#3b2fbd 0%,transparent 60%),radial-gradient(900px 600px at 85% 80%,#0e7490 0%,transparent 60%),linear-gradient(135deg,#0b1020 0%,#111a3a 50%,#0b1020 100%);}
        .lf-blob{position:absolute;border-radius:50%;filter:blur(70px);opacity:.45;animation:lf-float 22s ease-in-out infinite alternate}
        @keyframes lf-float{0%{transform:translate(0,0) scale(1)}100%{transform:translate(120px,-80px) scale(1.25)}}
        .lf-link{stroke:rgba(148,163,255,.24);stroke-width:1;stroke-dasharray:6 10;animation:lf-flow 14s linear infinite}
        @keyframes lf-flow{to{stroke-dashoffset:-320}}
        .lf-node{fill:rgba(199,210,254,.85)}
        .lf-bad{fill:#f87171;animation:lf-pulse 2.8s ease-in-out infinite}
        @keyframes lf-pulse{0%,100%{opacity:.55}50%{opacity:1}}
        .lf-scan{position:absolute;left:0;right:0;height:180px;background:linear-gradient(180deg,transparent,rgba(99,102,241,.12),transparent);animation:lf-scan 9s linear infinite}
        @keyframes lf-scan{0%{top:-200px}100%{top:100%}}
        @media (prefers-reduced-motion: reduce){.lf-blob,.lf-link,.lf-bad,.lf-scan{animation:none!important}}
      `}</style>
      <Box className="lf-bg" style={{ position: "absolute", inset: 0 }} />
      <div className="lf-blob" style={{ width: 420, height: 420, left: "8%", top: "10%", background: "#6366f1" }} />
      <div className="lf-blob" style={{ width: 380, height: 380, right: "6%", bottom: "8%", background: "#06b6d4", animationDelay: "-9s" }} />
      <svg ref={svgRef} viewBox="0 0 1600 1000" preserveAspectRatio="xMidYMid slice" style={{ position: "absolute", inset: 0, width: "100%", height: "100%" }}>
        {links.map(([a, b], i) => <line key={i} data-a={a} data-b={b} className="lf-link" x1={nodes[a].x} y1={nodes[a].y} x2={nodes[b].x} y2={nodes[b].y} style={{ animationDelay: `-${(i % 9) * 1.3}s` }} />)}
        {nodes.map((n) => <circle key={n.id} data-n={n.id} className={n.bad ? "lf-bad" : "lf-node"} cx={n.x} cy={n.y} r={n.r} style={{ animationDelay: `-${n.d}s` }} />)}
      </svg>
      <div className="lf-scan" />
    </Box>
  );
}

const SSO_ERRORS: Record<string, string> = {
  no_account: t("Bu kurumsal hesap Le Fureteur'de tanımlı değil. Yöneticinizden hesap açmasını isteyin."),
  failed: t("Kurumsal giriş doğrulanamadı. Lütfen tekrar deneyin."),
  denied: t("Kurumsal giriş iptal edildi."),
  config: t("Kurumsal giriş şu anda kullanılamıyor (yapılandırma hatası)."),
  maintenance: t("Sistem bakımda; şu anda yalnızca yöneticiler giriş yapabilir."),
};

export default function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [sp] = useSearchParams();
  const nav = useNavigate();
  const qc = useQueryClient();
  const sso = useQuery<{ enabled: boolean; label: string }>({ queryKey: ["oidc-config"], queryFn: () => api("/auth/oidc/config") });
  const ssoErr = sp.get("sso_error");
  const status = usePublicStatus(30000);
  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      if (!document.cookie.includes("scakit_csrf=")) await fetch("/api/health");
      const u = await api("/auth/login", { body: { email, password } });
      qc.setQueryData(["me"], u);
      nav("/");
    } catch (ex) {
      setErr(t(ex instanceof Error ? ex.message : String(ex)));
    } finally {
      setBusy(false);
    }
  }
  const features = [
    { icon: IconTopologyStar3, title: t("Tüm bileşenleri görün"), text: t("Kaynak kod, mobil uygulama, imaj ve web sitelerindeki üçüncü taraf bileşenler") },
    { icon: IconRadar2, title: t("Riskleri önceliklendirin"), text: t("Aktif sömürülen açıklar, istismar olasılığı ve düzeltme sürümü") },
    { icon: IconShieldCheck, title: t("Kurum içinde kalır"), text: t("Kod ve bulgular sunucunuzdan dışarı çıkmaz") },
  ];
  return (
    <Box style={{ position: "relative", minHeight: "100vh", color: "#e5e7eb" }}>
      <NetworkBackground />
      <Select size="xs" w={130} data={LANGS} value={lang} onChange={(v) => v && v !== lang && switchLang(v as Lang)} allowDeselect={false}
        aria-label={t("Dil")} leftSection={<IconLanguage size={14} />} style={{ position: "absolute", top: 16, right: 16, zIndex: 2 }} />
      <Group justify="center" align="center" gap={80} style={{ position: "relative", minHeight: "100vh", padding: 24 }} wrap="nowrap">
        <Stack gap="lg" maw={460} visibleFrom="md">
          <div>
            <Title order={1} c="white" style={{ fontSize: 46, letterSpacing: -1 }}>{PRODUCT}</Title>
            <Text size="lg" c="indigo.1" mt={6}>{t("Yazılımınızın içinde ne olduğunu bilin.")}</Text>
          </div>
          {features.map((f) => (
            <Group key={f.title} wrap="nowrap" align="flex-start" gap="md">
              <ThemeIcon size={42} radius="md" variant="light" color="indigo" style={{ background: "rgba(99,102,241,.18)" }}><f.icon size={22} color="#c7d2fe" /></ThemeIcon>
              <div><Text fw={600} c="white">{f.title}</Text><Text size="sm" c="gray.4">{f.text}</Text></div>
            </Group>
          ))}
        </Stack>
        <Paper component="form" onSubmit={submit} data-mantine-color-scheme="light" w={400} maw="100%" p="xl" radius="lg" shadow="xl"
          style={{ background: "rgba(255,255,255,.94)", backdropFilter: "blur(14px)", border: "1px solid rgba(255,255,255,.4)", color: "#1f2937" }}>
          <Stack>
            <Group justify="space-between" align="flex-start">
              <div>
                <Group gap={8}><ThemeIcon radius="md" size={34} variant="gradient" gradient={{ from: "indigo", to: "cyan" }}><IconLock size={18} /></ThemeIcon>
                  <Title order={3} c="dark">{PRODUCT}</Title></Group>
                <Text c="dimmed" size="sm" mt={4}>{t("Yazılım Bileşen Analizi")}</Text>
              </div>
            </Group>
            {status.data?.maintenance && (
              <Alert color="orange" variant="light" icon={<IconBarrierBlock size={18} />} title={t("Bakım çalışması")}>
                {t("Sistem şu anda bakımda; yalnızca yöneticiler giriş yapabilir.")}{status.data.message ? <><br />{status.data.message}</> : null}
              </Alert>
            )}
            {ssoErr && <Alert color="orange" variant="light">{SSO_ERRORS[ssoErr] ?? SSO_ERRORS.failed}</Alert>}
            {err && <Alert color="red" variant="light">{err}</Alert>}
            {sso.data?.enabled && (
              <>
                <Button component="a" href="/api/auth/oidc/start" size="md" variant="default" leftSection={<IconBuildingSkyscraper size={18} />}>
                  {sso.data.label || t("Kurumsal hesapla giriş")}
                </Button>
                <Divider label={t("veya e-posta ile")} labelPosition="center" />
              </>
            )}
            <TextInput label={t("E-posta")} value={email} onChange={(e) => setEmail(e.currentTarget.value)} autoComplete="username" required autoFocus={!sso.data?.enabled} />
            <PasswordInput label={t("Parola")} value={password} onChange={(e) => setPassword(e.currentTarget.value)} autoComplete="current-password" required />
            <Button type="submit" loading={busy} size="md" variant="gradient" gradient={{ from: "indigo", to: "cyan", deg: 90 }}>{t("Giriş yap")}</Button>
            <Text size="xs" c="dimmed" ta="center">{t("Erişim sorunları için kurumunuzdaki Le Fureteur yöneticisine başvurun.")}</Text>
          </Stack>
        </Paper>
      </Group>
    </Box>
  );
}
