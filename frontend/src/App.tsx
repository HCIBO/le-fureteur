import { Box, ActionIcon, Tooltip, AppShell, Burger, Group, Menu, NavLink, Text, UnstyledButton, Avatar, Loader, Center } from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { IconBug, IconBuilding, IconDatabase, IconFolders, IconGauge, IconHistory, IconLogout, IconRadar, IconSettings, IconUsers, IconKey, IconBell, IconHeartbeat, IconBook, IconAddressBook, IconLanguage, IconCheck, IconPlugConnected, IconUsersGroup, IconChecks, IconGavel, IconMail, IconTool, IconLayoutSidebarLeftCollapse, IconLayoutSidebarLeftExpand, IconTerminal2 } from "@tabler/icons-react";
import { Link, Navigate, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { api, ROLE_LABEL, User } from "./api";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Projects from "./pages/Projects";
import ProjectDetail from "./pages/ProjectDetail";
import TargetDetail from "./pages/TargetDetail";
import Scans from "./pages/Scans";
import ScanDetail from "./pages/ScanDetail";
import Findings from "./pages/Findings";
import Orgs from "./pages/Orgs";
import Users from "./pages/Users";
import UserDetail from "./pages/UserDetail";
import { AdminMaintenanceBanner, MaintenanceScreen, useMaintenanceBlock, usePublicStatus } from "./components/Maintenance";
import Settings from "./pages/Settings";
import Audit from "./pages/Audit";
import Account from "./pages/Account";
import Guide from "./pages/Guide";
import Scakit from "./pages/Scakit";
import Contact from "./pages/Contact";
import Toolset from "./pages/Toolset";
import { Clock } from "./components/Clock";
import { ThemeButton } from "./theme";
import ApiCi from "./pages/ApiCi";
import Teams from "./pages/Teams";
import Approvals from "./pages/Approvals";
import Disputes from "./pages/Disputes";
import Messages from "./pages/Messages";
import TeamDetail from "./pages/TeamDetail";
import AddTarget from "./pages/AddTarget";
import { MessagesBell } from "./components/Messaging";
import InboxPage from "./pages/Inbox";
import { InboxBell, PendingBadge } from "./components/Inbox";
import { LANGS, Lang, lang, storeLang, switchLang } from "./i18n";
import { PRODUCT } from "./brand";
import { useEffect, useState } from "react";
import Notifications from "./pages/Notifications";
import SystemPage from "./pages/System";
import { t } from "./i18n";

function MaintenanceGate() {
  const st = usePublicStatus();
  async function out() { await api("/auth/logout", { method: "POST" }).catch(() => undefined); window.location.href = "/login"; }
  return <MaintenanceScreen message={st.data?.message ?? ""} onLogout={out} />;
}

export default function App() {
  const loc = useLocation();
  const me = useQuery<User>({ queryKey: ["me"], queryFn: () => api("/auth/me"), enabled: loc.pathname !== "/login" });
  useEffect(() => {
    const ul = me.data?.lang as Lang | null | undefined;
    if (ul && ul !== lang) { storeLang(ul); window.location.reload(); }
  }, [me.data?.lang]);
  if (loc.pathname === "/login") return <Login />;
  if (me.isLoading) return <Center h="100vh"><Loader /></Center>;
  if ((me.error as any)?.status === 503) return <MaintenanceGate />;
  if (me.isError || !me.data) return <Navigate to="/login" replace />;
  return <Shell user={me.data} />;
}

function Shell({ user }: { user: User }) {
  const [opened, { toggle }] = useDisclosure();
  const [mini, setMini] = useState(() => { try { return localStorage.getItem("lf_nav_mini") === "1"; } catch { return false; } });
  const toggleMini = () => setMini((m) => { try { localStorage.setItem("lf_nav_mini", m ? "0" : "1"); } catch {  } return !m; });
  const loc = useLocation();
  const nav = useNavigate();
  const qc = useQueryClient();
  const staff = user.role !== "customer";
  const admin = user.role === "admin";
  const items = [
    { to: "/", label: t("Pano"), icon: IconGauge, show: true },
    { to: "/projects", label: t("Projeler & hedefler"), icon: IconFolders, show: true },
    { to: "/scans", label: t("Taramalar"), icon: IconRadar, show: true },
    { to: "/findings", label: t("Bulgular"), icon: IconBug, show: true },
    { to: "/approvals", label: t("Onaylar"), icon: IconChecks, show: true, badge: true },
    { to: "/messages", label: t("Mesajlar"), icon: IconMail, show: true },
    { to: "/disputes", label: t("Tartışmalar"), icon: IconGavel, show: true },
    { to: "/teams", label: t("Takımlar"), icon: IconUsersGroup, show: true },
    { to: "/orgs", label: t("Organizasyonlar"), icon: IconBuilding, show: staff },
    { to: "/users", label: t("Kullanıcılar"), icon: IconUsers, show: admin },
    { to: "/settings", label: t("Ayarlar & veritabanı"), icon: admin ? IconSettings : IconDatabase, show: staff },
    { to: "/notifications", label: t("Bildirim kanalları"), icon: IconBell, show: admin },
    { to: "/api-ci", label: t("API & CI/CD"), icon: IconPlugConnected, show: true },
    { to: "/system", label: t("Sistem durumu"), icon: IconHeartbeat, show: staff },
    { to: "/audit", label: t("Denetim kaydı"), icon: IconHistory, show: admin },
    { to: "/guide", label: t("Rehber"), icon: IconBook, show: true },
    { to: "/scakit", label: t("Komut satırı (scakit)"), icon: IconTerminal2, show: true },
    { to: "/tools", label: t("Araç seti"), icon: IconTool, show: true },
    { to: "/contact", label: t("İletişim"), icon: IconAddressBook, show: true },
  ];
  const active = (to: string) => (to === "/" ? loc.pathname === "/" : loc.pathname.startsWith(to));
  async function logout() {
    await api("/auth/logout", { method: "POST" }).catch(() => undefined);
    qc.clear();
    nav("/login");
  }
  const blocked = useMaintenanceBlock();
  if (blocked !== null && !admin) return <MaintenanceScreen message={blocked} onLogout={logout} />;
  return (
    <AppShell header={{ height: 56 }} navbar={{ width: mini ? 68 : 240, breakpoint: "sm", collapsed: { mobile: !opened } }} padding="lg" transitionDuration={150}>
      <AppShell.Header>
        <Group h="100%" px="md" justify="space-between" pos="relative">
          <Group gap="xs">
            <Burger opened={opened} onClick={toggle} hiddenFrom="sm" size="sm" />
            <Tooltip label={mini ? t("Menüyü genişlet") : t("Menüyü daralt")}><ActionIcon variant="subtle" color="gray" onClick={toggleMini} visibleFrom="sm" aria-label={t("Menüyü daralt")}>
              {mini ? <IconLayoutSidebarLeftExpand size={20} /> : <IconLayoutSidebarLeftCollapse size={20} />}</ActionIcon></Tooltip>
            <Text fw={800} size="lg">{PRODUCT}</Text>
            <Text size="xs" c="dimmed" visibleFrom="xs">{t("Yazılım Bileşen Analizi")}</Text>
          </Group>
          <Box visibleFrom="md"><Clock /></Box>
          <Group gap="xs" wrap="nowrap"><ThemeButton /><MessagesBell /><InboxBell />
          <Menu position="bottom-end">
            <Menu.Target>
              <UnstyledButton>
                <Group gap="xs">
                  <Avatar size="sm" color="indigo">{user.email[0].toUpperCase()}</Avatar>
                  <div style={{ lineHeight: 1.1 }}>
                    <Text size="sm">{user.email}</Text>
                    <Text size="xs" c="dimmed">{ROLE_LABEL[user.role]}{user.organization ? ` · ${user.organization}` : ""}</Text>
                  </div>
                </Group>
              </UnstyledButton>
            </Menu.Target>
            <Menu.Dropdown>
              <Menu.Label><Group gap={6}><IconLanguage size={14} />{t("Dil")}</Group></Menu.Label>
              {LANGS.map((l) => (
                <Menu.Item key={l.value} rightSection={l.value === lang ? <IconCheck size={14} /> : null}
                  onClick={() => l.value !== lang && switchLang(l.value, (v) => api("/auth/me", { method: "PATCH", body: { lang: v } }))}>{l.label}</Menu.Item>
              ))}
              <Menu.Divider />
              <Menu.Item leftSection={<IconKey size={16} />} component={Link} to="/account">{t("Hesabım")}</Menu.Item>
              <Menu.Item leftSection={<IconLogout size={16} />} onClick={logout}>{t("Çıkış")}</Menu.Item>
            </Menu.Dropdown>
          </Menu></Group>
        </Group>
      </AppShell.Header>
      <AppShell.Navbar p="xs">
        {items.filter((i) => i.show).map((i) => (
          mini ? (
            <Tooltip key={i.to} label={i.label} position="right" withArrow>
              <NavLink component={Link} to={i.to} label={null} leftSection={<i.icon size={20} />} active={active(i.to)} onClick={() => opened && toggle()} style={{ justifyContent: "center" }}
                rightSection={"badge" in i ? <PendingBadge /> : null} />
            </Tooltip>
          ) : (
            <NavLink key={i.to} component={Link} to={i.to} label={i.label} leftSection={<i.icon size={18} />} rightSection={"badge" in i ? <PendingBadge /> : null} active={active(i.to)} onClick={() => opened && toggle()} />
          )
        ))}
      </AppShell.Navbar>
      <AppShell.Main>
        {admin && <div style={{ margin: "calc(var(--mantine-spacing-lg) * -1) calc(var(--mantine-spacing-lg) * -1) var(--mantine-spacing-md)" }}><AdminMaintenanceBanner /></div>}
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/projects" element={<Projects user={user} />} />
          <Route path="/projects/:id" element={<ProjectDetail user={user} />} />
          <Route path="/projects/:id/targets/new" element={<AddTarget user={user} />} />
          <Route path="/targets/:id" element={<TargetDetail user={user} />} />
          <Route path="/scans" element={<Scans user={user} />} />
          <Route path="/scans/:id" element={<ScanDetail />} />
          <Route path="/findings" element={<Findings />} />
          {staff && <Route path="/orgs" element={<Orgs user={user} />} />}
          {admin && <Route path="/users" element={<Users />} />}
          {admin && <Route path="/users/:id" element={<UserDetail />} />}
          {staff && <Route path="/settings" element={<Settings user={user} />} />}
          {admin && <Route path="/audit" element={<Audit />} />}
          {admin && <Route path="/notifications" element={<Notifications />} />}
          {staff && <Route path="/system" element={<SystemPage user={user} />} />}
          <Route path="/account" element={<Account />} />
          <Route path="/guide" element={<Guide user={user} />} />
          <Route path="/scakit" element={<Scakit user={user} />} />
          <Route path="/contact" element={<Contact />} />
          <Route path="/tools" element={<Toolset />} />
          <Route path="/api-ci" element={<ApiCi user={user} />} />
          <Route path="/teams" element={<Teams user={user} />} />
          <Route path="/teams/:id" element={<TeamDetail />} />
          <Route path="/approvals" element={<Approvals />} />
          <Route path="/disputes" element={<Disputes />} />
          <Route path="/messages" element={<Messages />} />
          <Route path="/messages/:id" element={<Messages />} />
          <Route path="/disputes/:id" element={<Disputes />} />
          <Route path="/inbox" element={<InboxPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AppShell.Main>
    </AppShell>
  );
}
