import { Accordion, Badge, Code, Group, ScrollArea, Stack, Text, ThemeIcon, Timeline } from "@mantine/core";
import { IconShieldLock, IconAlertTriangle, IconBell, IconBellOff, IconCheck, IconFileDescription, IconFileUpload, IconFlag, IconGitMerge,
  IconListCheck, IconLock, IconPlayerPlay, IconTicket, IconX } from "@tabler/icons-react";
import { fmtDate } from "../api";
import { WAF_NAME } from "./WafCard";
import { t } from "../i18n";

export type JobEvent = { at: string; code: string; level: string; params: any };

export function reasonText(p: any): string {
  const host = p?.host ? String(p.host) : "";
  switch (p?.kind) {
    case "dns": return t("{host} adresi çözümlenemedi (DNS)", { host: host || "?" });
    case "timeout": return t("{host} yanıt vermedi (zaman aşımı)", { host: host || "?" });
    case "refused": return t("{host} bağlantıyı reddetti", { host: host || "?" });
    case "tls": return t("TLS / sertifika hatası");
    case "http": return t("Karşı sistem HTTP {status} döndürdü", { status: p.status });
    case "auth": return t("Kimlik doğrulama reddedildi");
    case "blocked": return t("İç ağ / ayrılmış adres güvenlik nedeniyle engellendi");
    case "unsafe": return p.detail ? t(p.detail) : t("Güvenlik sınırı aşıldı");
    default: return p?.detail ? t(p.detail) : t("Beklenmeyen hata");
  }
}

const KIND: Record<string, string> = {
  source: t("Kaynak kod"), archive: t("Derlenmiş paket"), image: t("Container imajı"), web: t("Web"), apk: "Android",
  ipa: "iOS", desktop: t("Masaüstü"), list: t("Paket listesi"), sbom: "SBOM",
};

function render(e: JobEvent): { icon: any; color: string; title: string; detail?: any } {
  const p = e.params ?? {};
  switch (e.code) {
    case "scan_started": return { icon: IconPlayerPlay, color: "indigo", title: t("Tarama başladı: {target}", { target: p.target }),
      detail: p.url ?? (p.files?.length ? p.files.join(", ") : undefined) };
    case "auth": return { icon: IconLock, color: "grape", title: t("Kimlik doğrulama kullanıldı: {type}", { type: p.type }) };
    case "input_started": return { icon: IconFileUpload, color: "blue", title: t("{name} inceleniyor", { name: p.name }) };
    case "input_done": return { icon: IconListCheck, color: "blue", title: t("{name}: {n} tespit, {m} yeni bileşen", { name: p.name, n: p.detections, m: p.new }),
      detail: [KIND[p.kind] ?? p.kind, p.nested ? t("{n} iç içe dosya", { n: p.nested }) : null].filter(Boolean).join(" · ") };
    case "input_error": return { icon: IconX, color: "red", title: t("{name} işlenemedi", { name: p.name }), detail: p.reason };
    case "matched": return { icon: IconGitMerge, color: "teal", title: t("{c} bileşen zafiyet veritabanıyla eşleştirildi: {f} bulgu", { c: p.components, f: p.findings }),
      detail: p.suppressed ? t("{n} bulgu kabul edilen risk / yanlış pozitif olarak ayrıldı", { n: p.suppressed }) : undefined };
    case "synced": return { icon: IconFlag, color: "teal", title: t("Bulgular güncellendi"),
      detail: <Group gap={6}><Badge size="sm" variant="light" color="red">{t("{n} yeni", { n: p.new })}</Badge><Badge size="sm" variant="light" color="green">{t("{n} kapandı", { n: p.fixed })}</Badge><Badge size="sm" variant="light" color="orange">{t("{n} yeniden açıldı", { n: p.reopened })}</Badge></Group> };
    case "reports": return { icon: IconFileDescription, color: "cyan", title: t("Raporlar hazırlandı"),
      detail: <Group gap={4}>{(p.files ?? []).map((f: string) => <Badge key={f} size="sm" variant="outline" tt="none">{f}</Badge>)}</Group> };
    case "jira_created": return { icon: IconTicket, color: "blue", title: t("Jira'da {n} kayıt açıldı", { n: p.count }) };
    case "jira_failed": return { icon: IconTicket, color: "orange", title: t("Jira kaydı açılamadı"), detail: reasonText(p) };
    case "notify_sent": return { icon: IconBell, color: "green", title: t("{channel} kanalına bildirim gönderildi", { channel: p.channel }) };
    case "notify_failed": return { icon: IconBellOff, color: "orange", title: t("{channel} kanalına bildirim gönderilemedi", { channel: p.channel }),
      detail: `${reasonText(p)} — ${t("Bildirim kanalları sayfasından adresi kontrol edin; tarama sonuçları etkilenmedi.")}` };
    case "waf_assist": return { icon: IconShieldLock, color: "green", title: t("Tarayıcı yardımcısı gerekiyor"), detail: t("Hedef ayarında seçildiği için size bildirim gönderildi; yardımcıyı sayfanın üstünden başlatın.") };
    case "waf_detected": return { icon: IconShieldLock, color: "orange", title: t("WAF / bot koruması tespit edildi: {name}", { name: WAF_NAME[p.vendor] ?? p.vendor }),
      detail: t("{b} / {r} istek engellendi; sonuçlar eksik olabilir. Çözüm seçenekleri sayfanın üstünde.", { b: p.blocked, r: p.requests }) };
    case "access_issue": return { icon: IconShieldLock, color: "orange", title: t("Erişim engeli: {k}", { k: p.issue }), detail: p.detail ? String(p.detail) : t("Çözüm seçenekleri sayfanın üstünde.") };
    case "browser_tls": return { icon: IconShieldLock, color: "blue", title: t("HTTP istemcisi: tarayıcı uyumlu TLS ({p})", { p: p.profile }) };
    case "scan_finished": return { icon: IconCheck, color: "green", title: t("Tarama tamamlandı") };
    case "failed": return { icon: IconX, color: "red", title: t("Tarama başarısız"), detail: reasonText(p) };
    default: return { icon: IconAlertTriangle, color: "gray", title: e.code };
  }
}

function since(start: string, at: string) {
  const s = Math.max(0, Math.round((new Date(at).getTime() - new Date(start).getTime()) / 1000));
  return s < 60 ? `+${s} ${t("sn")}` : `+${Math.floor(s / 60)} ${t("dk")} ${s % 60} ${t("sn")}`;
}

export function JobTimeline({ events, log }: { events: JobEvent[]; log?: string }) {
  const warns = events.filter((e) => e.level === "warn" || e.level === "error").length;
  return (
    <Stack>
      {events.length === 0 ? <Text size="sm" c="dimmed">{t("(henüz kayıt yok)")}</Text> : (
        <>
          {warns > 0 && <Group gap={6}><ThemeIcon size="sm" color="orange" variant="light"><IconAlertTriangle size={12} /></ThemeIcon><Text size="sm" c="orange">{t("{n} uyarı — ayrıntılar aşağıda", { n: warns })}</Text></Group>}
          <Timeline bulletSize={28} lineWidth={2} active={events.length}>
            {events.map((e, i) => {
              const r = render(e);
              return (
                <Timeline.Item key={i} bullet={<r.icon size={14} />} color={r.color}
                  title={<Group justify="space-between" wrap="nowrap"><Text size="sm" fw={600}>{r.title}</Text><Text size="xs" c="dimmed" style={{ whiteSpace: "nowrap" }}>{since(events[0].at, e.at)}</Text></Group>}>
                  {r.detail && (typeof r.detail === "string" ? <Text size="xs" c="dimmed" style={{ wordBreak: "break-word" }}>{r.detail}</Text> : <div style={{ marginTop: 4 }}>{r.detail}</div>)}
                </Timeline.Item>
              );
            })}
          </Timeline>
          <Text size="xs" c="dimmed">{fmtDate(events[0].at)} – {fmtDate(events[events.length - 1].at)}</Text>
        </>
      )}
      {log && (
        <Accordion variant="contained">
          <Accordion.Item value="raw">
            <Accordion.Control><Text size="sm">{t("Teknik günlük (uzmanlar için)")}</Text></Accordion.Control>
            <Accordion.Panel><ScrollArea h={320}><Code block>{log}</Code></ScrollArea></Accordion.Panel>
          </Accordion.Item>
        </Accordion>
      )}
    </Stack>
  );
}
