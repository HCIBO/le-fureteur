import { Button, Card, Group, Modal, NumberInput, Select, Stack, Switch, Table, Text, TextInput } from "@mantine/core";
import { useState } from "react";
import { IconPencil } from "@tabler/icons-react";
import { api } from "../api";
import { t } from "../i18n";
import { fail, ok } from "./ui";
import { EgressSelect, egressLabel, HttpClientSelect, httpClientLabel } from "./HttpClientSelect";
import { useQuery } from "@tanstack/react-query";

const OSES = ["Debian:12", "Debian:11", "Ubuntu:24.04", "Ubuntu:22.04", "Ubuntu:20.04", "Alpine:3.20", "Alpine:3.19", "RedHat:9", "Rocky:9", "AlmaLinux:9"];
const yes = (v: any) => (v ? t("Evet") : t("Hayır"));

export function TargetOptionsCard({ tg, onSaved }: { tg: any; onSaved: () => void }) {
  const web = tg.kind === "web";
  const o = tg.options ?? {};
  const [edit, setEdit] = useState<any | null>(null);
  const meta = useQuery<any>({ queryKey: ["meta"], queryFn: () => api("/meta") });
  const rows: [string, string][] = web
    ? [[t("İstekler arası bekleme"), o.delay != null ? `${o.delay} sn` : t("Varsayılan")], [t("En fazla sayfa"), o.max_pages != null ? String(o.max_pages) : t("Varsayılan")],
       [t("Bilinen yolları yokla"), yes(o.probe ?? true)], [t("TLS doğrulama"), yes(o.verify_tls ?? true)], ["User-Agent", o.user_agent || t("Varsayılan")], [t("HTTP istemcisi"), httpClientLabel(o.browser_tls)], [t("CDN dosyalarını incele"), yes(o.external_assets ?? true)], [t("Çıkış noktası"), egressLabel(o.egress)], [t("WAF'a takılırsa"), o.waf_assist ? t("Tarayıcı yardımcısıyla tamamla") : t("Yalnızca uyar")]]
    : [[t("İşletim sistemi"), o.os || t("Otomatik")], [t("Geliştirme bağımlılıkları"), yes(o.dev)]];
  async function save() {
    try {
      const opts: any = web
        ? { delay: edit.delay, max_pages: edit.max_pages, probe: edit.probe, verify_tls: edit.verify_tls, waf_assist: edit.waf_assist, ...(edit.user_agent?.trim() ? { user_agent: edit.user_agent.trim() } : {}), ...(edit.browser_tls ? { browser_tls: edit.browser_tls } : {}), external_assets: edit.external_assets, ...(edit.egress ? { egress: edit.egress } : {}) }
        : { ...(o.type ? { type: o.type } : {}), dev: edit.dev, ...(edit.os ? { os: edit.os } : {}) };
      await api(`/targets/${tg.id}`, { method: "PATCH", body: { options: opts } });
      ok(t("Kaydedildi")); setEdit(null); onSaved();
    } catch (e) { fail(e); }
  }
  return (
    <Card withBorder>
      <Group justify="space-between" mb="xs"><Text fw={600}>{t("Tarama seçenekleri")}</Text>
        <Button size="xs" variant="subtle" leftSection={<IconPencil size={14} />} onClick={() => setEdit(web ? { delay: o.delay ?? 1, max_pages: o.max_pages ?? 30, probe: o.probe ?? true, verify_tls: o.verify_tls ?? true, user_agent: o.user_agent ?? "", waf_assist: !!o.waf_assist, browser_tls: o.browser_tls ?? "", external_assets: o.external_assets ?? true, egress: o.egress ?? "" } : { os: o.os ?? "", dev: !!o.dev })}>{t("Düzenle")}</Button></Group>
      <Table verticalSpacing={4}><Table.Tbody>
        {rows.map(([k, v]) => <Table.Tr key={k}><Table.Td c="dimmed" w="55%"><Text size="sm">{k}</Text></Table.Td><Table.Td><Text size="sm" fw={500} truncate>{v}</Text></Table.Td></Table.Tr>)}
      </Table.Tbody></Table>
      <Modal opened={edit !== null} onClose={() => setEdit(null)} title={t("Tarama seçenekleri")}>
        {edit && (
          <Stack>
            {web ? (
              <>
                <Group grow>
                  <NumberInput label={t("İstekler arası bekleme (sn)")} min={0.2} max={10} step={0.5} decimalScale={1} value={edit.delay} onChange={(v) => setEdit({ ...edit, delay: Number(v) })} />
                  <NumberInput label={t("En fazla sayfa")} min={1} max={200} value={edit.max_pages} onChange={(v) => setEdit({ ...edit, max_pages: Number(v) })} />
                </Group>
                <Switch label={t("Bilinen dosya yollarını yokla (sürüm ifşası, lisans dosyaları)")} checked={edit.probe} onChange={(e) => setEdit({ ...edit, probe: e.currentTarget.checked })} />
                <Switch label={t("TLS sertifikasını doğrula")} checked={edit.verify_tls} onChange={(e) => setEdit({ ...edit, verify_tls: e.currentTarget.checked })} />
                <Switch label={t("WAF / bot korumasına takılırsa tarayıcı yardımcısıyla tamamla")} description={t("Tarama engellenirse size bildirim gelir; yardımcıyı tek komutla başlatırsınız.")} checked={edit.waf_assist} onChange={(e) => setEdit({ ...edit, waf_assist: e.currentTarget.checked })} />
                <Switch label={t("Başka sunuculardaki (CDN) betik ve stil dosyalarını da incele")} checked={edit.external_assets} onChange={(e) => setEdit({ ...edit, external_assets: e.currentTarget.checked })} />
                <EgressSelect value={edit.egress} onChange={(v) => setEdit({ ...edit, egress: v })} names={meta.data?.egress ?? []} />
                <HttpClientSelect value={edit.browser_tls} onChange={(v) => setEdit({ ...edit, browser_tls: v })} available={!!meta.data?.browser_tls} />
                <TextInput label="User-Agent" description={t("WAF izin listesi için sistem sahibiyle paylaşılan değer (boş = varsayılan)")} value={edit.user_agent} onChange={(e) => setEdit({ ...edit, user_agent: e.currentTarget.value })} maxLength={300} />
              </>
            ) : (
              <>
                <Select label={t("İşletim sistemi / dağıtım")} clearable searchable data={OSES} value={edit.os || null} onChange={(v) => setEdit({ ...edit, os: v ?? "" })} />
                <Switch label={t("Geliştirme bağımlılıklarını da dahil et (test, derleme araçları)")} checked={edit.dev} onChange={(e) => setEdit({ ...edit, dev: e.currentTarget.checked })} />
              </>
            )}
            <Group justify="flex-end"><Button onClick={save}>{t("Kaydet")}</Button></Group>
          </Stack>
        )}
      </Modal>
    </Card>
  );
}
