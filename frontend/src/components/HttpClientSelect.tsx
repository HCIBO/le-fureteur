import { Select } from "@mantine/core";
import { t } from "../i18n";

export const HTTP_CLIENTS = () => [
  { value: "", label: t("Otomatik (önerilen)") },
  { value: "off", label: t("Standart (Python requests)") },
  { value: "chrome", label: t("Tarayıcı uyumlu TLS — Chrome") },
  { value: "firefox", label: t("Tarayıcı uyumlu TLS — Firefox") },
  { value: "safari", label: t("Tarayıcı uyumlu TLS — Safari") },
  { value: "edge", label: t("Tarayıcı uyumlu TLS — Edge") },
];
export const httpClientLabel = (v?: string) => HTTP_CLIENTS().find((x) => x.value === (v === "auto" ? "" : v ?? ""))?.label ?? t("Otomatik (önerilen)");

export function HttpClientSelect({ value, onChange, available }: { value: string; onChange: (v: string) => void; available: boolean }) {
  return (
    <Select label={t("HTTP istemcisi")} data={HTTP_CLIENTS().filter((x) => available || x.value === "" || x.value === "off")} value={value === "auto" ? "" : value}
      allowDeselect={false} onChange={(v) => onChange(v ?? "")}
      description={available ? t("Otomatik: tarama WAF engeli görürse kendiliğinden tarayıcı uyumlu TLS'e geçer ve devam eder.") : t("Sunucuda curl_cffi kurulu değil (pip install 'scakit[browser-tls]').")} />
  );
}

export function EgressSelect({ value, onChange, names }: { value: string; onChange: (v: string) => void; names: string[] }) {
  return (
    <Select label={t("Çıkış noktası")} allowDeselect={false} value={value || ""} onChange={(v) => onChange(v ?? "")}
      data={[{ value: "", label: t("Otomatik (doğrudan; engellenirse çıkış noktalarını dene)") }, { value: "direct", label: t("Yalnızca doğrudan") },
        ...names.map((n) => ({ value: n, label: t("Her zaman: {n}", { n }) }))]}
      description={names.length ? t("Coğrafi engel, IP engeli veya bağlantı zaman aşımında Otomatik mod tanımlı çıkış noktalarını sırayla dener.") : t("Tanımlı çıkış noktası yok; yönetici Ayarlar → Çıkış noktaları bölümünden ekleyebilir.")} />
  );
}
export const egressLabel = (v?: string) => !v ? t("Otomatik") : v === "direct" ? t("Yalnızca doğrudan") : v;
