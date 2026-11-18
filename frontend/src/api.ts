import { locale, t } from "./i18n";
export function csrf(): string {
  const m = document.cookie.match(/(?:^|;\s*)scakit_csrf=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : "";
}

export class ApiError extends Error {
  status: number;
  detail: any;
  raw: string;
  constructor(status: number, message: string, detail?: any) {
    super(t(message));
    this.raw = message;
    this.status = status;
    this.detail = detail;
  }
}

export async function api<T = any>(path: string, opts: { method?: string; body?: unknown; form?: FormData } = {}): Promise<T> {
  const method = opts.method ?? (opts.body !== undefined || opts.form ? "POST" : "GET");
  const headers: Record<string, string> = {};
  if (method !== "GET") headers["X-CSRF-Token"] = csrf();
  let body: BodyInit | undefined;
  if (opts.form) body = opts.form;
  else if (opts.body !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(opts.body);
  }
  const r = await fetch(`/api${path}`, { method, headers, body, credentials: "same-origin" });
  if (!r.ok) {
    let msg = r.statusText;
    let detail: any;
    try {
      const j = await r.json();
      if (j.detail?.code === "maintenance") {
        window.dispatchEvent(new CustomEvent("lf-maintenance", { detail: j.detail.message ?? "" }));
        msg = "Bakım modu: sistem şu anda yalnızca yöneticilere açık";
      } else if (j.detail?.message) { msg = j.detail.message; detail = j.detail; }
      else msg = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail);
    } catch {  }
    if (r.status === 401 && !path.startsWith("/auth/")) window.location.href = "/login";
    throw new ApiError(r.status, msg, detail);
  }
  return r.json();
}

export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"] as const;
export const SEV_LABEL: Record<string, string> = {
  CRITICAL: t("Kritik"), HIGH: t("Yüksek"), MEDIUM: t("Orta"), LOW: t("Düşük"), UNKNOWN: t("Bilinmiyor"),
};
export const SEV_COLOR: Record<string, string> = {
  CRITICAL: "#d03b3b", HIGH: "#ec835a", MEDIUM: "#fab219", LOW: "#8a8983", UNKNOWN: "#b5b4ad",
};
export const STATUS_LABEL: Record<string, string> = {
  open: t("Açık"), in_progress: t("Üzerinde çalışılıyor"), accepted_risk: t("Kabul edilen risk"),
  false_positive: t("Yanlış pozitif"), not_affected: t("Etkilenmiyor"), fixed: t("Düzeltildi"),
};
export const JOB_LABEL: Record<string, string> = {
  queued: t("Kuyrukta"), running: t("Çalışıyor"), done: t("Tamamlandı"), failed: t("Başarısız"), canceled: t("İptal edildi"),
};
export const ROLE_LABEL: Record<string, string> = { admin: t("Yönetici"), analyst: t("Analist"), customer: t("Müşteri") };

export function fmtDate(s?: string | null): string {
  if (!s) return "-";
  return new Date(s).toLocaleString(locale, { dateStyle: "short", timeStyle: "short" });
}

export function fmtDay(s?: string | null): string {
  if (!s) return "-";
  return new Date(s).toLocaleDateString(locale, { dateStyle: "short" });
}

export function fmtPct(v: number, digits = 1): string {
  return new Intl.NumberFormat(locale, { style: "percent", minimumFractionDigits: digits, maximumFractionDigits: digits }).format(v);
}

export function fmtSize(n: number | null | undefined): string {
  if (n == null) return "-";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0, v = n;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${new Intl.NumberFormat(locale, { maximumFractionDigits: i === 0 ? 0 : 1 }).format(v)} ${units[i]}`;
}

export type User = { id: number; email: string; name: string; role: string; organization_id: number | null; organization: string | null; active: boolean; last_login: string | null; lang: string | null; permissions?: string[] };
