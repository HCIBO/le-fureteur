import en from "./locales/en";
import fr from "./locales/fr";
import de from "./locales/de";

export type Lang = "tr" | "en" | "fr" | "de";
export const LANGS: { value: Lang; label: string }[] = [
  { value: "tr", label: "Türkçe" }, { value: "en", label: "English" },
  { value: "fr", label: "Français" }, { value: "de", label: "Deutsch" },
];
const KEY = "lf_lang";

function detect(): Lang {
  try {
    const s = localStorage.getItem(KEY);
    if (s && LANGS.some((l) => l.value === s)) return s as Lang;
  } catch {  }
  const nav = (navigator.language || "tr").slice(0, 2);
  return (LANGS.some((l) => l.value === nav) ? nav : "tr") as Lang;
}

export const lang: Lang = detect();
export const locale = { tr: "tr-TR", en: "en-GB", fr: "fr-FR", de: "de-DE" }[lang];
const dict: Record<string, string> | null = lang === "tr" ? null : ({ en, fr, de } as Record<string, Record<string, string>>)[lang];
document.documentElement.lang = lang;

export function t(s: string, vars?: Record<string, string | number | null | undefined>): string {
  let out = (dict && dict[s]) || s;
  if (vars) out = out.replace(/\{(\w+)\}/g, (m, k) => (k in vars ? String(vars[k] ?? "") : m));
  return out;
}

export function storeLang(l: Lang) {
  try { localStorage.setItem(KEY, l); } catch {  }
}

export function switchLang(l: Lang, save?: (l: Lang) => Promise<unknown>) {
  storeLang(l);
  Promise.resolve(save?.(l)).catch(() => undefined).finally(() => window.location.reload());
}
