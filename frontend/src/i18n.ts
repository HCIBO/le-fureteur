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
  const nav = (navigator.language || "en").slice(0, 2);
  return (LANGS.some((l) => l.value === nav) ? nav : "en") as Lang;
}

export const lang: Lang = detect();
export const locale = { tr: "tr-TR", en: "en-GB", fr: "fr-FR", de: "de-DE" }[lang];
const dict: Record<string, string> | null = lang === "tr" ? null : ({ en, fr, de } as Record<string, Record<string, string>>)[lang];
document.documentElement.lang = lang;

type Tpl = { re: RegExp; names: string[]; out: string; lit: number };
let tpls: Tpl[] | null = null;
const seen = new Map<string, string>();

function templates(): Tpl[] {
  if (!tpls) {
    tpls = Object.entries(dict ?? {}).filter(([k]) => /\{\w+\}/.test(k)).map(([k, out]) => {
      const names: string[] = [];
      const src = k.split(/(\{\w+\})/).map((p) => {
        const m = /^\{(\w+)\}$/.exec(p);
        if (m) { names.push(m[1]); return "([\\s\\S]+?)"; }
        return p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      }).join("");
      return { re: new RegExp("^" + src + "$"), names, out, lit: (k.replace(/\{\w+\}/g, "").match(/\p{L}/gu) ?? []).length };
    }).filter((x) => x.lit > 0).sort((a, b) => b.lit - a.lit);
  }
  return tpls;
}

function fromTemplate(s: string, depth: number): string | undefined {
  if (!dict || depth > 1 || s.length > 4000) return undefined;
  if (depth === 0 && seen.has(s)) return seen.get(s) || undefined;
  let hit: string | undefined;
  for (const x of templates()) {
    const m = x.re.exec(s);
    if (!m) continue;
    const vals: Record<string, string> = {};
    x.names.forEach((n, i) => { vals[n] = dict[m[i + 1]] || fromTemplate(m[i + 1], depth + 1) || m[i + 1]; });
    hit = x.out.replace(/\{(\w+)\}/g, (q, k) => (k in vals ? vals[k] : q));
    break;
  }
  if (depth === 0 && seen.size < 5000) seen.set(s, hit ?? "");
  return hit;
}

export function t(s: string, vars?: Record<string, string | number | null | undefined>): string {
  let out = (dict && dict[s]) || (!vars && typeof s === "string" && fromTemplate(s, 0)) || s;
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
