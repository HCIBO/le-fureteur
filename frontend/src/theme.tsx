import { ActionIcon, ColorSwatch, createTheme, DEFAULT_THEME, Group, MantineProvider, Popover, SegmentedControl, Stack, Text, Tooltip, useMantineColorScheme, CheckIcon } from "@mantine/core";
import { createContext, ReactNode, useContext, useState } from "react";
import { IconDeviceDesktop, IconMoon, IconPalette, IconSun } from "@tabler/icons-react";
import { t } from "./i18n";

export const ACCENTS: { value: string; label: string }[] = [
  { value: "indigo", label: t("Le Fureteur (çivit)") }, { value: "blue", label: t("Okyanus") }, { value: "teal", label: t("Orman") },
  { value: "violet", label: t("Lavanta") }, { value: "orange", label: t("Gün batımı") }, { value: "pink", label: t("Gül") },
  { value: "gray", label: t("Grafit") },
];
type Prefs = { accent: string; radius: string; density: string };
const KEY = "lf_theme";
const DEFAULTS: Prefs = { accent: "indigo", radius: "md", density: "normal" };

function load(): Prefs {
  try {
    const v = JSON.parse(localStorage.getItem(KEY) ?? "{}");
    return {
      accent: ACCENTS.some((a) => a.value === v.accent) ? v.accent : DEFAULTS.accent,
      radius: ["xs", "md", "xl"].includes(v.radius) ? v.radius : DEFAULTS.radius,
      density: ["compact", "normal"].includes(v.density) ? v.density : DEFAULTS.density,
    };
  } catch { return DEFAULTS; }
}

const Ctx = createContext<{ prefs: Prefs; set: (p: Partial<Prefs>) => void }>({ prefs: DEFAULTS, set: () => undefined });
export const useThemePrefs = () => useContext(Ctx);

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [prefs, setPrefs] = useState<Prefs>(load);
  const set = (p: Partial<Prefs>) => {
    const n = { ...prefs, ...p };
    setPrefs(n);
    try { localStorage.setItem(KEY, JSON.stringify(n)); } catch {  }
  };
  const theme = createTheme({
    primaryColor: prefs.accent, defaultRadius: prefs.radius,
    fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, sans-serif",
    scale: prefs.density === "compact" ? 0.93 : 1,
  });
  return (
    <Ctx.Provider value={{ prefs, set }}>
      <MantineProvider theme={theme} defaultColorScheme="auto">{children}</MantineProvider>
    </Ctx.Provider>
  );
}

export function ThemeSettings() {
  const { colorScheme, setColorScheme } = useMantineColorScheme();
  const { prefs, set } = useThemePrefs();
  return (
    <Stack gap="sm">
      <div>
        <Text size="xs" fw={600} c="dimmed" mb={4}>{t("Görünüm")}</Text>
        <SegmentedControl fullWidth value={colorScheme} onChange={(v) => setColorScheme(v as any)} data={[
          { value: "light", label: <Group gap={4} wrap="nowrap" justify="center"><IconSun size={14} />{t("Açık")}</Group> },
          { value: "dark", label: <Group gap={4} wrap="nowrap" justify="center"><IconMoon size={14} />{t("Koyu")}</Group> },
          { value: "auto", label: <Group gap={4} wrap="nowrap" justify="center"><IconDeviceDesktop size={14} />{t("Sistem")}</Group> },
        ]} />
      </div>
      <div>
        <Text size="xs" fw={600} c="dimmed" mb={6}>{t("Vurgu rengi")}</Text>
        <Group gap={8}>
          {ACCENTS.map((a) => (
            <Tooltip key={a.value} label={a.label}>
              <ColorSwatch component="button" color={DEFAULT_THEME.colors[a.value][6]} size={28} onClick={() => set({ accent: a.value })} style={{ color: "#fff", cursor: "pointer" }} aria-label={a.label}>
                {prefs.accent === a.value && <CheckIcon style={{ width: 12, height: 12 }} />}
              </ColorSwatch>
            </Tooltip>
          ))}
        </Group>
      </div>
      <div>
        <Text size="xs" fw={600} c="dimmed" mb={4}>{t("Köşeler")}</Text>
        <SegmentedControl fullWidth size="xs" value={prefs.radius} onChange={(v) => set({ radius: v })} data={[{ value: "xs", label: t("Keskin") }, { value: "md", label: t("Yumuşak") }, { value: "xl", label: t("Yuvarlak") }]} />
      </div>
      <div>
        <Text size="xs" fw={600} c="dimmed" mb={4}>{t("Yoğunluk")}</Text>
        <SegmentedControl fullWidth size="xs" value={prefs.density} onChange={(v) => set({ density: v })} data={[{ value: "normal", label: t("Rahat") }, { value: "compact", label: t("Sıkı") }]} />
      </div>
      <Text size="xs" c="dimmed">{t("Tema tercihleri bu tarayıcıda saklanır.")}</Text>
    </Stack>
  );
}

export function ThemeButton() {
  return (
    <Popover width={300} position="bottom-end" shadow="md" withArrow>
      <Popover.Target>
        <Tooltip label={t("Tema")}><ActionIcon variant="subtle" size="lg" aria-label={t("Tema")}><IconPalette size={20} /></ActionIcon></Tooltip>
      </Popover.Target>
      <Popover.Dropdown><ThemeSettings /></Popover.Dropdown>
    </Popover>
  );
}
