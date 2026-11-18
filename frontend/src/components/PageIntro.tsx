import { ActionIcon, Anchor, Card, Group, List, Text, ThemeIcon, UnstyledButton } from "@mantine/core";
import { IconBulb, IconInfoCircle, IconX } from "@tabler/icons-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { t } from "../i18n";

function readClosed(id: string): boolean {
  try { return localStorage.getItem(`lf_intro_${id}`) === "1"; } catch { return false; }
}
function writeClosed(id: string, v: boolean) {
  try { if (v) localStorage.setItem(`lf_intro_${id}`, "1"); else localStorage.removeItem(`lf_intro_${id}`); } catch {  }
}

export function PageIntro({ id, text, points, guide }: { id: string; text: string; points?: string[]; guide?: string }) {
  const [closed, setClosed] = useState(() => readClosed(id));
  if (closed) {
    return (
      <UnstyledButton mb="md" onClick={() => { writeClosed(id, false); setClosed(false); }}>
        <Group gap={4}><IconInfoCircle size={14} color="var(--mantine-color-dimmed)" /><Text size="xs" c="dimmed">{t("Bu sayfa hakkında")}</Text></Group>
      </UnstyledButton>
    );
  }
  return (
    <Card withBorder mb="lg" padding="md" style={{ background: "var(--mantine-color-indigo-light)", borderColor: "var(--mantine-color-indigo-light-hover)" }}>
      <Group align="flex-start" wrap="nowrap" gap="md">
        <ThemeIcon variant="light" color="indigo" size={36} radius="md"><IconBulb size={20} /></ThemeIcon>
        <div style={{ flex: 1 }}>
          <Text size="sm">{text}</Text>
          {points && points.length > 0 && <List size="sm" mt={6} spacing={2}>{points.map((p, i) => <List.Item key={i}>{p}</List.Item>)}</List>}
          {guide && <Anchor component={Link} to={`/guide#${guide}`} size="sm" mt={6} display="inline-block">{t("Rehberde ayrıntılı oku →")}</Anchor>}
        </div>
        <ActionIcon variant="subtle" color="gray" onClick={() => { writeClosed(id, true); setClosed(true); }} aria-label={t("Kapat")}><IconX size={16} /></ActionIcon>
      </Group>
    </Card>
  );
}
