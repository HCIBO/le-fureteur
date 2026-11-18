import { Text } from "@mantine/core";
import { useEffect, useState } from "react";
import { locale } from "../i18n";

export function Clock() {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => { const id = window.setInterval(() => setNow(new Date()), 1000); return () => window.clearInterval(id); }, []);
  const loc = locale;
  return (
    <div style={{ position: "absolute", left: "50%", top: "50%", transform: "translate(-50%, -50%)", textAlign: "center", lineHeight: 1.15, pointerEvents: "none" }}>
      <Text fw={700} size="md" style={{ fontVariantNumeric: "tabular-nums" }}>{now.toLocaleTimeString(loc, { hour: "2-digit", minute: "2-digit", second: "2-digit" })}</Text>
      <Text size="xs" c="dimmed">{now.toLocaleDateString(loc, { weekday: "long", day: "numeric", month: "long", year: "numeric" })}</Text>
    </div>
  );
}
