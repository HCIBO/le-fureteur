import { ActionIcon, Badge, Group, Paper, Progress, Stack, Text, ThemeIcon } from "@mantine/core";
import { useRef, useState } from "react";
import { IconCheck, IconCloudUpload, IconFile, IconX } from "@tabler/icons-react";
import { csrf, fmtSize } from "../api";
import { t } from "../i18n";

export type Pending = { file: File; progress: number; status: "waiting" | "uploading" | "done" | "error"; error?: string };

export function Dropzone({ files, onChange, accept, maxFiles, maxMb, disabled }: { files: Pending[]; onChange: (f: Pending[]) => void; accept?: string; maxFiles: number; maxMb: number; disabled?: boolean }) {
  const input = useRef<HTMLInputElement>(null);
  const [over, setOver] = useState(false);
  const [warn, setWarn] = useState("");
  function add(list: FileList | null) {
    if (!list) return;
    const next = [...files];
    const msgs: string[] = [];
    for (const f of Array.from(list)) {
      if (f.size > maxMb * 1024 * 1024) { msgs.push(t("{name}: {mb} MB sınırını aşıyor", { name: f.name, mb: maxMb })); continue; }
      if (next.some((x) => x.file.name === f.name && x.file.size === f.size)) continue;
      if (next.length >= maxFiles) { msgs.push(t("En fazla {n} dosya", { n: maxFiles })); break; }
      next.push({ file: f, progress: 0, status: "waiting" });
    }
    setWarn(msgs.join(" · "));
    onChange(next);
  }
  return (
    <Stack gap="xs">
      <Paper
        withBorder radius="md" p="xl" ta="center"
        onClick={() => !disabled && input.current?.click()}
        onDragOver={(e) => { e.preventDefault(); if (!disabled) setOver(true); }}
        onDragLeave={() => setOver(false)}
        onDrop={(e) => { e.preventDefault(); setOver(false); if (!disabled) add(e.dataTransfer.files); }}
        style={{ cursor: disabled ? "not-allowed" : "pointer", borderStyle: "dashed", borderWidth: 2, transition: "all .15s",
          borderColor: over ? "var(--mantine-primary-color-filled)" : undefined, background: over ? "var(--mantine-primary-color-light)" : "var(--mantine-color-default-hover)" }}>
        <input ref={input} type="file" multiple hidden accept={accept} onChange={(e) => { add(e.currentTarget.files); e.currentTarget.value = ""; }} />
        <ThemeIcon size={56} radius="xl" variant="light" mx="auto"><IconCloudUpload size={30} /></ThemeIcon>
        <Text fw={700} mt="sm">{over ? t("Bırakın") : t("Dosyaları buraya sürükleyin veya tıklayıp seçin")}</Text>
        <Text size="xs" c="dimmed">{t("Dosya başına en fazla {mb} MB · en fazla {n} dosya", { mb: maxMb, n: maxFiles })}</Text>
      </Paper>
      {warn && <Text size="xs" c="orange">{warn}</Text>}
      {files.map((p, i) => (
        <Paper key={i} withBorder p="xs" radius="md">
          <Group wrap="nowrap" gap="sm">
            <ThemeIcon variant="light" color={p.status === "done" ? "green" : p.status === "error" ? "red" : "gray"}>
              {p.status === "done" ? <IconCheck size={16} /> : p.status === "error" ? <IconX size={16} /> : <IconFile size={16} />}
            </ThemeIcon>
            <div style={{ flex: 1, minWidth: 0 }}>
              <Group justify="space-between" wrap="nowrap"><Text size="sm" truncate>{p.file.name}</Text><Text size="xs" c="dimmed" style={{ whiteSpace: "nowrap" }}>{fmtSize(p.file.size)}</Text></Group>
              {p.status === "uploading" && <Progress value={p.progress} size="sm" mt={4} animated />}
              {p.status === "error" && <Text size="xs" c="red">{p.error}</Text>}
            </div>
            {p.status === "waiting" && !disabled && <ActionIcon variant="subtle" color="gray" onClick={() => onChange(files.filter((_, j) => j !== i))} aria-label={t("Kaldır")}><IconX size={14} /></ActionIcon>}
            {p.status === "done" && <Badge color="green" variant="light" size="sm">{t("Yüklendi")}</Badge>}
          </Group>
        </Paper>
      ))}
    </Stack>
  );
}

export function uploadFile(targetId: number, file: File, onProgress: (pct: number) => void): Promise<void> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", `/api/targets/${targetId}/files`);
    xhr.setRequestHeader("X-CSRF-Token", csrf());
    xhr.withCredentials = true;
    xhr.upload.onprogress = (e) => { if (e.lengthComputable) onProgress(Math.round((e.loaded / e.total) * 100)); };
    xhr.onload = () => {
      if (xhr.status < 300) return resolve();
      let msg = xhr.statusText;
      try { const j = JSON.parse(xhr.responseText); msg = typeof j.detail === "string" ? j.detail : msg; } catch {  }
      reject(new Error(t(msg)));
    };
    xhr.onerror = () => reject(new Error(t("Bağlantı hatası")));
    const fd = new FormData();
    fd.append("file", file);
    xhr.send(fd);
  });
}

export async function uploadAll(targetId: number, files: Pending[], set: (f: Pending[]) => void): Promise<number> {
  const cur = [...files];
  let okCount = 0;
  for (let i = 0; i < cur.length; i++) {
    if (cur[i].status === "done") { okCount++; continue; }
    cur[i] = { ...cur[i], status: "uploading", progress: 0 }; set([...cur]);
    try {
      await uploadFile(targetId, cur[i].file, (pct) => { cur[i] = { ...cur[i], progress: pct }; set([...cur]); });
      cur[i] = { ...cur[i], status: "done", progress: 100 }; okCount++;
    } catch (e: any) { cur[i] = { ...cur[i], status: "error", error: e?.message }; }
    set([...cur]);
  }
  return okCount;
}
