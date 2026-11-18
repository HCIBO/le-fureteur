import { ActionIcon, Badge, Box, Group, Text, Tooltip, CopyButton } from "@mantine/core";
import { IconCheck, IconCopy, IconDownload, IconFileCode } from "@tabler/icons-react";
import { ReactNode } from "react";
import { t } from "../i18n";

const C = { comment: "#7d8590", key: "#79c0ff", string: "#a5d6ff", expr: "#ffa657", keyword: "#ff7b72", text: "#e6edf3" };

function highlight(line: string, lang: string): ReactNode[] {
  const out: ReactNode[] = [];
  const commentAt = lang === "groovy" ? line.indexOf("//") : line.search(/(^|\s)#/);
  let code = line, comment = "";
  if (commentAt >= 0 && !(lang === "bash" && line.trimStart().startsWith("#!"))) {
    code = line.slice(0, commentAt);
    comment = line.slice(commentAt);
  }
  const re = /(\$\{\{[^}]*\}\}|\$\([A-Za-z_.]+\)|\$[A-Z_][A-Z0-9_]*)|("[^"]*"|'[^']*')|(^\s*-?\s*[A-Za-z_][\w.-]*(?=:\s|:$))|(\b(?:python3|curl|export|pipeline|stage|steps|withCredentials|sh|uses|run|if)\b)/g;
  let last = 0, m: RegExpExecArray | null, i = 0;
  while ((m = re.exec(code))) {
    if (m.index > last) out.push(code.slice(last, m.index));
    const color = m[1] ? C.expr : m[2] ? C.string : m[3] ? C.key : C.keyword;
    out.push(<span key={i++} style={{ color }}>{m[0]}</span>);
    last = m.index + m[0].length;
  }
  if (last < code.length) out.push(code.slice(last));
  if (comment) out.push(<span key="c" style={{ color: C.comment, fontStyle: "italic" }}>{comment}</span>);
  return out;
}

export function CodeBlock({ code, filename, lang = "yaml", download }: { code: string; filename?: string; lang?: string; download?: string }) {
  function save() {
    const url = URL.createObjectURL(new Blob([code], { type: "text/plain;charset=utf-8" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = download ?? filename?.split("/").pop() ?? "dosya.txt";
    a.click();
    URL.revokeObjectURL(url);
  }
  const lines = code.split("\n");
  return (
    <Box style={{ borderRadius: 10, overflow: "hidden", border: "1px solid #30363d", background: "#0d1117" }}>
      <Group justify="space-between" px="sm" py={6} style={{ background: "#161b22", borderBottom: "1px solid #30363d" }}>
        <Group gap={8}>
          <IconFileCode size={16} color="#7d8590" />
          <Text size="sm" ff="monospace" c="#e6edf3">{filename ?? lang}</Text>
          <Badge size="xs" variant="outline" color="gray">{lang}</Badge>
        </Group>
        <Group gap={4}>
          <CopyButton value={code} timeout={1500}>
            {({ copied, copy }) => (
              <Tooltip label={copied ? t("Kopyalandı") : t("Kopyala")} withArrow>
                <ActionIcon variant="subtle" color={copied ? "teal" : "gray"} onClick={copy} aria-label={t("Kopyala")}>{copied ? <IconCheck size={16} /> : <IconCopy size={16} />}</ActionIcon>
              </Tooltip>
            )}
          </CopyButton>
          {(download || filename) && (
            <Tooltip label={t("İndir")} withArrow><ActionIcon variant="subtle" color="gray" onClick={save} aria-label={t("İndir")}><IconDownload size={16} /></ActionIcon></Tooltip>
          )}
        </Group>
      </Group>
      <Box component="pre" m={0} p="sm" style={{ overflowX: "auto", fontSize: 12.5, lineHeight: 1.6, color: C.text, fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace" }}>
        {lines.map((ln, i) => (
          <div key={i} style={{ display: "flex" }}>
            <span style={{ color: "#484f58", userSelect: "none", minWidth: 28, textAlign: "right", paddingRight: 12 }}>{i + 1}</span>
            <span style={{ whiteSpace: "pre" }}>{highlight(ln, lang)}</span>
          </div>
        ))}
      </Box>
    </Box>
  );
}
