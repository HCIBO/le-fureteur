from __future__ import annotations

import io
import re
import xml.etree.ElementTree as ET
import zipfile

from ..common import comp
from ...safeio import SafeZipFile, UnsafeInput, xml_fromstring

ECO = "Maven"


def _strip_ns(root):
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
    return root


def parse_pom(text: str, loc: str, target: str = ""):
    try:
        root = _strip_ns(xml_fromstring(text))
    except (ET.ParseError, UnsafeInput):
        return []
    props = {}
    parent = root.find("parent")
    proj_ver = root.findtext("version") or (parent.findtext("version") if parent is not None else None)
    proj_grp = root.findtext("groupId") or (parent.findtext("groupId") if parent is not None else None)
    for k, v in (("project.version", proj_ver), ("version", proj_ver), ("pom.version", proj_ver),
                 ("project.groupId", proj_grp), ("project.parent.version",
                                                 parent.findtext("version") if parent is not None else None)):
        if v:
            props[k] = v.strip()
    pr = root.find("properties")
    if pr is not None:
        for el in pr:
            if isinstance(el.tag, str) and el.text:
                props[el.tag] = el.text.strip()

    def resolve(v):
        if v is None:
            return None
        for _ in range(5):
            nv = re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), v)
            if nv == v:
                break
            v = nv
        return None if "${" in v else v.strip()

    out = []
    managed = root.find("dependencyManagement")
    for sect, is_managed in ((root.find("dependencies"), False),
                             (managed.find("dependencies") if managed is not None else None, True)):
        if sect is None:
            continue
        for d in sect.findall("dependency"):
            g, a = resolve(d.findtext("groupId")), resolve(d.findtext("artifactId"))
            if not g or not a:
                continue
            if (d.findtext("scope") or "") == "import":
                continue
            raw_ver = d.findtext("version")
            ver = resolve(raw_ver)
            if ver and re.search(r"[\[\](),]", ver):
                ver = None
            scope = (d.findtext("scope") or "compile").strip()
            out.append(comp(ECO, f"{g}:{a}", ver, "manifest", loc,
                            detail=("dependencyManagement " if is_managed else "") + f"scope={scope}",
                            target=target, direct=not is_managed,
                            scope="dev" if scope == "test" else "runtime",
                            confidence="medium" if ver else "low"))
    return out


_MVN_LINE = re.compile(
    r"^(?P<prefix>(?:\[\w+\]\s)?(?P<tree>[| +\\-]*))(?P<coord>[\w.\-]+:[\w.\-]+:[\w.\-]+(?::[\w.\-]+)*)"
    r"(?P<rest>.*)$")


def parse_maven_tree(text: str, loc: str, target: str = ""):
    out = []
    stack: list[tuple[int, str]] = []
    for line in text.splitlines():
        line = line.rstrip()
        m = _MVN_LINE.match(line)
        if not m:
            continue
        tree = m.group("tree")
        parts = m.group("coord").split(":")
        if not tree.strip():
            stack = []
            continue
        if len(parts) < 4:
            continue
        g, a = parts[0], parts[1]
        if len(parts) >= 6:
            ver, scope = parts[4], parts[5]
        elif len(parts) == 5:
            ver, scope = parts[3], parts[4]
        else:
            ver, scope = parts[3], "compile"
        depth = len(tree) // 3
        while stack and stack[-1][0] >= depth:
            stack.pop()
        parent = stack[-1][1] if stack else ""
        stack.append((depth, f"{g}:{a}@{ver}"))
        if "omitted for" in m.group("rest"):
            continue
        out.append(comp(ECO, f"{g}:{a}", ver, "command-output", loc, detail=f"mvn dependency:tree scope={scope}",
                        target=target, direct=depth == 1, scope="dev" if scope == "test" else "runtime",
                        parents=[parent] if parent else None))
    return out


def parse_gradle_lockfile(text: str, loc: str, target: str = ""):
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("empty="):
            continue
        coord, _, confs = line.partition("=")
        parts = coord.split(":")
        if len(parts) < 3:
            continue
        confs_l = [c for c in confs.split(",") if c]
        dev = bool(confs_l) and all("test" in c.lower() for c in confs_l)
        out.append(comp(ECO, f"{parts[0]}:{parts[1]}", parts[2], "lockfile", loc, target=target,
                        scope="dev" if dev else "runtime"))
    return out


_GRADLE_DEP = re.compile(r"^(?P<indent>[| ]*)[+\\]--- (?P<body>.+)$")
_GRADLE_CONF = re.compile(r"^([A-Za-z][\w]*)(?: - .*)?$")


def parse_gradle_deps(text: str, loc: str, target: str = ""):
    out = []
    conf = ""
    stack: list[tuple[int, str]] = []
    for line in text.splitlines():
        line = line.rstrip()
        cm = _GRADLE_CONF.match(line)
        if cm and not line.startswith(("+", "\\", "|", " ")):
            conf = cm.group(1)
            stack = []
            continue
        m = _GRADLE_DEP.match(line)
        if not m:
            continue
        body = m.group("body")
        if body.startswith("project ") or body.endswith(("(n)", "(c)")):
            continue
        body = re.sub(r"\s+\((\*|c|n|\+)\)$", "", body)
        body = re.sub(r"\{(?:strictly|require|prefer) ([^}]+)\}", r"\1", body)
        bm = re.match(r"^([^:\s]+):([^:\s]+)(?::([^\s]+))?(?:\s*->\s*([^\s]+))?", body)
        if not bm:
            continue
        g, a, req, resolved = bm.groups()
        ver = resolved or req
        if not ver or "{" in ver or "+" in ver:
            continue
        depth = len(m.group("indent")) // 5
        while stack and stack[-1][0] >= depth:
            stack.pop()
        parent = stack[-1][1] if stack else ""
        stack.append((depth, f"{g}:{a}@{ver}"))
        dev = "test" in conf.lower()
        out.append(comp(ECO, f"{g}:{a}", ver, "command-output", loc, detail=f"gradle {conf}", target=target,
                        direct=depth == 0, scope="dev" if dev else "runtime", parents=[parent] if parent else None))
    return out


def looks_like_gradle_deps(text: str) -> bool:
    return bool(re.search(r"^[+\\]--- [\w.\-]+:[\w.\-]+", text[:200000], re.M)) and \
        ("Classpath" in text or "compile" in text.lower() or "runtime" in text.lower())


def looks_like_maven_tree(text: str) -> bool:
    return bool(re.search(r"^(?:\[INFO\] )?[+\\|][- ] ?[\w.\-]+:[\w.\-]+:(?:jar|war|pom|aar|bundle)", text[:200000],
                          re.M))


_JAR_NAME = re.compile(r"^(?P<a>[A-Za-z][\w.\-]*?)-(?P<v>\d[\w.\-]*?)(?:-(?:sources|javadoc|tests|shaded|all))?\.jar$")


def _manifest_attrs(data: bytes) -> dict:
    attrs, last = {}, None
    for line in data.decode("utf-8", "replace").splitlines():
        if line.startswith(" ") and last:
            attrs[last] += line[1:]
        elif ":" in line:
            k, v = line.split(":", 1)
            last = k.strip()
            attrs[last] = v.strip()
    return attrs


def scan_archive(data: bytes, loc: str, target: str = "", _depth: int = 0, parent: str = ""):
    out = []
    try:
        zf = SafeZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, UnsafeInput):
        return out
    names = zf.namelist()
    found_pom = False
    for n in names:
        if n.startswith("META-INF/maven/") and n.endswith("/pom.properties"):
            props = {}
            for line in zf.read(n).decode("utf-8", "replace").splitlines():
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    props[k.strip()] = v.strip()
            if props.get("groupId") and props.get("artifactId") and props.get("version"):
                found_pom = True
                lics = []
                pom_name = n[: -len("pom.properties")] + "pom.xml"
                if pom_name in names:
                    lics = re.findall(r"<license>\s*<name>([^<]{1,120})</name>", zf.read(pom_name).decode("utf-8", "replace"))
                out.append(comp(ECO, f"{props['groupId']}:{props['artifactId']}", props["version"], "jar-meta",
                                f"{loc}!/{n}", target=target, parents=[parent] if parent else None,
                                licenses=[x.strip() for x in lics[:3]]))
    if not found_pom and (_depth > 0 or loc.lower().endswith(".jar")):
        attrs = _manifest_attrs(zf.read("META-INF/MANIFEST.MF")) if "META-INF/MANIFEST.MF" in names else {}
        fname = loc.rsplit("/", 1)[-1]
        fm = _JAR_NAME.match(fname)
        ver = attrs.get("Implementation-Version") or attrs.get("Bundle-Version") or (fm.group("v") if fm else None)
        art = fm.group("a") if fm else None
        if art and ver:
            out.append(comp(ECO, art, ver, "jar-meta", loc, detail="MANIFEST/dosya adı (groupId yok)",
                            target=target, confidence="medium", estimated=not attrs))
    if _depth < 4:
        for n in names:
            if n.lower().endswith((".jar", ".war", ".ear", ".aar")) and not n.endswith("/"):
                try:
                    inner = zf.read(n)
                except (zipfile.BadZipFile, RuntimeError, OSError):
                    continue
                out += scan_archive(inner, f"{loc}!/{n}", target, _depth + 1, parent=n.rsplit("/", 1)[-1])
    return out
