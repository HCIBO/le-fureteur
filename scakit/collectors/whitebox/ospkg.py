from __future__ import annotations

import re

from ..common import comp


def os_ecosystem(os_release: str) -> str | None:
    info = {}
    for line in os_release.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            info[k.strip()] = v.strip().strip('"')
    osid, ver = info.get("ID", "").lower(), info.get("VERSION_ID", "")
    if osid == "debian":
        return f"Debian:{ver.split('.')[0]}" if ver else "Debian"
    if osid == "ubuntu":
        lts = ver.endswith(".04") and int(ver.split(".")[0]) % 2 == 0 if ver[:2].isdigit() else False
        return f"Ubuntu:{ver}:LTS" if lts else f"Ubuntu:{ver}"
    if osid == "alpine":
        return "Alpine:v" + ".".join(ver.split(".")[:2]) if ver else "Alpine"
    major = ver.split(".")[0] if ver else ""
    if osid in ("rhel", "centos"):
        return f"Red Hat:{major}" if major else "Red Hat"
    if osid in ("rocky", "almalinux"):
        return ("Rocky Linux" if osid == "rocky" else "AlmaLinux") + (f":{major}" if major else "")
    if osid in ("ol", "fedora", "amzn", "sles", "opensuse-leap", "opensuse-tumbleweed"):
        return {"ol": "Oracle Linux", "fedora": "Fedora", "amzn": "Amazon Linux"}.get(osid, "SUSE") + \
            (f":{major}" if major else "")
    if osid == "wolfi":
        return "Wolfi"
    return None


def parse_dpkg_status(text: str, loc: str, eco: str = "Debian", target: str = ""):
    out, seen = [], set()
    for para in re.split(r"\n\s*\n", text):
        f = {}
        for line in para.splitlines():
            if line and not line.startswith(" ") and ":" in line:
                k, v = line.split(":", 1)
                f[k] = v.strip()
        if "install ok installed" not in f.get("Status", "install ok installed") or not f.get("Package"):
            continue
        ver = f.get("Version")
        src = f.get("Source", f["Package"])
        sm = re.match(r"^(\S+)(?:\s+\(([^)]+)\))?", src)
        src_name = sm.group(1)
        src_ver = sm.group(2) or ver
        if not src_ver or (src_name, src_ver) in seen:
            continue
        seen.add((src_name, src_ver))
        out.append(comp(eco, src_name, src_ver, "pkgdb", loc, detail=f"binary={f['Package']}", target=target))
    return out


def parse_apk_installed(text: str, loc: str, eco: str = "Alpine", target: str = ""):
    out, seen = [], set()
    for para in re.split(r"\n\s*\n", text):
        f = {}
        for line in para.splitlines():
            if len(line) > 2 and line[1] == ":":
                f.setdefault(line[0], line[2:].strip())
        if not f.get("P") or not f.get("V"):
            continue
        name = f.get("o") or f["P"]
        if (name, f["V"]) in seen:
            continue
        seen.add((name, f["V"]))
        lic = f.get("L")
        out.append(comp(eco, name, f["V"], "pkgdb", loc, detail=f"binary={f['P']}", target=target,
                        licenses=[lic] if lic else None))
    return out


def parse_rpm_packages(pkgs: list[dict], loc: str, eco: str, target: str = ""):
    out, seen = [], set()
    by_source = eco.startswith("Rocky Linux")
    for p in pkgs:
        name = (p["source"] or p["name"]) if by_source else p["name"]
        if (name, p["version"]) in seen:
            continue
        seen.add((name, p["version"]))
        out.append(comp(eco, name, p["version"], "pkgdb", loc, detail=f"binary={p['name']}", target=target,
                        licenses=[p["license"]] if p.get("license") and len(p["license"]) < 80 else None))
    return out


def parse_package_list(text: str, loc: str, eco: str, target: str = ""):
    out, seen = [], set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        p = line.split("\t")
        if len(p) == 3 and p[2].endswith(".src.rpm"):
            src = p[2].rsplit("-", 2)[0]
            name = src if eco.startswith("Rocky Linux") else p[0]
            ver = p[1][2:] if p[1].startswith("0:") else p[1]
            if (name, ver) not in seen:
                seen.add((name, ver))
                out.append(comp(eco, name, ver, "command-output", loc, detail=f"binary={p[0]}", target=target))
            continue
        if len(p) >= 4 and p[2]:
            name, ver, detail = p[2], p[3] or p[1], f"binary={p[0]}"
        elif len(p) >= 2:
            name, ver, detail = p[0], p[1], ""
        else:
            m = re.match(r"^(.+)-(\d[^-]*-r\d+)$", line)
            if not m:
                continue
            name, ver, detail = m.group(1), m.group(2), "apk info -v"
        if (name, ver) in seen:
            continue
        seen.add((name, ver))
        out.append(comp(eco, name, ver, "command-output", loc, detail=detail, target=target,
                        confidence="high" if detail.startswith("binary=") or eco.startswith(("Alpine", "Red Hat"))
                        else "medium"))
    return out
