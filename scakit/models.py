from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from urllib.parse import quote

CONFIDENCE_ORDER = {"high": 3, "medium": 2, "low": 1}

PURL_TYPES = {
    "npm": "npm", "PyPI": "pypi", "Maven": "maven", "Go": "golang", "NuGet": "nuget",
    "Packagist": "composer", "crates.io": "cargo", "RubyGems": "gem", "Pub": "pub",
    "SwiftURL": "swift", "CocoaPods": "cocoapods", "Debian": "deb", "Ubuntu": "deb",
    "Alpine": "apk", "Red Hat": "rpm", "Rocky Linux": "rpm", "AlmaLinux": "rpm", "generic": "generic",
}


def base_ecosystem(ecosystem: str) -> str:
    return ecosystem.split(":", 1)[0]


def normalize_name(ecosystem: str, name: str) -> str:
    eco = base_ecosystem(ecosystem)
    if eco == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    if eco in ("NuGet", "Packagist", "RubyGems", "Pub", "generic", "CocoaPods"):
        return name.lower()
    return name


def make_purl(ecosystem: str, name: str, version: str | None) -> str:
    eco = base_ecosystem(ecosystem)
    ptype = PURL_TYPES.get(eco, "generic")
    ns = ""
    pname = name
    if eco == "Maven" and ":" in name:
        ns, pname = name.split(":", 1)
    elif eco == "npm" and name.startswith("@") and "/" in name:
        ns, pname = name.split("/", 1)
    elif eco in ("Go", "Packagist", "SwiftURL") and "/" in name:
        ns, pname = name.rsplit("/", 1)
    elif eco == "PyPI":
        pname = normalize_name(eco, name)
    elif eco in OS_PURL_VENDOR:
        ns = OS_PURL_VENDOR[eco][0]
    path = (quote(ns, safe="/@") + "/" if ns else "") + quote(pname, safe="")
    purl = f"pkg:{ptype}/{path}"
    if version:
        purl += "@" + quote(version, safe="")
    if eco in OS_PURL_VENDOR and ":" in ecosystem:
        m = re.search(r"\d+(?:\.\d+)?", ecosystem.split(":", 1)[1])
        if m:
            purl += "?distro=" + quote(f"{OS_PURL_VENDOR[eco][1]}-{m.group()}", safe="")
    return purl


OS_PURL_VENDOR = {"Debian": ("debian", "debian"), "Ubuntu": ("ubuntu", "ubuntu"), "Alpine": ("alpine", "alpine"),
                  "Red Hat": ("redhat", "rhel"), "Rocky Linux": ("rocky", "rocky"), "AlmaLinux": ("almalinux", "almalinux")}


@dataclass
class Evidence:
    method: str
    location: str
    detail: str = ""
    target: str = ""
    line: int | None = None
    snippet: str = ""


@dataclass
class Component:
    ecosystem: str
    name: str
    version: str | None
    confidence: str = "high"
    direct: bool | None = None
    scope: str = "runtime"
    licenses: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    parents: list[str] = field(default_factory=list)
    version_estimated: bool = False
    usage: str | None = None
    registry: str | None = None
    extra: dict = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{base_ecosystem(self.ecosystem)}|{normalize_name(self.ecosystem, self.name)}|{self.version or ''}"

    @property
    def purl(self) -> str:
        return make_purl(self.ecosystem, self.name, self.version)

    def merge(self, other: "Component") -> None:
        if CONFIDENCE_ORDER[other.confidence] > CONFIDENCE_ORDER[self.confidence]:
            self.confidence = other.confidence
            self.version_estimated = other.version_estimated
        if other.usage == "imported" or self.usage is None:
            self.usage = other.usage or self.usage
        self.registry = self.registry or other.registry
        self.extra.update(other.extra)
        if other.direct:
            self.direct = True
        elif self.direct is None:
            self.direct = other.direct
        if self.scope != other.scope:
            self.scope = "runtime" if "runtime" in (self.scope, other.scope) else self.scope
        if ":" in other.ecosystem and ":" not in self.ecosystem:
            self.ecosystem = other.ecosystem
        for lic in other.licenses:
            if lic not in self.licenses:
                self.licenses.append(lic)
        seen = {(e.method, e.location, e.detail) for e in self.evidence}
        for e in other.evidence:
            if (e.method, e.location, e.detail) not in seen:
                self.evidence.append(e)
        for p in other.parents:
            if p not in self.parents:
                self.parents.append(p)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["purl"] = self.purl
        d["key"] = self.key
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Component":
        d = dict(d)
        d.pop("purl", None)
        d.pop("key", None)
        d["evidence"] = [Evidence(**e) for e in d.get("evidence", [])]
        return cls(**d)


@dataclass
class Finding:
    vuln_id: str
    component_key: str
    component_purl: str
    aliases: list[str] = field(default_factory=list)
    summary: str = ""
    severity: str = "UNKNOWN"
    cvss_score: float | None = None
    cvss_vector: str = ""
    fixed_versions: list[str] = field(default_factory=list)
    upgrade_to: str = ""
    references: list[str] = field(default_factory=list)
    epss: float | None = None
    epss_percentile: float | None = None
    kev: bool = False
    kev_ransomware: bool = False
    malicious: bool = False
    confidence: str = "high"
    published: str = ""
    source: str = "OSV"
    reachability: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        return cls(**d)
