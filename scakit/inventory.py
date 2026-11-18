from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .models import Component, base_ecosystem, normalize_name


@dataclass
class Observation:
    kind: str
    target: str
    location: str
    detail: str = ""


@dataclass
class Inventory:
    components: dict[str, Component] = field(default_factory=dict)
    observations: list[Observation] = field(default_factory=list)
    runs: list[dict] = field(default_factory=list)

    def add(self, comps: list[Component]) -> int:
        n = 0
        for c in comps:
            if c.key in self.components:
                self.components[c.key].merge(c)
            else:
                self.components[c.key] = c
                n += 1
        return n

    def observe(self, kind: str, target: str, location: str, detail: str = ""):
        o = Observation(kind, target, location, detail)
        if o not in self.observations:
            self.observations.append(o)

    def finalize(self) -> None:
        by_name: dict[str, list[Component]] = {}
        for c in self.components.values():
            by_name.setdefault(f"{base_ecosystem(c.ecosystem)}|{normalize_name(c.ecosystem, c.name)}", []).append(c)
        for group in by_name.values():
            versioned = [c for c in group if c.version]
            if not versioned:
                continue
            for c in group:
                if c.version:
                    continue
                for v in versioned:
                    if c.direct:
                        v.direct = True
                    v.evidence += [e for e in c.evidence if e not in v.evidence]
                del self.components[c.key]

    def sorted_components(self) -> list[Component]:
        return sorted(self.components.values(), key=lambda c: (base_ecosystem(c.ecosystem), c.name.lower(),
                                                               c.version or ""))

    def to_dict(self) -> dict:
        return {
            "components": [c.to_dict() for c in self.sorted_components()],
            "observations": [o.__dict__ for o in self.observations],
            "runs": self.runs,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Inventory":
        inv = cls()
        for cd in d.get("components", []):
            c = Component.from_dict(cd)
            inv.components[c.key] = c
        inv.observations = [Observation(**o) for o in d.get("observations", [])]
        inv.runs = d.get("runs", [])
        return inv

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=1, ensure_ascii=False))

    @classmethod
    def load(cls, path: str | Path) -> "Inventory":
        p = Path(path)
        return cls.from_dict(json.loads(p.read_text())) if p.exists() else cls()
