from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .inventory import Inventory
from .models import Finding


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Engagement:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        if not (self.path / "engagement.json").exists():
            raise FileNotFoundError(f"Engagement bulunamadı: {self.path} (önce `scakit init` çalıştırın)")
        self.meta = json.loads((self.path / "engagement.json").read_text())
        self.inventory = Inventory.load(self.path / "inventory.json")

    @classmethod
    def create(cls, path: str | Path, name: str, client: str = "", lang: str = "tr") -> "Engagement":
        p = Path(path)
        p.mkdir(parents=True, exist_ok=True)
        for sub in ("evidence", "reports"):
            (p / sub).mkdir(exist_ok=True)
        meta = {"name": name, "client": client, "lang": lang, "created": now(), "tool": "scakit"}
        (p / "engagement.json").write_text(json.dumps(meta, indent=1, ensure_ascii=False))
        return cls(p)

    @property
    def evidence_dir(self) -> Path:
        d = self.path / "evidence"
        d.mkdir(exist_ok=True)
        return d

    def record_run(self, kind: str, source: str, target: str, added: int, total: int, **extra):
        self.inventory.runs.append({"time": now(), "kind": kind, "source": source, "target": target,
                                    "new_components": added, "detections": total, **extra})

    def save(self):
        self.inventory.save(self.path / "inventory.json")

    def merge_usage(self, go_calls: dict, stats: dict):
        p = self.path / "usage.json"
        doc = json.loads(p.read_text()) if p.exists() else {"go_calls": {}, "runs": []}
        for path, syms in go_calls.items():
            doc["go_calls"][path] = sorted(set(doc["go_calls"].get(path, [])) | set(syms))
        doc["runs"].append(stats)
        p.write_text(json.dumps(doc, indent=1))

    def go_calls(self) -> dict:
        p = self.path / "usage.json"
        if not p.exists():
            return {}
        return {k: set(v) for k, v in json.loads(p.read_text()).get("go_calls", {}).items()}

    def save_findings(self, findings: list[Finding], notes: dict, db_meta: dict):
        doc = {"generated": now(), "db": db_meta, "notes": notes, "findings": [f.to_dict() for f in findings]}
        (self.path / "findings.json").write_text(json.dumps(doc, indent=1, ensure_ascii=False))

    def suppressions(self) -> list[dict]:
        p = self.path / "suppressions.json"
        return json.loads(p.read_text()) if p.exists() else []

    def add_suppression(self, entry: dict):
        items = self.suppressions()
        items.append(entry)
        (self.path / "suppressions.json").write_text(json.dumps(items, indent=1, ensure_ascii=False))

    def load_findings(self) -> tuple[list[Finding], dict]:
        p = self.path / "findings.json"
        if not p.exists():
            return [], {}
        doc = json.loads(p.read_text())
        return [Finding.from_dict(f) for f in doc["findings"]], doc
