from __future__ import annotations

import json

from ..models import Component, Evidence


def comp(eco: str, name: str, version: str | None, method: str, location: str, *, detail: str = "",
         target: str = "", confidence: str = "high", direct=None, scope: str = "runtime",
         licenses=None, parents=None, estimated: bool = False) -> Component:
    if version is not None:
        version = str(version).strip() or None
    return Component(
        ecosystem=eco, name=name.strip(), version=version, confidence=confidence, direct=direct, scope=scope,
        licenses=list(licenses or []), evidence=[Evidence(method, location, detail, target)],
        parents=list(parents or []), version_estimated=estimated,
    )


def load_json(text: str):
    try:
        return json.loads(text)
    except ValueError:
        return None
