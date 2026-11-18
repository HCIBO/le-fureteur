from __future__ import annotations

import math

_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> float | None:
    if not vector.startswith("CVSS:3"):
        return None
    try:
        m = dict(p.split(":", 1) for p in vector.split("/")[1:])
        scope = m["S"]
        c, i, a = (_W["C"][m[k]] for k in ("C", "I", "A"))
        iss = 1 - (1 - c) * (1 - i) * (1 - a)
        if scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        expl = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * _PR[scope][m["PR"]] * _W["UI"][m["UI"]]
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    if scope == "U":
        return _roundup(min(impact + expl, 10))
    return _roundup(min(1.08 * (impact + expl), 10))


def severity_from_score(score: float | None) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"
