from __future__ import annotations

import re
from functools import lru_cache

LANG_INDEX = {"en": 0, "fr": 1, "de": 2}
_PH = re.compile(r"\{(\w+)\}")


@lru_cache(maxsize=1)
def _templates() -> list:
    from .catalog import T
    out = []
    for key, value in T.items():
        names = _PH.findall(key)
        if not names:
            continue
        parts = _PH.split(key)
        rx = "".join(re.escape(p) if i % 2 == 0 else r"([\s\S]+?)" for i, p in enumerate(parts))
        out.append((len(_PH.sub("", key)), re.compile("^" + rx + "$"), names, value))
    out.sort(key=lambda x: -x[0])
    return out


def translate(text: str, lang: str, _depth: int = 0) -> str:
    i = LANG_INDEX.get(lang)
    if i is None or not text or not isinstance(text, str):
        return text
    from .catalog import T
    hit = T.get(text)
    if hit:
        return hit[i] or text
    if _depth > 1 or len(text) > 4000:
        return text
    for _, rx, names, value in _templates():
        m = rx.match(text)
        if m and value[i]:
            vals = {n: translate(g, lang, _depth + 1) for n, g in zip(names, m.groups())}
            return _PH.sub(lambda x: vals.get(x.group(1), x.group(0)), value[i])
    return text
