from __future__ import annotations

import re
from functools import cmp_to_key

from packaging.version import InvalidVersion, Version

from .models import base_ecosystem


def _sign(x: int) -> int:
    return (x > 0) - (x < 0)


def _semver_parse(v: str):
    v = v.strip().lstrip("vV=")
    v = v.split("+", 1)[0]
    main, _, pre = v.partition("-")
    nums = []
    for p in main.split("."):
        m = re.match(r"\d+", p)
        nums.append(int(m.group()) if m else 0)
    while len(nums) < 3:
        nums.append(0)
    return nums, pre


def _pre_cmp(a: str, b: str, ci: bool = False) -> int:
    if a == b:
        return 0
    if not a:
        return 1
    if not b:
        return -1
    if ci:
        a, b = a.lower(), b.lower()
    pa, pb = a.split("."), b.split(".")
    for x, y in zip(pa, pb):
        if x == y:
            continue
        xd, yd = x.isdigit(), y.isdigit()
        if xd and yd:
            return _sign(int(x) - int(y))
        if xd != yd:
            return -1 if xd else 1
        return -1 if x < y else 1
    return _sign(len(pa) - len(pb))


def semver_cmp(a: str, b: str) -> int:
    na, pa = _semver_parse(a)
    nb, pb = _semver_parse(b)
    n = max(len(na), len(nb))
    na += [0] * (n - len(na))
    nb += [0] * (n - len(nb))
    if na != nb:
        return -1 if na < nb else 1
    return _pre_cmp(pa, pb)


def nuget_cmp(a: str, b: str) -> int:
    na, pa = _semver_parse(a)
    nb, pb = _semver_parse(b)
    n = max(len(na), len(nb), 4)
    na += [0] * (n - len(na))
    nb += [0] * (n - len(nb))
    if na != nb:
        return -1 if na < nb else 1
    return _pre_cmp(pa, pb, ci=True)


def pep440_cmp(a: str, b: str) -> int:
    try:
        va, vb = Version(a), Version(b)
    except InvalidVersion:
        return generic_cmp(a, b)
    return (va > vb) - (va < vb)


_MVN_QUALIFIERS = ["alpha", "beta", "milestone", "rc", "snapshot", "", "sp"]
_MVN_ALIASES = {"ga": "", "final": "", "release": "", "cr": "rc"}


class _Q(str):
    pass


def _mvn_str_item(s: str, followed_by_digit: bool) -> _Q:
    if followed_by_digit and len(s) == 1:
        s = {"a": "alpha", "b": "beta", "m": "milestone"}.get(s, s)
    return _Q(_MVN_ALIASES.get(s, s))


def _mvn_qual_key(q: str) -> str:
    return str(_MVN_QUALIFIERS.index(q)) if q in _MVN_QUALIFIERS else f"{len(_MVN_QUALIFIERS)}-{q}"


def _mvn_is_null(item) -> bool:
    if isinstance(item, list):
        return len(item) == 0
    if isinstance(item, _Q):
        return _mvn_qual_key(item) == _mvn_qual_key("")
    return item == 0


def _mvn_normalize(lst: list) -> None:
    for item in lst:
        if isinstance(item, list):
            _mvn_normalize(item)
    while lst:
        last = lst[-1]
        if _mvn_is_null(last):
            lst.pop()
        elif not isinstance(last, list):
            break
        else:
            break


def _mvn_parse(v: str) -> list:
    v = v.lower()
    root: list = []
    cur = root
    is_digit = False
    start = 0

    def make(s: str, digit: bool, followed: bool = False):
        return int(s) if digit else _mvn_str_item(s, followed)

    for i, ch in enumerate(v):
        if ch == ".":
            cur.append(0 if i == start else make(v[start:i], is_digit))
            start = i + 1
        elif ch == "-":
            cur.append(0 if i == start else make(v[start:i], is_digit))
            start = i + 1
            new: list = []
            cur.append(new)
            cur = new
        elif ch.isdigit():
            if not is_digit and i > start:
                cur.append(make(v[start:i], False, followed=True))
                start = i
                new = []
                cur.append(new)
                cur = new
            is_digit = True
        else:
            if is_digit and i > start:
                cur.append(int(v[start:i]))
                start = i
                new = []
                cur.append(new)
                cur = new
            is_digit = False
    if len(v) > start:
        cur.append(make(v[start:], is_digit))
    _mvn_normalize(root)
    return root


def _mvn_item_cmp(a, b) -> int:
    if a is None and b is None:
        return 0
    if a is None:
        return -_mvn_item_cmp(b, None)
    if isinstance(a, list):
        if b is None:
            for x in a:
                r = _mvn_item_cmp(x, None)
                if r:
                    return r
            return 0
        if isinstance(b, list):
            for i in range(max(len(a), len(b))):
                x = a[i] if i < len(a) else None
                y = b[i] if i < len(b) else None
                r = _mvn_item_cmp(x, y)
                if r:
                    return r
            return 0
        return -1 if isinstance(b, int) else 1
    if isinstance(a, _Q):
        if b is None:
            ka, kb = _mvn_qual_key(a), _mvn_qual_key("")
            return (ka > kb) - (ka < kb)
        if isinstance(b, _Q):
            ka, kb = _mvn_qual_key(a), _mvn_qual_key(b)
            return (ka > kb) - (ka < kb)
        return -1
    if b is None:
        return 1 if a > 0 else 0
    if isinstance(b, int) and not isinstance(b, _Q):
        return _sign(a - b)
    return 1


def maven_cmp(a: str, b: str) -> int:
    return _mvn_item_cmp(_mvn_parse(a), _mvn_parse(b))


def gem_cmp(a: str, b: str) -> int:
    def segs(v):
        return [int(s) if s.isdigit() else s for s in re.findall(r"[0-9]+|[a-zA-Z]+", v.strip())]

    sa, sb = segs(a), segs(b)
    for i in range(max(len(sa), len(sb))):
        x = sa[i] if i < len(sa) else 0
        y = sb[i] if i < len(sb) else 0
        if x == y:
            continue
        if isinstance(x, str) and isinstance(y, int):
            return -1
        if isinstance(x, int) and isinstance(y, str):
            return 1
        return -1 if x < y else 1
    return 0


_PHP_SPECIAL = {"dev": 0, "alpha": 1, "a": 1, "beta": 2, "b": 2, "rc": 3, "#": 4, "pl": 5, "p": 5}


def _php_canon(v: str) -> list[str]:
    v = v.strip().lstrip("vV")
    v = re.sub(r"[-_+]", ".", v)
    v = re.sub(r"(?<=\d)(?=[^\d.])|(?<=[^\d.])(?=\d)", ".", v)
    parts = [p for p in v.split(".") if p != ""]
    nums = 0
    for p in parts:
        if p.isdigit():
            nums += 1
        else:
            break
    if nums < 4:
        parts = parts[:nums] + ["0"] * (4 - nums) + parts[nums:]
    return parts


def _php_order(p: str) -> int:
    return 4 if p.isdigit() else _PHP_SPECIAL.get(p.lower(), -6)


def composer_cmp(a: str, b: str) -> int:
    pa, pb = _php_canon(a), _php_canon(b)
    for i in range(max(len(pa), len(pb))):
        x = pa[i] if i < len(pa) else None
        y = pb[i] if i < len(pb) else None
        if x is None:
            return -1 if y.isdigit() else -_sign(_php_order(y) - 4)
        if y is None:
            return 1 if x.isdigit() else _sign(_php_order(x) - 4)
        if x.isdigit() and y.isdigit():
            r = _sign(int(x) - int(y))
        else:
            r = _sign(_php_order(x) - _php_order(y))
        if r:
            return r
    return 0


def _dpkg_order(c: str) -> int:
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if not c:
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _dpkg_verrevcmp(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _dpkg_order(a[i]) if i < len(a) else 0
            bc = _dpkg_order(b[j]) if j < len(b) else 0
            if ac != bc:
                return _sign(ac - bc)
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return _sign(first_diff)
    return 0


def _dpkg_split(v: str):
    v = v.strip()
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    if "-" in v:
        upstream, rev = v.rsplit("-", 1)
    else:
        upstream, rev = v, ""
    return epoch, upstream, rev


def dpkg_cmp(a: str, b: str) -> int:
    ea, ua, ra = _dpkg_split(a)
    eb, ub, rb = _dpkg_split(b)
    if ea != eb:
        return _sign(ea - eb)
    return _dpkg_verrevcmp(ua, ub) or _dpkg_verrevcmp(ra, rb)


def _rpmvercmp(a: str, b: str) -> int:
    if a == b:
        return 0
    i = j = 0
    while i < len(a) or j < len(b):
        while i < len(a) and not a[i].isalnum() and a[i] not in "~^":
            i += 1
        while j < len(b) and not b[j].isalnum() and b[j] not in "~^":
            j += 1
        if (i < len(a) and a[i] == "~") or (j < len(b) and b[j] == "~"):
            if not (i < len(a) and a[i] == "~"):
                return 1
            if not (j < len(b) and b[j] == "~"):
                return -1
            i += 1
            j += 1
            continue
        if (i < len(a) and a[i] == "^") or (j < len(b) and b[j] == "^"):
            if i >= len(a):
                return -1
            if j >= len(b):
                return 1
            if a[i] != "^":
                return 1
            if b[j] != "^":
                return -1
            i += 1
            j += 1
            continue
        if not (i < len(a) and j < len(b)):
            break
        isnum = a[i].isdigit()
        si, sj = i, j
        if isnum:
            while i < len(a) and a[i].isdigit():
                i += 1
            while j < len(b) and b[j].isdigit():
                j += 1
        else:
            while i < len(a) and a[i].isalpha():
                i += 1
            while j < len(b) and b[j].isalpha():
                j += 1
        sa, sb = a[si:i], b[sj:j]
        if not sb:
            return 1 if isnum else -1
        if isnum:
            sa, sb = sa.lstrip("0"), sb.lstrip("0")
            if len(sa) != len(sb):
                return _sign(len(sa) - len(sb))
        if sa != sb:
            return -1 if sa < sb else 1
    if i >= len(a) and j >= len(b):
        return 0
    return -1 if i >= len(a) else 1


def rpm_cmp(a: str, b: str) -> int:
    def split(v):
        epoch = 0
        if ":" in v:
            e, v = v.split(":", 1)
            epoch = int(e) if e.isdigit() else 0
        ver, _, rel = v.partition("-")
        return epoch, ver, rel

    ea, va, ra = split(a.strip())
    eb, vb, rb = split(b.strip())
    if ":" not in a:
        ea = eb
    if ":" not in b:
        eb = ea
    if ea != eb:
        return _sign(ea - eb)
    return _rpmvercmp(va, vb) or (_rpmvercmp(ra, rb) if ra and rb else 0)


_APK_SUFFIX = {"alpha": -4, "beta": -3, "pre": -2, "rc": -1, "": 0, "cvs": 1, "svn": 2, "git": 3, "hg": 4, "p": 5}


def _apk_parse(v: str):
    v = v.strip()
    rev = 0
    m = re.search(r"-r(\d+)$", v)
    if m:
        rev = int(m.group(1))
        v = v[:m.start()]
    main, *suffixes = v.split("_")
    m = re.match(r"^([\d.]+)([a-z]?)$", main)
    if m:
        nums = [int(x) for x in m.group(1).split(".") if x != ""]
        letter = m.group(2)
    else:
        nums, letter = [int(x) for x in re.findall(r"\d+", main)], ""
    suf = []
    for s in suffixes:
        sm = re.match(r"([a-z]+)(\d*)", s)
        if sm:
            suf.append((_APK_SUFFIX.get(sm.group(1), 0), int(sm.group(2) or 0)))
    return nums, letter, suf, rev


def apk_cmp(a: str, b: str) -> int:
    na, la, sa, ra = _apk_parse(a)
    nb, lb, sb, rb = _apk_parse(b)
    for i in range(max(len(na), len(nb))):
        x = na[i] if i < len(na) else -1
        y = nb[i] if i < len(nb) else -1
        if x != y:
            return _sign(x - y)
    if la != lb:
        return -1 if la < lb else 1
    for i in range(max(len(sa), len(sb))):
        x = sa[i] if i < len(sa) else (0, 0)
        y = sb[i] if i < len(sb) else (0, 0)
        if x != y:
            return -1 if x < y else 1
    return _sign(ra - rb)


_PRE_WORDS = {"dev": 0, "alpha": 1, "a": 1, "beta": 2, "b": 2, "pre": 3, "preview": 3, "rc": 4, "cr": 4}


def _cpe_segments(v: str):
    out = []
    for seg in re.split(r"[._\-+]", v.strip().lower().lstrip("v")):
        if not seg:
            continue
        m = re.match(r"^(\d+)([a-z]*)$", seg)
        if m:
            out.append((1, int(m.group(1)), m.group(2)))
            continue
        m = re.match(r"^([a-z]+)(\d*)$", seg)
        if m and m.group(1) in _PRE_WORDS:
            out.append((0, _PRE_WORDS[m.group(1)], int(m.group(2) or 0)))
            continue
        m = re.match(r"^(\d+)([a-z]+)(\d+)$", seg)
        if m:
            word = m.group(2)
            out.append((1, int(m.group(1)), ""))
            out.append((0, _PRE_WORDS[word], int(m.group(3))) if word in _PRE_WORDS else (1, 0, word + m.group(3)))
            continue
        out.append((1, 0, seg))
    return out


def cpe_cmp(a: str, b: str) -> int:
    sa, sb = _cpe_segments(a), _cpe_segments(b)
    pad = (1, 0, "")
    for i in range(max(len(sa), len(sb))):
        x = sa[i] if i < len(sa) else pad
        y = sb[i] if i < len(sb) else pad
        if x != y:
            return -1 if x < y else 1
    return 0


def generic_cmp(a: str, b: str) -> int:
    ta = [int(t) if t.isdigit() else t.lower() for t in re.findall(r"\d+|[a-zA-Z]+", a)]
    tb = [int(t) if t.isdigit() else t.lower() for t in re.findall(r"\d+|[a-zA-Z]+", b)]
    for i in range(max(len(ta), len(tb))):
        x = ta[i] if i < len(ta) else 0
        y = tb[i] if i < len(tb) else 0
        if x == y:
            continue
        if isinstance(x, int) != isinstance(y, int):
            return 1 if isinstance(x, int) else -1
        return -1 if x < y else 1
    return 0


_BY_ECOSYSTEM = {
    "npm": semver_cmp, "Go": semver_cmp, "crates.io": semver_cmp, "Pub": semver_cmp, "SwiftURL": semver_cmp,
    "Hex": semver_cmp, "GitHub Actions": semver_cmp,
    "PyPI": pep440_cmp, "Maven": maven_cmp, "NuGet": nuget_cmp, "RubyGems": gem_cmp, "Packagist": composer_cmp,
    "Debian": dpkg_cmp, "Ubuntu": dpkg_cmp,
    "Alpine": apk_cmp, "Wolfi": apk_cmp, "Chainguard": apk_cmp,
    "Red Hat": rpm_cmp, "Rocky Linux": rpm_cmp, "AlmaLinux": rpm_cmp, "SUSE": rpm_cmp, "openSUSE": rpm_cmp,
}


def comparator(ecosystem: str, range_type: str = "ECOSYSTEM"):
    if range_type == "SEMVER":
        return semver_cmp
    if base_ecosystem(ecosystem) == "generic":
        return cpe_cmp
    return _BY_ECOSYSTEM.get(base_ecosystem(ecosystem), generic_cmp)


def compare(ecosystem: str, a: str, b: str, range_type: str = "ECOSYSTEM") -> int:
    return comparator(ecosystem, range_type)(a, b)


def sort_key(ecosystem: str, range_type: str = "ECOSYSTEM"):
    return cmp_to_key(comparator(ecosystem, range_type))
