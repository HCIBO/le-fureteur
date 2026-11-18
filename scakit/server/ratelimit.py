from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

_lock = threading.Lock()
_hits: dict[str, deque] = defaultdict(deque)


def hit(key: str, limit: int, window: float = 60.0) -> tuple[bool, int]:
    if limit <= 0:
        return True, 0
    now = time.monotonic()
    with _lock:
        q = _hits[key]
        while q and q[0] <= now - window:
            q.popleft()
        if len(q) >= limit:
            return False, max(1, int(q[0] + window - now) + 1)
        q.append(now)
        return True, 0


def reset() -> None:
    with _lock:
        _hits.clear()
