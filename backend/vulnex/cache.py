"""A tiny in-memory cache for read-heavy API responses.

Dashboard numbers and the CVE list only change when a scan finishes or someone
saves a triage edit. Recomputing them for every visitor costs several database
round trips each, so answers are kept for a short time and thrown away the moment
the data is known to have changed (any write request, or the end of a scan). The
short expiry is a safety net for changes made by another process, such as the
scheduled GitHub Actions scan writing straight to the database.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable

TTL_SECONDS = 60.0

_lock = threading.Lock()
_store: dict[Any, tuple[float, Any]] = {}


def cached(key: Any, compute: Callable[[], Any]) -> Any:
    """Return the fresh cached value for ``key``, computing it on a miss."""
    now = time.monotonic()
    with _lock:
        hit = _store.get(key)
        if hit and now - hit[0] < TTL_SECONDS:
            return hit[1]
    value = compute()
    with _lock:
        _store[key] = (time.monotonic(), value)
    return value


def clear() -> None:
    with _lock:
        _store.clear()
