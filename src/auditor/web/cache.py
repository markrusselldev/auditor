"""A small thread-safe TTL cache for scan results.

The passive per-target limit is a result CACHE, not a lockout: a repeat scan
of the same URL within the window returns the saved report instead of re-running the engine, so a
popular site returns a saved report and never an error, and the instance never pays to rescan it.

In-memory, so it holds only within one instance - which is the deploy posture anyway (Cloud Run
pinned to a single instance so the rate-limiter state is authoritative). The clock is injectable so
tests are deterministic.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Callable


class TTLCache:
    def __init__(
        self, ttl_seconds: float, max_entries: int = 2048,
        clock: Callable[[], float] = time.monotonic, disabled: bool = False,
    ) -> None:
        self.ttl = ttl_seconds
        self.max_entries = max_entries
        self._clock = clock
        self._lock = threading.Lock()
        self._store: OrderedDict[str, tuple[float, object]] = OrderedDict()
        # A disabled cache always misses and never stores: the local testing escape hatch, so a site
        # can be re-scanned instead of served a saved report.
        self.disabled = disabled

    def get(self, key: str):
        """Return the stored value if present and unexpired, else None."""
        if self.disabled:
            return None
        now = self._clock()
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            expires_at, value = entry
            if now >= expires_at:
                del self._store[key]
                return None
            self._store.move_to_end(key)  # keep recently-served entries warm for LRU eviction
            return value

    def put(self, key: str, value: object) -> None:
        if self.disabled:
            return
        now = self._clock()
        with self._lock:
            self._store[key] = (now + self.ttl, value)
            self._store.move_to_end(key)
            while len(self._store) > self.max_entries:
                self._store.popitem(last=False)  # evict the least-recently-used
