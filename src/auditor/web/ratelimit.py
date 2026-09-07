"""Per-IP rate limiting + a global concurrency cap.

A free public tool must survive one abuser. This is the FIRST guardrail; the provider's hard
monthly spend cap is the financial backstop behind it. The limiter is in-memory, so it holds only
within one instance: pin Cloud Run to a single instance (min=max=1) at deploy (see the plan) so
this state is authoritative.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Callable


class RateLimiter:
    def __init__(self, per_ip: int = 5, window_seconds: float = 600.0, max_concurrent: int = 2) -> None:
        self.per_ip = per_ip
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()
        self._slots = threading.BoundedSemaphore(max_concurrent)

    def check(self, ip: str, now: float | None = None) -> tuple[bool, float]:
        """Record an attempt. Returns (allowed, retry_after_seconds)."""
        now = time.monotonic() if now is None else now
        with self._lock:
            hits = self._hits.setdefault(ip, deque())
            while hits and now - hits[0] > self.window:
                hits.popleft()
            if len(hits) >= self.per_ip:
                return False, round(self.window - (now - hits[0]), 1)
            hits.append(now)
            # Opportunistic prune so idle IPs do not accumulate forever.
            if len(self._hits) > 4096:
                self._prune(now)
            return True, 0.0

    def _prune(self, now: float) -> None:
        for ip in list(self._hits):
            hits = self._hits[ip]
            while hits and now - hits[0] > self.window:
                hits.popleft()
            if not hits:
                del self._hits[ip]

    def acquire_slot(self, timeout: float = 0.0) -> bool:
        return self._slots.acquire(blocking=timeout > 0, timeout=timeout or None) if timeout else self._slots.acquire(blocking=False)

    def release_slot(self) -> None:
        try:
            self._slots.release()
        except ValueError:
            pass


class DailyCap:
    """A global rolling-24h ceiling on real engine runs - the app-side backstop to the provider's
    hard monthly spend cap. Not per-IP: this bounds total scan cost across
    everyone, so no distributed abuse can run the bill up faster than the daily ceiling allows. Cache
    hits are free and must NOT be counted against it - only actual scans consume.
    """

    def __init__(self, max_per_day: int, window_seconds: float = 24 * 3600,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.max_per_day = max_per_day
        self.window = window_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._hits: deque[float] = deque()

    def try_consume(self, now: float | None = None) -> bool:
        """Record one scan if under the daily ceiling. Returns False (do not scan) once at the cap."""
        now = self._clock() if now is None else now
        with self._lock:
            while self._hits and now - self._hits[0] > self.window:
                self._hits.popleft()
            if len(self._hits) >= self.max_per_day:
                return False
            self._hits.append(now)
            return True


class DomainCap:
    """A hard, low, rolling-window ceiling on the deep form test PER REGISTRABLE DOMAIN.
    The deep test fills and submits, so it must not be aimable at one site in
    volume: each registrable domain gets its own small budget, keyed off the Public Suffix List so
    shared hosts (foo.wixsite.com vs bar.wixsite.com) are separate buckets and one tenant cannot
    exhaust another's. An empty key (an IP or localhost target, which has no registrable domain) is
    never grantable - there is nothing to bound it by.
    """

    def __init__(self, max_per_domain: int, window_seconds: float = 24 * 3600,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.max_per_domain = max_per_domain
        self.window = window_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._hits: dict[str, deque[float]] = {}

    def try_consume(self, key: str, now: float | None = None) -> bool:
        """Record one deep test for `key` if under its ceiling. Returns False once at the cap, or
        when `key` is empty (no registrable domain to bound)."""
        if not key:
            return False
        now = self._clock() if now is None else now
        with self._lock:
            hits = self._hits.setdefault(key, deque())
            while hits and now - hits[0] > self.window:
                hits.popleft()
            if len(hits) >= self.max_per_domain:
                return False
            hits.append(now)
            if len(self._hits) > 4096:  # opportunistic prune of drained buckets
                for k in [k for k, v in self._hits.items() if not v]:
                    del self._hits[k]
            return True
