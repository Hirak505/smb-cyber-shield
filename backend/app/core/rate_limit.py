"""Simple in-memory rate limiter keyed by (ip, endpoint_group)."""
from __future__ import annotations

import time
from collections import defaultdict
from threading import Lock


class _Bucket:
    __slots__ = ("count", "window_start")

    def __init__(self) -> None:
        self.count: int = 0
        self.window_start: float = time.monotonic()


class RateLimiter:
    """Fixed-window rate limiter (thread-safe, in-process)."""

    def __init__(self, limit: int, window_seconds: int) -> None:
        self._limit = limit
        self._window = window_seconds
        self._buckets: dict[str, _Bucket] = defaultdict(_Bucket)
        self._lock = Lock()

    def is_allowed(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets[key]
            if now - bucket.window_start >= self._window:
                bucket.count = 0
                bucket.window_start = now
            bucket.count += 1
            return bucket.count <= self._limit

    def reset(self, key: str) -> None:
        with self._lock:
            self._buckets.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._buckets.clear()


# Module-level singletons (re-created per test if needed)
from app.core.config import get_settings as _gs

def _scan_limiter() -> RateLimiter:
    s = _gs()
    return RateLimiter(s.SCAN_RATE_LIMIT, s.SCAN_RATE_WINDOW)


def _auth_limiter() -> RateLimiter:
    s = _gs()
    return RateLimiter(s.AUTH_RATE_LIMIT, s.AUTH_RATE_WINDOW)


scan_limiter: RateLimiter = _scan_limiter()
auth_limiter: RateLimiter = _auth_limiter()
