"""Per-IP rate limiting for the API (token bucket).

Opt-in: disabled unless `RATE_LIMIT_RPM` > 0 (see `config.py`). StegSuite runs a
single uvicorn worker, so an in-process bucket is the correct scope — with more
workers each would grant its own budget (see tasks/remaining.md B7).
"""
from __future__ import annotations

import threading
import time
from typing import Callable

# registry key -> TokenBucket, with the monotonic time it was last used
_BUCKETS: dict[str, tuple["TokenBucket", float]] = {}

# seam for tests: monotonic seconds
_clock: Callable[[], float] = time.monotonic

# a bucket untouched for this long is dropped, so memory can't grow without bound
DEFAULT_TTL = 900.0


class TokenBucket:
    """Classic token bucket: `capacity` tokens, refilled at `refill_per_sec`."""

    def __init__(self, capacity: float, refill_per_sec: float,
                 clock: Callable[[], float] | None = None) -> None:
        self.capacity = float(capacity)
        self.refill_per_sec = float(refill_per_sec)
        self._clock = clock or time.monotonic
        self._tokens = float(capacity)
        self._at = self._clock()
        self._lock = threading.Lock()

    def take(self) -> bool:
        """Consume one token; False when the caller is over budget."""
        with self._lock:
            now = self._clock()
            if self.refill_per_sec > 0:
                self._tokens = min(self.capacity, self._tokens + (now - self._at) * self.refill_per_sec)
            self._at = now
            if self._tokens >= 1:
                self._tokens -= 1
                return True
            return False


def get_bucket(key: str, *, capacity: float, refill_per_sec: float,
               ttl: float = DEFAULT_TTL) -> TokenBucket:
    """Fetch (or create) the bucket for `key`, evicting buckets idle past `ttl`."""
    now = _clock()
    with _lock:
        hit = _BUCKETS.get(key)
        if hit is not None:
            _BUCKETS[key] = (hit[0], now)   # refresh, so active callers aren't evicted
            return hit[0]
        for k in [k for k, (_, seen) in _BUCKETS.items() if now - seen > ttl]:
            del _BUCKETS[k]
        bucket = TokenBucket(capacity, refill_per_sec, clock=_clock)
        _BUCKETS[key] = (bucket, now)
        return bucket


_lock = threading.Lock()


def client_ip(request) -> str:
    """Best-effort peer identity.

    `X-Forwarded-For` wins when present (the app is published behind a reverse
    proxy in some setups) and only its first hop is trusted.
    """
    forwarded = (request.headers.get("x-forwarded-for") or "").strip()
    if forwarded:
        return forwarded.split(",")[0].strip()
    host = getattr(getattr(request, "client", None), "host", "") or "unknown"
    return host.split(":")[0]


def reset() -> None:
    """Drop all state (tests)."""
    with _lock:
        _BUCKETS.clear()