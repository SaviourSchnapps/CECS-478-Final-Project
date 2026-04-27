"""Token-bucket rate limiter.

Used to cap how many alerts a single source IP can produce in a window so a
flood does not drown out the rest of the report. Per-key buckets are lazily
created and refilled by elapsed time.
"""

from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass
class _Bucket:
    tokens: float
    last_refill: float


class TokenBucketLimiter:
    def __init__(self, rate_per_sec: float, burst: float | None = None,
                 clock: callable = time.monotonic) -> None:
        if rate_per_sec <= 0:
            raise ValueError("rate_per_sec must be > 0")
        self._rate = float(rate_per_sec)
        self._capacity = float(burst) if burst is not None else float(rate_per_sec)
        if self._capacity <= 0:
            raise ValueError("burst must be > 0")
        self._clock = clock
        self._buckets: dict[str, _Bucket] = {}

    def allow(self, key: str) -> bool:
        now = self._clock()
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = _Bucket(tokens=self._capacity, last_refill=now)
            self._buckets[key] = bucket

        elapsed = max(0.0, now - bucket.last_refill)
        bucket.tokens = min(self._capacity, bucket.tokens + elapsed * self._rate)
        bucket.last_refill = now

        if bucket.tokens >= 1.0:
            bucket.tokens -= 1.0
            return True
        return False
