"""Sliding-window rate limiting matching AWS WAFv2 RateBasedStatement semantics.

Real AWS evaluates "has this key exceeded `limit` requests in the trailing
`evaluation_window_sec` seconds" on every request. We implement the same
sliding-window check but take a clock callable instead of wall time, so a
300s AWS window can be exercised in a fraction of a second during a demo
round while the window math itself stays real.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Callable


class SlidingWindowRateLimiter:
    def __init__(self, clock: Callable[[], float] | None = None):
        # Defaults to wall-clock time so real (non-test) usage is a genuine
        # sliding window; tests inject a fake clock for determinism.
        self._clock = clock or time.time
        self._hits: dict[tuple[str, str], deque[float]] = defaultdict(deque)

    def record_and_check(self, rule_name: str, key: str, limit: int, window_sec: int) -> bool:
        """Record a hit for (rule_name, key) at the current clock time and
        return True if the count within the trailing window now exceeds limit."""
        now = self._clock()
        window = self._hits[(rule_name, key)]
        window.append(now)
        cutoff = now - window_sec
        while window and window[0] < cutoff:
            window.popleft()
        return len(window) > limit

    def current_count(self, rule_name: str, key: str, window_sec: int) -> int:
        now = self._clock()
        window = self._hits[(rule_name, key)]
        cutoff = now - window_sec
        while window and window[0] < cutoff:
            window.popleft()
        return len(window)

    def reset(self) -> None:
        self._hits.clear()
