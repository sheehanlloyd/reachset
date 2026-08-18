"""Owns rate limiting and retry policy for outbound API calls.

Token bucket per (tenant, app); jittered exponential backoff honoring
Retry-After; max 5 attempts and then the page goes to dead letters. Clock,
sleep, and RNG are injectable so every test of this file is deterministic.
"""

import asyncio
import random
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

Clock = Callable[[], float]
Sleeper = Callable[[float], Awaitable[None]]


class TokenBucket:
    """Classic token bucket. acquire() waits until a token is available."""

    def __init__(
        self,
        rate_per_second: float,
        capacity: float,
        *,
        clock: Clock = time.monotonic,
        sleeper: Sleeper = asyncio.sleep,
    ) -> None:
        if rate_per_second <= 0 or capacity <= 0:
            raise ValueError("rate and capacity must be positive")
        self._rate = rate_per_second
        self._capacity = capacity
        self._tokens = capacity
        self._clock = clock
        self._sleeper = sleeper
        self._updated = clock()

    def _refill(self) -> None:
        now = self._clock()
        self._tokens = min(self._capacity, self._tokens + (now - self._updated) * self._rate)
        self._updated = now

    async def acquire(self, tokens: float = 1.0) -> float:
        """Take `tokens`, sleeping as needed. Returns the time spent waiting."""
        waited = 0.0
        while True:
            self._refill()
            if self._tokens >= tokens:
                self._tokens -= tokens
                return waited
            deficit = (tokens - self._tokens) / self._rate
            waited += deficit
            await self._sleeper(deficit)


class BucketRegistry:
    """One bucket per (tenant, app). Defaults are deliberately conservative."""

    def __init__(
        self,
        rate_per_second: float = 5.0,
        capacity: float = 10.0,
        *,
        clock: Clock = time.monotonic,
        sleeper: Sleeper = asyncio.sleep,
    ) -> None:
        self._rate = rate_per_second
        self._capacity = capacity
        self._clock = clock
        self._sleeper = sleeper
        self._buckets: dict[tuple[str, str], TokenBucket] = {}

    def bucket(self, tenant_id: str, app_id: str) -> TokenBucket:
        key = (tenant_id, app_id)
        if key not in self._buckets:
            self._buckets[key] = TokenBucket(
                self._rate, self._capacity, clock=self._clock, sleeper=self._sleeper
            )
        return self._buckets[key]


@dataclass(frozen=True)
class BackoffPolicy:
    """Jittered exponential backoff. Retry-After always wins when larger."""

    base_seconds: float = 0.5
    cap_seconds: float = 30.0
    max_attempts: int = 5
    jitter_fraction: float = 0.25

    def delay_for(self, attempt: int, retry_after: float | None, rng: random.Random) -> float:
        """Delay before retry number `attempt` (1-based). Full jitter on the
        exponential term; a server-provided Retry-After is a floor, not a hint."""
        exponential: float = min(self.cap_seconds, self.base_seconds * (2 ** (attempt - 1)))
        jitter = exponential * self.jitter_fraction * rng.random()
        delay: float = exponential + jitter
        if retry_after is not None:
            delay = max(delay, retry_after)
        return delay


@dataclass
class RetryState:
    """Bookkeeping for one page-fetch's retry loop; tests read `history`."""

    policy: BackoffPolicy
    rng: random.Random = field(default_factory=lambda: random.Random(0))
    history: list[float] = field(default_factory=list)

    def next_delay(self, attempt: int, retry_after: float | None) -> float:
        delay: float = self.policy.delay_for(attempt, retry_after, self.rng)
        self.history.append(delay)
        return delay
