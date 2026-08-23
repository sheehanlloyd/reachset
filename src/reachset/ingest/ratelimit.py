"""Owns rate limiting and retry policy for outbound API calls.

Token bucket per (tenant, app); jittered exponential backoff honoring
Retry-After; max 5 attempts and then the page goes to dead letters. Clock,
sleep, and RNG are injectable so every test of this file is deterministic.

Two bucket implementations, one protocol. `BucketRegistry`/`TokenBucket` keep
state in process memory: correct for a single worker, but N worker processes
each get their own independent allowance, so N workers draw N times the
configured rate against whatever they're calling. `RedisBucketRegistry`/
`RedisTokenBucket` keep the same state in Redis instead, refilled and
decremented by one atomic Lua script per acquire, so every process pointed at
the same Redis instance shares one real rate. `StreamSyncer` (ingest/engine.py)
takes either through the `BucketSource` protocol below.
"""

import asyncio
import random
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from redis.asyncio import Redis

Clock = Callable[[], float]
Sleeper = Callable[[float], Awaitable[None]]


class Bucket(Protocol):
    async def acquire(self, tokens: float = 1.0) -> float: ...  # pragma: no cover


class BucketSource(Protocol):
    def bucket(self, tenant_id: str, app_id: str) -> Bucket: ...  # pragma: no cover


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


# Refill + conditional-decrement, atomically. Without the atomicity, two
# workers racing acquire() could both read "3.2 tokens available", both decide
# they can take 1, and the bucket would end up granting more than its own
# capacity implies — exactly the bug a distributed limiter exists to avoid.
# The clock is Redis's own TIME command rather than each worker's wall clock,
# so clock skew between workers can't distort refill timing.
#
# KEYS[1]: the bucket's hash key.
# ARGV: rate_per_second, capacity, tokens_requested, key_ttl_seconds.
# Returns: {acquired (0 or 1), wait_seconds (0 if acquired)}.
_LUA_ACQUIRE = """
local key = KEYS[1]
local rate = tonumber(ARGV[1])
local capacity = tonumber(ARGV[2])
local requested = tonumber(ARGV[3])
local ttl = tonumber(ARGV[4])

local time_parts = redis.call('TIME')
local now = tonumber(time_parts[1]) + tonumber(time_parts[2]) / 1000000

local data = redis.call('HMGET', key, 'tokens', 'updated')
local tokens = tonumber(data[1])
local updated = tonumber(data[2])
if tokens == nil then
    tokens = capacity
    updated = now
end

local elapsed = now - updated
if elapsed < 0 then
    elapsed = 0
end
tokens = math.min(capacity, tokens + elapsed * rate)

local acquired = 0
local wait_seconds = 0
if tokens >= requested then
    tokens = tokens - requested
    acquired = 1
else
    wait_seconds = (requested - tokens) / rate
end

redis.call('HSET', key,
    'tokens', string.format('%.9f', tokens),
    'updated', string.format('%.9f', now))
redis.call('EXPIRE', key, ttl)

return {acquired, tostring(wait_seconds)}
"""


class RedisTokenBucket:
    """Token bucket whose state lives in Redis instead of process memory —
    see the module docstring for why that's the point. Same `acquire()`
    contract as TokenBucket: take `tokens`, sleeping as needed, return the
    time spent waiting.
    """

    def __init__(
        self,
        redis: "Redis",
        key: str,
        rate_per_second: float,
        capacity: float,
        *,
        sleeper: Sleeper = asyncio.sleep,
        ttl_seconds: float | None = None,
    ) -> None:
        if rate_per_second <= 0 or capacity <= 0:
            raise ValueError("rate and capacity must be positive")
        self._key = key
        self._rate = rate_per_second
        self._capacity = capacity
        self._sleeper = sleeper
        # Long enough that a bucket under steady use never expires between
        # refills; short enough that an abandoned tenant/app pair doesn't sit
        # in Redis forever. A full refill from empty takes capacity/rate
        # seconds, so four of those is a comfortable margin.
        self._ttl = (
            ttl_seconds if ttl_seconds is not None else max(60.0, capacity / rate_per_second * 4)
        )
        self._script = redis.register_script(_LUA_ACQUIRE)

    async def acquire(self, tokens: float = 1.0) -> float:
        waited = 0.0
        while True:
            acquired, wait_seconds = await self._script(
                keys=[self._key], args=[self._rate, self._capacity, tokens, self._ttl]
            )
            if int(acquired):
                return waited
            delay = float(wait_seconds)
            waited += delay
            await self._sleeper(delay)


class RedisBucketRegistry:
    """Redis-backed BucketRegistry: same per-(tenant, app) bucket shape, but
    every process pointed at the same Redis instance shares the same bucket
    state, so the configured rate is the real aggregate rate against the
    upstream API regardless of how many workers are running.
    """

    def __init__(
        self,
        redis: "Redis",
        rate_per_second: float = 5.0,
        capacity: float = 10.0,
        *,
        key_prefix: str = "reachset:ratelimit",
        sleeper: Sleeper = asyncio.sleep,
    ) -> None:
        self._redis = redis
        self._rate = rate_per_second
        self._capacity = capacity
        self._key_prefix = key_prefix
        self._sleeper = sleeper
        self._buckets: dict[tuple[str, str], RedisTokenBucket] = {}

    def bucket(self, tenant_id: str, app_id: str) -> RedisTokenBucket:
        key = (tenant_id, app_id)
        if key not in self._buckets:
            self._buckets[key] = RedisTokenBucket(
                self._redis,
                f"{self._key_prefix}:{tenant_id}:{app_id}",
                self._rate,
                self._capacity,
                sleeper=self._sleeper,
            )
        return self._buckets[key]
