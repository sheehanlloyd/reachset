"""RedisTokenBucket / RedisBucketRegistry: correctness proved against a real
Redis, under real concurrency, with real wall-clock time. That combination is
the point of this file — the bug being fixed (BucketRegistry gives each
process its own independent allowance, so N processes draw N times the
configured rate) only shows up when multiple *independent* registries race
against the same shared state, which a single-process unit test with a fake
clock can't exercise honestly.
"""

import asyncio
import time
import uuid

import pytest
from redis.asyncio import Redis

from reachset.ingest.ratelimit import RedisBucketRegistry, RedisTokenBucket

pytestmark = pytest.mark.integration


async def test_single_bucket_bursts_then_throttles(redis_client: Redis) -> None:
    key = f"test:{uuid.uuid4().hex}"
    bucket = RedisTokenBucket(redis_client, key, rate_per_second=10.0, capacity=3.0)
    for _ in range(3):
        assert await bucket.acquire() == 0.0  # capacity burst is free
    started = time.monotonic()
    await bucket.acquire()
    elapsed = time.monotonic() - started
    assert elapsed == pytest.approx(0.1, abs=0.05)  # 1 token / 10 per second


async def test_bucket_rejects_nonpositive_config(redis_client: Redis) -> None:
    with pytest.raises(ValueError):
        RedisTokenBucket(redis_client, "k", 0.0, 1.0)


async def test_registry_is_per_tenant_app_and_shares_state_by_key(redis_client: Redis) -> None:
    prefix = f"test:{uuid.uuid4().hex}"
    registry = RedisBucketRegistry(redis_client, 10.0, 3.0, key_prefix=prefix)
    a = registry.bucket("t1", "vault")
    b = registry.bucket("t1", "github")
    assert a is registry.bucket("t1", "vault")
    for _ in range(3):
        await a.acquire()
    # a is drained; a fresh registry instance pointed at the same key sees the
    # same drained state, because the state lives in Redis, not in `registry`.
    other_registry = RedisBucketRegistry(redis_client, 10.0, 3.0, key_prefix=prefix)
    started = time.monotonic()
    await other_registry.bucket("t1", "vault").acquire()
    assert time.monotonic() - started == pytest.approx(0.1, abs=0.05)
    # t1/github was never touched, so it still has its full burst capacity.
    assert await b.acquire() == 0.0


async def test_concurrent_independent_registries_share_one_real_rate(redis_client: Redis) -> None:
    """The actual bug this feature fixes: N worker *processes* each holding
    their own BucketRegistry instance would each get their own full
    allowance, so N of them racing the same tenant/app draw N times the
    intended rate against the upstream API. Here N independent
    RedisBucketRegistry instances (standing in for N worker processes) race
    the same Redis-backed bucket; the aggregate acquisition rate across all
    of them must land near the single configured rate, not N times it.
    """
    key_prefix = f"test:{uuid.uuid4().hex}"
    rate = 40.0
    capacity = 8.0
    n_workers = 4
    acquisitions_per_worker = 20  # well past the capacity burst

    async def worker() -> list[float]:
        # A fresh registry per worker: no shared Python object, no shared
        # in-process state — the only thing tying them together is Redis.
        registry = RedisBucketRegistry(redis_client, rate, capacity, key_prefix=key_prefix)
        bucket = registry.bucket("acme", "vault")
        timestamps = []
        for _ in range(acquisitions_per_worker):
            await bucket.acquire()
            timestamps.append(time.monotonic())
        return timestamps

    started = time.monotonic()
    results = await asyncio.gather(*(worker() for _ in range(n_workers)))
    total_acquired = n_workers * acquisitions_per_worker
    total_elapsed = max(ts[-1] for ts in results) - started

    # Steady-state: after the shared capacity burst is drained, the aggregate
    # rate across every worker combined must track the *single* configured
    # rate. If each worker instead drew its own independent allowance (the
    # bug), total_elapsed would be ~1/n_workers of this floor.
    tokens_from_backoff = total_acquired - capacity
    expected_min_seconds = tokens_from_backoff / rate
    assert total_elapsed >= expected_min_seconds * 0.7  # generous slack for CI jitter
    observed_rate = total_acquired / total_elapsed
    assert observed_rate < rate * 1.5, (
        f"observed aggregate rate {observed_rate:.1f}/s exceeds the configured "
        f"rate {rate}/s by more than CI jitter can explain - looks like the "
        f"workers were not actually sharing one bucket"
    )
