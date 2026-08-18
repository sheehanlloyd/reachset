"""Token bucket and backoff, fully deterministic via injected clock/sleep/RNG."""

import random

import pytest

from reachset.ingest.ratelimit import BackoffPolicy, BucketRegistry, RetryState, TokenBucket


class FakeTime:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def clock(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


async def test_bucket_burst_then_throttle() -> None:
    fake = FakeTime()
    bucket = TokenBucket(2.0, 3.0, clock=fake.clock, sleeper=fake.sleep)
    for _ in range(3):
        assert await bucket.acquire() == 0.0  # capacity burst is free
    waited = await bucket.acquire()
    assert waited == pytest.approx(0.5)  # 1 token / 2 per second
    assert fake.sleeps == [pytest.approx(0.5)]


async def test_bucket_refills_over_time() -> None:
    fake = FakeTime()
    bucket = TokenBucket(1.0, 1.0, clock=fake.clock, sleeper=fake.sleep)
    await bucket.acquire()
    fake.now += 10.0  # long idle refills to capacity, not beyond
    assert await bucket.acquire() == 0.0
    waited = await bucket.acquire()
    assert waited == pytest.approx(1.0)


def test_bucket_rejects_nonpositive_config() -> None:
    with pytest.raises(ValueError):
        TokenBucket(0.0, 1.0)


async def test_registry_is_per_tenant_app() -> None:
    fake = FakeTime()
    registry = BucketRegistry(1.0, 1.0, clock=fake.clock, sleeper=fake.sleep)
    a = registry.bucket("t1", "vault")
    b = registry.bucket("t1", "github")
    c = registry.bucket("t2", "vault")
    assert a is registry.bucket("t1", "vault")
    assert len({id(a), id(b), id(c)}) == 3
    await a.acquire()  # draining t1/vault must not affect t1/github
    assert await b.acquire() == 0.0


def test_backoff_is_exponential_with_jitter() -> None:
    policy = BackoffPolicy(base_seconds=1.0, cap_seconds=60.0, jitter_fraction=0.5)
    rng = random.Random(42)
    delays = [policy.delay_for(attempt, None, rng) for attempt in (1, 2, 3, 4)]
    for i, delay in enumerate(delays):
        exponential = 2**i
        assert exponential <= delay <= exponential * 1.5
    assert delays[3] > delays[0]


def test_backoff_honors_retry_after_as_floor() -> None:
    policy = BackoffPolicy(base_seconds=0.1, cap_seconds=60.0)
    rng = random.Random(0)
    assert policy.delay_for(1, 45.0, rng) == 45.0
    # but a small Retry-After never shrinks the computed backoff
    big = policy.delay_for(5, 0.001, rng)
    assert big >= 0.1 * 2**4


def test_backoff_caps_exponential_term() -> None:
    policy = BackoffPolicy(base_seconds=1.0, cap_seconds=8.0, jitter_fraction=0.0)
    rng = random.Random(0)
    assert policy.delay_for(10, None, rng) == 8.0


def test_retry_state_records_history() -> None:
    state = RetryState(BackoffPolicy(base_seconds=1.0, jitter_fraction=0.0))
    state.next_delay(1, None)
    state.next_delay(2, None)
    assert state.history == [1.0, 2.0]
