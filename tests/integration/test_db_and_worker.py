"""Session lifecycle and the worker's resilience paths."""

import json

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from reachset.config import Settings
from reachset.db import session_scope
from reachset.ingest import worker as worker_module
from reachset.ingest.worker import QUEUE_KEY, handle_job, run_worker
from reachset.models import Principal, PrincipalKind
from reachset.records import ExtractBatch, PrincipalRecord

pytestmark = pytest.mark.integration


async def test_session_scope_commits_on_success(
    session_factory: async_sessionmaker[AsyncSession], tenant: str
) -> None:
    async with session_scope(session_factory) as session:
        session.add(
            Principal(
                tenant_id=tenant,
                app_id="vault",
                external_id="committed",
                kind=PrincipalKind.SERVICE,
            )
        )

    async with session_factory() as check:
        found = (
            await check.execute(
                text("SELECT COUNT(*) FROM principals WHERE tenant_id = :t"), {"t": tenant}
            )
        ).scalar_one()
    assert found == 1


async def test_session_scope_rolls_back_on_error(
    session_factory: async_sessionmaker[AsyncSession], tenant: str
) -> None:
    """A half-written batch must leave nothing behind — this is what lets the
    sync engine treat a failed page as simply not having happened."""
    with pytest.raises(RuntimeError, match="mid-batch failure"):
        async with session_scope(session_factory) as session:
            session.add(
                Principal(
                    tenant_id=tenant,
                    app_id="vault",
                    external_id="doomed",
                    kind=PrincipalKind.SERVICE,
                )
            )
            await session.flush()
            raise RuntimeError("mid-batch failure")

    async with session_factory() as check:
        found = (
            await check.execute(
                text("SELECT COUNT(*) FROM principals WHERE tenant_id = :t"), {"t": tenant}
            )
        ).scalar_one()
    assert found == 0


async def test_handle_job_succeeds_with_an_injected_syncer(
    session_factory: async_sessionmaker[AsyncSession], tenant: str
) -> None:
    """The worker's syncer is injectable precisely so this path can be tested
    without a live tenant."""

    async def _fake_sync(tenant_id: str, app_id: str) -> ExtractBatch:
        return ExtractBatch(
            principals=[PrincipalRecord(external_id="from-worker", kind=PrincipalKind.SERVICE)]
        )

    ok = await handle_job(session_factory, {"tenant_id": tenant, "app_id": "vault"}, _fake_sync)
    assert ok is True

    async with session_factory() as check:
        found = (
            await check.execute(
                text("SELECT external_id FROM principals WHERE tenant_id = :t"), {"t": tenant}
            )
        ).scalar_one()
    assert found == "from-worker"


async def test_handle_job_dead_letters_a_post_sync_failure_instead_of_raising(
    session_factory: async_sessionmaker[AsyncSession],
    tenant: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failure *after* a successful sync (a bad upsert, a materialize bug)
    must be caught the same way a failed fetch is — dead-lettered, failure
    counter bumped, `handle_job` returns False — not left to propagate out of
    the function and kill the worker loop. Found by reading handle_job: only
    the `syncer(...)` call was wrapped in try/except; upsert_batch/
    watermarks.advance/materialize ran unguarded below it, which contradicts
    this module's own docstring claim that "the loop itself never dies"."""

    async def _fake_sync(tenant_id: str, app_id: str) -> ExtractBatch:
        return ExtractBatch(
            principals=[PrincipalRecord(external_id="from-worker", kind=PrincipalKind.SERVICE)]
        )

    async def _boom(*args: object, **kwargs: object) -> int:
        raise RuntimeError("materialize exploded")

    monkeypatch.setattr(worker_module, "materialize", _boom)

    ok = await handle_job(session_factory, {"tenant_id": tenant, "app_id": "vault"}, _fake_sync)
    assert ok is False

    async with session_factory() as check:
        dead_letters = (
            await check.execute(
                text("SELECT COUNT(*) FROM dead_letters WHERE tenant_id = :t"), {"t": tenant}
            )
        ).scalar_one()
        failures = (
            await check.execute(
                text(
                    "SELECT consecutive_failures FROM sync_watermarks "
                    "WHERE tenant_id = :t AND app_id = 'vault' AND stream = 'full'"
                ),
                {"t": tenant},
            )
        ).scalar_one()
    assert dead_letters == 1
    assert failures == 1


async def test_worker_skips_an_undecodable_job_without_dying(
    migrated_pg_url: str,
    redis_url: str,
    pg_engine: object,
    session_factory: async_sessionmaker[AsyncSession],
    tenant: str,
) -> None:
    """One malformed queue entry must not take the worker down with it."""
    from redis.asyncio import Redis

    settings = Settings(
        database_url=migrated_pg_url,
        redis_url=redis_url,
        vault_addr="http://127.0.0.1:9",
        vault_token="placeholder",
    )
    queue: Redis = Redis.from_url(redis_url)
    try:
        await queue.flushdb()
        # lpush + brpop is FIFO, so the garbage entry is dequeued first and
        # the real job behind it must still run.
        await queue.lpush(QUEUE_KEY, "{not json at all")
        await queue.lpush(QUEUE_KEY, json.dumps({"tenant_id": tenant, "app_id": "vault"}))
        handled = await run_worker(settings, max_jobs=1)
    finally:
        await queue.aclose()

    # The garbage entry is skipped without counting as a handled job, and the
    # real job behind it still runs.
    assert handled == 1
    async with session_factory() as check:
        letters = (
            await check.execute(
                text("SELECT COUNT(*) FROM dead_letters WHERE tenant_id = :t"), {"t": tenant}
            )
        ).scalar_one()
    assert letters == 1


async def test_worker_returns_when_the_queue_stays_empty(
    migrated_pg_url: str, redis_url: str, pg_engine: object
) -> None:
    """brpop times out and the loop keeps going; with max_jobs=0 it exits
    immediately rather than blocking a shutdown."""
    settings = Settings(database_url=migrated_pg_url, redis_url=redis_url)
    assert await run_worker(settings, max_jobs=0) == 0


async def test_an_idle_poll_is_not_a_handled_job(
    migrated_pg_url: str, redis_url: str, pg_engine: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    """brpop returns None when the queue stays quiet. The loop must go round
    again rather than counting the timeout as work or falling out of the loop."""
    from reachset.ingest import worker as worker_module

    polls: list[int] = []

    class _StubRedis:
        async def brpop(
            self,
            keys: list[str],
            timeout: int,  # noqa: ASYNC109 - mirrors redis-py's own signature
        ) -> tuple[bytes, bytes] | None:
            polls.append(timeout)
            if len(polls) < 3:
                return None  # two idle polls
            return (
                keys[0].encode(),
                json.dumps({"tenant_id": "idle-tenant", "app_id": "vault"}).encode(),
            )

        async def aclose(self) -> None:
            return None

    monkeypatch.setattr(worker_module.Redis, "from_url", staticmethod(lambda *a, **k: _StubRedis()))

    settings = Settings(
        database_url=migrated_pg_url,
        redis_url=redis_url,
        vault_addr="http://127.0.0.1:9",
        vault_token="placeholder",
    )
    handled = await run_worker(settings, max_jobs=1)

    assert handled == 1
    assert len(polls) == 3  # two idle polls, then the job
