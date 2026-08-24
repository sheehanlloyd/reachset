"""Owns the worker loop: pull sync jobs from Redis, run the connector, upsert,
advance the watermark, rebuild reach for the tenant. Failures bump the
watermark's failure count and dead-letter the job; the loop itself never dies.

Job shape on the `reachset:jobs` list: {"tenant_id": ..., "app_id": "vault"}.
"""

import asyncio
import json
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from reachset.config import Settings, load_settings
from reachset.connectors.transports import HttpTransport
from reachset.connectors.vault.connector import VaultConnector, make_transport_headers
from reachset.db import make_engine, make_session_factory
from reachset.ingest import dead_letter, watermarks
from reachset.ingest.pipeline import upsert_batch
from reachset.logging import configure_logging, get_logger
from reachset.reach.engine import materialize
from reachset.records import ExtractBatch

log = get_logger(__name__)

QUEUE_KEY = "reachset:jobs"

# A "syncer" produces one full ExtractBatch for (tenant, app). Injectable so
# tests run the worker loop against fixtures instead of live Vault.
Syncer = Callable[[str, str], Awaitable[ExtractBatch]]


def vault_syncer(settings: Settings) -> Syncer:
    async def _sync(tenant_id: str, app_id: str) -> ExtractBatch:
        transport = HttpTransport(
            settings.vault_addr, headers=make_transport_headers(settings.vault_token)
        )
        try:
            return await VaultConnector(transport).sync()
        finally:
            await transport.aclose()

    return _sync


async def handle_job(
    session_factory: async_sessionmaker[AsyncSession],
    job: dict[str, Any],
    syncer: Syncer,
) -> bool:
    """Run one job to completion. Returns True on success. All failure paths
    leave a dead letter and a bumped failure counter behind — including a
    failure after the sync itself succeeds (a bad upsert, a materialize
    error), not just a failed fetch. Both must be caught the same way, or a
    DB-side failure on an otherwise-good batch would crash the loop instead
    of dead-lettering the job.
    """
    tenant_id = job["tenant_id"]
    app_id = job["app_id"]
    try:
        batch = await syncer(tenant_id, app_id)
        async with session_factory() as session:
            stats = await upsert_batch(session, tenant_id, app_id, batch)
            await watermarks.advance(
                session, tenant_id, app_id, "full", datetime.now(UTC).isoformat()
            )
            edges = await materialize(session, tenant_id)
            await session.commit()
    except Exception as exc:
        log.warning("sync_failed", tenant=tenant_id, app=app_id, error=str(exc))
        async with session_factory() as session:
            await dead_letter.bury(
                session, tenant_id, app_id, "full", {"job": job}, str(exc), attempts=1
            )
            await watermarks.record_failure(session, tenant_id, app_id, "full")
            await session.commit()
        return False

    log.info("job_done", tenant=tenant_id, app=app_id, reach_edges=edges, **stats.as_dict())
    return True


async def run_worker(
    settings: Settings | None = None,
    *,
    max_jobs: int | None = None,
) -> int:
    """Blocking worker loop; max_jobs bounds it for tests. Returns jobs handled."""
    settings = settings or load_settings()
    configure_logging(settings.log_level)
    redis: Redis = Redis.from_url(settings.redis_url)
    engine = make_engine(settings.database_url)
    factory = make_session_factory(engine)
    syncer = vault_syncer(settings)
    handled = 0
    try:
        while max_jobs is None or handled < max_jobs:
            item = await redis.brpop([QUEUE_KEY], timeout=5)
            if item is None:
                continue
            _, raw = item
            try:
                job = json.loads(raw)
            except json.JSONDecodeError:
                log.warning("job_undecodable", raw=raw[:200])
                continue
            await handle_job(factory, job, syncer)
            handled += 1
    finally:
        await redis.aclose()
        await engine.dispose()
    return handled


if __name__ == "__main__":
    asyncio.run(run_worker())
