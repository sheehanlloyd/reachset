"""Owns the stream sync loop: watermark in, pages out, retries in between.

The loop guarantees, in order of importance:
1. No data loss: a page either upserts + advances the watermark in one
   transaction, or the stream stops with the cursor unmoved (resume retries it).
2. No duplicates: upserts are idempotent, so replays are harmless by design.
3. Termination: bounded retries per page, bounded repeats per cursor.
"""

import asyncio
import random
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from reachset.connectors.base import (
    StreamSpec,
    Transport,
    TransportConnectionError,
    TransportHTTPError,
)
from reachset.ingest import dead_letter, watermarks
from reachset.ingest.pipeline import upsert_batch
from reachset.ingest.ratelimit import BackoffPolicy, BucketSource, Sleeper
from reachset.logging import get_logger
from reachset.records import ExtractBatch

log = get_logger(__name__)


@dataclass(frozen=True)
class PageResult:
    """What a page extractor returns: records plus where the stream goes next."""

    batch: ExtractBatch
    next_cursor: str | None


PageExtractor = Callable[[dict[str, Any]], PageResult]


@dataclass(frozen=True)
class StreamOutcome:
    pages: int
    dead_lettered: bool
    retries: int


@dataclass
class StreamSyncer:
    session_factory: async_sessionmaker[AsyncSession]
    transport: Transport
    limiter: BucketSource
    backoff: BackoffPolicy = field(default_factory=BackoffPolicy)
    sleeper: Sleeper = asyncio.sleep
    rng: random.Random = field(default_factory=lambda: random.Random())
    max_cursor_repeats: int = 8

    async def _fetch_page(
        self, tenant_id: str, app_id: str, spec: StreamSpec, cursor: str | None
    ) -> tuple[dict[str, Any] | None, int]:
        """One page with retries. Returns (payload, attempts_used); payload None
        means retries were exhausted."""
        bucket = self.limiter.bucket(tenant_id, app_id)
        attempt = 0
        while True:
            attempt += 1
            await bucket.acquire()
            try:
                response = await self.transport.request(
                    spec.method, spec.path, spec.params_for(cursor)
                )
                payload = response.json()
                if not isinstance(payload, dict):
                    raise ValueError(f"expected object page, got {type(payload).__name__}")
                return payload, attempt
            except (TransportHTTPError, TransportConnectionError, ValueError) as exc:
                retryable = not (isinstance(exc, TransportHTTPError) and not exc.retryable)
                retry_after = exc.retry_after if isinstance(exc, TransportHTTPError) else None
                if not retryable or attempt >= self.backoff.max_attempts:
                    log.warning(
                        "page_fetch_exhausted",
                        stream=spec.name,
                        cursor=cursor,
                        attempts=attempt,
                        error=str(exc),
                    )
                    return None, attempt
                delay = self.backoff.delay_for(attempt, retry_after, self.rng)
                log.info(
                    "page_fetch_retry",
                    stream=spec.name,
                    cursor=cursor,
                    attempt=attempt,
                    delay=round(delay, 3),
                )
                await self.sleeper(delay)

    async def sync_stream(
        self,
        tenant_id: str,
        app_id: str,
        spec: StreamSpec,
        extract_page: PageExtractor,
    ) -> StreamOutcome:
        async with self.session_factory() as session:
            cursor = await watermarks.get_cursor(session, tenant_id, app_id, spec.name)

        pages = 0
        total_retries = 0
        cursor_seen: dict[str | None, int] = {}

        while True:
            seen = cursor_seen.get(cursor, 0) + 1
            cursor_seen[cursor] = seen
            if seen > self.max_cursor_repeats:
                # A pagination loop the retries never broke: stop without
                # advancing so the operator sees it, rather than spinning.
                async with self.session_factory() as session:
                    await dead_letter.bury(
                        session,
                        tenant_id,
                        app_id,
                        spec.name,
                        {"cursor": cursor, "reason": "pagination_loop"},
                        f"cursor {cursor!r} served more than {self.max_cursor_repeats} times",
                        attempts=seen,
                    )
                    await watermarks.record_failure(session, tenant_id, app_id, spec.name)
                    await session.commit()
                return StreamOutcome(pages=pages, dead_lettered=True, retries=total_retries)

            payload, attempts = await self._fetch_page(tenant_id, app_id, spec, cursor)
            total_retries += attempts - 1
            if payload is None:
                async with self.session_factory() as session:
                    await dead_letter.bury(
                        session,
                        tenant_id,
                        app_id,
                        spec.name,
                        {"cursor": cursor, "reason": "retries_exhausted"},
                        "page fetch failed after max attempts",
                        attempts=attempts,
                    )
                    await watermarks.record_failure(session, tenant_id, app_id, spec.name)
                    await session.commit()
                return StreamOutcome(pages=pages, dead_lettered=True, retries=total_retries)

            page = extract_page(payload)
            async with self.session_factory() as session:
                stats = await upsert_batch(session, tenant_id, app_id, page.batch)
                await watermarks.advance(session, tenant_id, app_id, spec.name, page.next_cursor)
                await session.commit()
            pages += 1
            log.info(
                "page_synced",
                stream=spec.name,
                cursor=cursor,
                next_cursor=page.next_cursor,
                **stats.as_dict(),
            )

            if page.next_cursor is None:
                return StreamOutcome(pages=pages, dead_lettered=False, retries=total_retries)
            cursor = page.next_cursor
