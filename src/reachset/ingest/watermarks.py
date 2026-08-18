"""Owns sync watermark bookkeeping. A watermark only ever advances in the same
transaction as the page upsert it describes — that invariant is the whole reason
replays are safe."""

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from reachset.models import SyncWatermark


async def get_cursor(session: AsyncSession, tenant_id: str, app_id: str, stream: str) -> str | None:
    row = (
        await session.execute(
            select(SyncWatermark.cursor).where(
                SyncWatermark.tenant_id == tenant_id,
                SyncWatermark.app_id == app_id,
                SyncWatermark.stream == stream,
            )
        )
    ).scalar_one_or_none()
    return row


async def advance(
    session: AsyncSession, tenant_id: str, app_id: str, stream: str, cursor: str | None
) -> None:
    now = datetime.now(UTC)
    stmt = (
        insert(SyncWatermark)
        .values(
            tenant_id=tenant_id,
            app_id=app_id,
            stream=stream,
            cursor=cursor,
            last_success_at=now,
            consecutive_failures=0,
        )
        .on_conflict_do_update(
            index_elements=["tenant_id", "app_id", "stream"],
            set_={"cursor": cursor, "last_success_at": now, "consecutive_failures": 0},
        )
    )
    await session.execute(stmt)


async def record_failure(session: AsyncSession, tenant_id: str, app_id: str, stream: str) -> int:
    """Bump consecutive_failures without touching the cursor; returns new count."""
    stmt = (
        insert(SyncWatermark)
        .values(tenant_id=tenant_id, app_id=app_id, stream=stream, consecutive_failures=1)
        .on_conflict_do_update(
            index_elements=["tenant_id", "app_id", "stream"],
            set_={"consecutive_failures": SyncWatermark.consecutive_failures + 1},
        )
        .returning(SyncWatermark.consecutive_failures)
    )
    return (await session.execute(stmt)).scalar_one()
