"""Owns dead letters: pages that exhausted their retries land here with enough
context to replay them by hand later. Nothing is ever dropped silently."""

from typing import Any

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from reachset.models import DeadLetter
from reachset.observability import DEAD_LETTERS


async def bury(
    session: AsyncSession,
    tenant_id: str,
    app_id: str,
    stream: str,
    payload: dict[str, Any],
    error: str,
    attempts: int,
) -> None:
    DEAD_LETTERS.inc(app=app_id, stream=stream)
    await session.execute(
        insert(DeadLetter).values(
            tenant_id=tenant_id,
            app_id=app_id,
            stream=stream,
            payload=payload,
            error=error[:2000],
            attempts=attempts,
        )
    )
