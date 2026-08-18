"""Synthetic tenant generator: determinism, distribution shape, and reach
compatibility at small scale."""

from datetime import UTC, datetime

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from reachset.models import Event, Grant, Principal, Resource
from reachset.reach.engine import materialize
from reachset.synth.generator import SynthConfig, estimate_batches, generate

pytestmark = [pytest.mark.integration, pytest.mark.bench]


def test_estimate_batches() -> None:
    assert estimate_batches(0) == 0
    assert estimate_batches(1) == 1
    assert estimate_batches(5000) == 1
    assert estimate_batches(5001) == 2


async def test_generate_counts_and_distributions(db: AsyncSession, tenant: str) -> None:
    counts = await generate(
        db, SynthConfig(tenant_id=tenant, principals=300, grants=900, events=6000, seed=7)
    )
    assert counts == {"principals": 300, "resources": 150, "grants": 900, "events": 6000}

    kinds = dict(
        (
            await db.execute(
                select(Principal.kind, func.count())
                .where(Principal.tenant_id == tenant)
                .group_by(Principal.kind)
            )
        ).all()
    )
    assert kinds["human"] > kinds["service"] > kinds.get("agent", 0)

    # Long tail: the top 10% of actors produce well over half the events.
    top_share = (
        await db.execute(
            text(
                "WITH per_actor AS ("
                "  SELECT actor_principal_id, COUNT(*) AS n FROM events"
                "  WHERE tenant_id = :tenant GROUP BY actor_principal_id"
                "), ranked AS ("
                "  SELECT n, NTILE(10) OVER (ORDER BY n DESC) AS decile FROM per_actor"
                ") SELECT SUM(n) FILTER (WHERE decile = 1)::float / SUM(n) FROM ranked"
            ),
            {"tenant": tenant},
        )
    ).scalar_one()
    assert top_share > 0.5

    # Most principals are inert (no events at all).
    actors = (
        await db.execute(
            select(func.count(func.distinct(Event.actor_principal_id))).where(
                Event.tenant_id == tenant
            )
        )
    ).scalar_one()
    assert actors < 300 * 0.6

    # The generated graph materializes without error.
    edges = await materialize(db, tenant)
    await db.commit()
    assert edges > 0


async def test_same_seed_same_tenant_is_deterministic(db: AsyncSession, tenant: str) -> None:
    config = SynthConfig(tenant_id=tenant, principals=50, grants=100, events=500, seed=11)
    await generate(db, config)
    first = {
        row[0]: (row[1], row[2])
        for row in (
            await db.execute(
                select(Grant.dedupe_key, Grant.resource_selector, Grant.scope_raw).where(
                    Grant.tenant_id == tenant
                )
            )
        ).all()
    }
    # wipe and regenerate with the same seed
    for table in ("events", "grants", "resources", "principals"):
        await db.execute(
            text(f"DELETE FROM {table} WHERE tenant_id = :tenant"),
            {"tenant": tenant},
        )
    await db.commit()
    await generate(db, config)
    second = {
        row[0]: (row[1], row[2])
        for row in (
            await db.execute(
                select(Grant.dedupe_key, Grant.resource_selector, Grant.scope_raw).where(
                    Grant.tenant_id == tenant
                )
            )
        ).all()
    }
    assert first == second


async def test_generation_is_timestamp_bounded(db: AsyncSession, tenant: str) -> None:
    await generate(db, SynthConfig(tenant_id=tenant, principals=30, grants=60, events=300))
    newest = (
        await db.execute(select(func.max(Event.ts)).where(Event.tenant_id == tenant))
    ).scalar_one()
    assert newest <= datetime(2026, 8, 18, tzinfo=UTC)
    resources = (
        await db.execute(
            select(func.count()).select_from(Resource).where(Resource.tenant_id == tenant)
        )
    ).scalar_one()
    assert resources == 50  # floor kicks in below principals // 2
