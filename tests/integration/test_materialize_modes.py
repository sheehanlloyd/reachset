"""Full versus incremental materialization.

Incremental exists so a single principal's change does not force a whole-tenant
recompute; the guarantee that matters is that it produces the same rows for the
principals it touches and leaves everyone else alone.
"""

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from reachset.models import Capability, Grant, Principal, PrincipalKind, Resource, ResourceKind
from reachset.observability import REACH_EDGES
from reachset.reach.engine import materialize

pytestmark = pytest.mark.integration


async def _seed(db: AsyncSession, tenant: str, count: int = 3) -> list[Principal]:
    principals = []
    for i in range(count):
        principal = Principal(
            tenant_id=tenant,
            app_id="vault",
            external_id=f"svc-{i}",
            kind=PrincipalKind.SERVICE,
        )
        resource = Resource(
            tenant_id=tenant,
            app_id="vault",
            external_id=f"secret/data/{i}",
            kind=ResourceKind.SECRET_PATH,
            path=f"secret/data/{i}",
            sensitivity=1,
        )
        db.add_all([principal, resource])
        await db.flush()
        db.add(
            Grant(
                tenant_id=tenant,
                principal_id=principal.id,
                resource_selector=f"secret/data/{i}",
                scope_raw="policy:ro",
                capabilities=[Capability.READ.value],
                source_app_id="vault",
                dedupe_key=uuid.uuid4().hex,
            )
        )
        principals.append(principal)
    await db.flush()
    return principals


async def _edge_count(db: AsyncSession, tenant: str) -> int:
    return (
        await db.execute(
            text("SELECT COUNT(*) FROM reach_edges WHERE tenant_id = :t"), {"t": tenant}
        )
    ).scalar_one()


async def test_incremental_matches_full_for_the_touched_principals(
    db: AsyncSession, tenant: str
) -> None:
    principals = await _seed(db, tenant)
    assert await materialize(db, tenant) == 3
    await db.commit()

    # Recomputing one principal incrementally leaves the total unchanged.
    assert await materialize(db, tenant, origins=[principals[0].id]) == 1
    await db.commit()
    assert await _edge_count(db, tenant) == 3


async def test_incremental_recompute_picks_up_a_revoked_grant(
    db: AsyncSession, tenant: str
) -> None:
    principals = await _seed(db, tenant)
    await materialize(db, tenant)
    await db.commit()

    await db.execute(
        text("DELETE FROM grants WHERE tenant_id = :t AND principal_id = :p"),
        {"t": tenant, "p": principals[1].id},
    )
    await materialize(db, tenant, origins=[principals[1].id])
    await db.commit()

    # That principal's edge is gone; the other two are untouched.
    assert await _edge_count(db, tenant) == 2
    remaining = (
        (
            await db.execute(
                text(
                    "SELECT p.external_id FROM reach_edges re "
                    "JOIN principals p ON p.id = re.principal_id WHERE re.tenant_id = :t "
                    "ORDER BY p.external_id"
                ),
                {"t": tenant},
            )
        )
        .scalars()
        .all()
    )
    assert remaining == ["svc-0", "svc-2"]


async def test_incremental_with_no_origins_is_a_no_op(db: AsyncSession, tenant: str) -> None:
    """An empty work list must not be mistaken for "recompute everything" — that
    confusion would wipe a tenant's reach on an empty change batch."""
    await _seed(db, tenant)
    await materialize(db, tenant)
    await db.commit()

    assert await materialize(db, tenant, origins=[]) == 0
    await db.commit()
    assert await _edge_count(db, tenant) == 3


async def test_only_a_full_recompute_reports_the_edge_gauge(db: AsyncSession, tenant: str) -> None:
    """An incremental pass knows its own slice, not the tenant total; publishing
    it as the gauge would make the dashboard lie."""
    principals = await _seed(db, tenant)
    await materialize(db, tenant)
    await db.commit()
    assert REACH_EDGES.value(tenant=tenant) == 3

    await materialize(db, tenant, origins=[principals[0].id])
    await db.commit()
    assert REACH_EDGES.value(tenant=tenant) == 3
