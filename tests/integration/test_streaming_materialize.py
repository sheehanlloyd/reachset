"""materialize() streams the CTE's result through a server-side cursor in
bounded chunks instead of buffering the whole tenant in Python (see
NOTES.md, "Reach engine performance" — peak RSS was 4.3 GB on a 2M-edge
tenant before this). The correctness bar is the same as any other
materialization path: same edge set regardless of chunk size. These tests
force a tiny chunk size so a real tenant's worth of rows crosses several
chunk boundaries, which is exactly the case a buffered implementation and a
streaming one could disagree on if the chunking were buggy (an off-by-one
losing or duplicating the row at a boundary)."""

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from reachset.models import Capability, Grant, Principal, PrincipalKind, Resource, ResourceKind
from reachset.reach import engine as reach_engine
from reachset.reach.engine import materialize

pytestmark = pytest.mark.integration


async def _seed(db: AsyncSession, tenant: str, count: int) -> None:
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
    await db.flush()


async def test_materialize_is_correct_across_chunk_boundaries(
    db: AsyncSession, tenant: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(reach_engine, "_MATERIALIZE_CHUNK", 3)
    await _seed(db, tenant, count=10)

    total = await materialize(db, tenant)
    await db.commit()

    assert total == 10
    count = (
        await db.execute(
            text("SELECT COUNT(*) FROM reach_edges WHERE tenant_id = :t"), {"t": tenant}
        )
    ).scalar_one()
    assert count == 10
    resources = (
        (
            await db.execute(
                text(
                    "SELECT DISTINCT r.path FROM reach_edges re "
                    "JOIN resources r ON r.id = re.resource_id WHERE re.tenant_id = :t "
                    "ORDER BY r.path"
                ),
                {"t": tenant},
            )
        )
        .scalars()
        .all()
    )
    assert resources == [f"secret/data/{i}" for i in range(10)]


async def test_materialize_with_no_matching_rows_is_zero(db: AsyncSession, tenant: str) -> None:
    """An empty result must not raise or insert anything — the streaming
    partitions() call yields zero partitions rather than one empty one."""
    assert await materialize(db, tenant) == 0
