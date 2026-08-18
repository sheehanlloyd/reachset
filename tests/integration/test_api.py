"""API surface tests over a real database.

Uses httpx's ASGITransport rather than TestClient so the app, the test, and the
asyncpg pool all share one event loop.
"""

from collections.abc import AsyncIterator

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from reachset.api.app import _session, app
from reachset.models import Capability, Principal, PrincipalKind, ReachEdge, Resource, ResourceKind

pytestmark = pytest.mark.integration


@pytest.fixture
async def client(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncClient]:
    async def _gen() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            yield session

    app.dependency_overrides[_session] = _gen
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            yield c
    finally:
        app.dependency_overrides.clear()


async def test_healthz(client: AsyncClient) -> None:
    resp = await client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


async def test_reach_endpoint_orders_by_sensitivity(
    db: AsyncSession, client: AsyncClient, tenant: str
) -> None:
    p = Principal(tenant_id=tenant, app_id="vault", external_id="svc-1", kind=PrincipalKind.SERVICE)
    low = Resource(
        tenant_id=tenant,
        app_id="vault",
        external_id="secret/dev/foo",
        kind=ResourceKind.SECRET_PATH,
        path="secret/dev/foo",
        sensitivity=0,
    )
    high = Resource(
        tenant_id=tenant,
        app_id="vault",
        external_id="secret/prod/db",
        kind=ResourceKind.SECRET_PATH,
        path="secret/prod/db",
        sensitivity=3,
    )
    db.add_all([p, low, high])
    await db.flush()
    db.add_all(
        [
            ReachEdge(
                tenant_id=tenant,
                principal_id=p.id,
                resource_id=low.id,
                capability=Capability.READ,
                path_json=[{"via": "grant"}],
                confidence=1.0,
            ),
            ReachEdge(
                tenant_id=tenant,
                principal_id=p.id,
                resource_id=high.id,
                capability=Capability.WRITE,
                path_json=[{"via": "grant"}],
                confidence=0.95,
            ),
        ]
    )
    await db.commit()

    resp = await client.get(f"/principals/{p.id}/reach")
    assert resp.status_code == 200
    body = resp.json()
    assert body["principal"]["external_id"] == "svc-1"
    assert [r["resource"] for r in body["reach"]] == ["secret/prod/db", "secret/dev/foo"]
    assert body["reach"][0]["capability"] == "write"

    resp = await client.get("/principals/00000000-0000-0000-0000-000000000000/reach")
    assert resp.status_code == 404


async def test_tenant_summary(db: AsyncSession, client: AsyncClient, tenant: str) -> None:
    db.add(Principal(tenant_id=tenant, app_id="vault", external_id="x", kind=PrincipalKind.HUMAN))
    await db.commit()
    resp = await client.get(f"/tenants/{tenant}/summary")
    assert resp.status_code == 200
    assert resp.json() == {"tenant_id": tenant, "principals": 1, "reach_edges": 0}
