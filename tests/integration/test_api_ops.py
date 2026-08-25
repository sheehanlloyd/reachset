"""Operational endpoints added on top of the API."""

import uuid
from collections.abc import AsyncIterator

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from reachset.api.app import _session, app
from reachset.models import (
    Capability,
    Credential,
    CredentialKind,
    Grant,
    Principal,
    PrincipalKind,
    Resource,
    ResourceKind,
)
from reachset.observability import HTTP_REQUESTS
from reachset.reach.engine import materialize

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


async def _seed(db: AsyncSession, tenant: str) -> Principal:
    principal = Principal(
        tenant_id=tenant,
        app_id="vault",
        external_id="svc-api",
        kind=PrincipalKind.SERVICE,
        display_name="svc-api",
    )
    resource = Resource(
        tenant_id=tenant,
        app_id="vault",
        external_id="secret/data/prod/db",
        kind=ResourceKind.SECRET_PATH,
        path="secret/data/prod/db",
        sensitivity=3,
    )
    db.add_all([principal, resource])
    await db.flush()
    credential = Credential(
        tenant_id=tenant,
        principal_id=principal.id,
        kind=CredentialKind.VAULT_TOKEN,
        external_id="acc-api",
    )
    db.add(credential)
    await db.flush()
    db.add(
        Grant(
            tenant_id=tenant,
            principal_id=principal.id,
            credential_id=credential.id,
            resource_selector="secret/data/prod/*",
            scope_raw="policy:rw",
            capabilities=[Capability.READ.value, Capability.WRITE.value],
            source_app_id="vault",
            dedupe_key=uuid.uuid4().hex,
        )
    )
    await db.flush()
    await materialize(db, tenant)
    await db.commit()
    return principal


async def test_healthz_is_dependency_free(client: AsyncClient) -> None:
    resp = await client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


async def test_readyz_reports_each_check(client: AsyncClient) -> None:
    resp = await client.get("/readyz")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ready"
    assert body["checks"]["database"] == "ok"


async def test_readyz_returns_503_when_the_database_is_unreachable(
    client: AsyncClient,
) -> None:
    """A readiness probe that lies is worse than none: force a failure and
    assert the drain signal, not just the happy path."""

    class _BrokenSession:
        async def execute(self, *args: object, **kwargs: object) -> None:
            raise ConnectionError("database is down")

    async def _broken() -> AsyncIterator[object]:
        yield _BrokenSession()

    app.dependency_overrides[_session] = _broken
    try:
        resp = await client.get("/readyz")
    finally:
        app.dependency_overrides.pop(_session, None)

    assert resp.status_code == 503
    body = resp.json()
    assert body["status"] == "not ready"
    assert body["checks"]["database"] == "error: ConnectionError"


async def test_metrics_exposes_prometheus_text(client: AsyncClient) -> None:
    await client.get("/healthz")
    resp = await client.get("/metrics")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    assert "# TYPE reachset_http_requests_total counter" in resp.text
    assert "# TYPE reachset_http_request_duration_seconds histogram" in resp.text


async def test_request_metrics_use_route_templates_not_paths(
    db: AsyncSession, client: AsyncClient, tenant: str
) -> None:
    """Cardinality guard: 50 distinct principals must not create 50 series."""
    principal = await _seed(db, tenant)
    route = "/tenants/{tenant_id}/principals/{principal_id}/reach"
    before = HTTP_REQUESTS.value(method="GET", route=route, status="200")
    for _ in range(3):
        await client.get(f"/tenants/{tenant}/principals/{principal.id}/reach")
    after = HTTP_REQUESTS.value(method="GET", route=route, status="200")
    assert after - before == 3

    metrics = (await client.get("/metrics")).text
    assert f'route="{route}"' in metrics
    assert str(principal.id) not in metrics


async def test_lifespan_builds_and_disposes_its_own_engine(
    migrated_pg_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nothing else exercises the real startup path: the tests override the
    session dependency, so without this the app could fail to boot in
    production and every test would still pass."""
    from httpx import ASGITransport, AsyncClient
    from sqlalchemy.ext.asyncio import AsyncEngine

    monkeypatch.setenv("REACHSET_DATABASE_URL", migrated_pg_url)
    monkeypatch.setenv("REACHSET_LOG_LEVEL", "CRITICAL")
    app.dependency_overrides.clear()

    transport = ASGITransport(app=app)
    async with (
        AsyncClient(transport=transport, base_url="http://test") as client,
        app.router.lifespan_context(app),
    ):
        assert isinstance(app.state.engine, AsyncEngine)
        # The real dependency resolves against the real engine.
        resp = await client.get("/readyz")
        assert resp.status_code == 200
        assert resp.json()["checks"]["database"] == "ok"

    # After shutdown the engine is disposed; using it again must reconnect
    # rather than hand back a dead connection.
    assert app.state.engine.pool.checkedout() == 0
