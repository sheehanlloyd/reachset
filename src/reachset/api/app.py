"""Owns the HTTP API. Endpoints return computed conclusions from the canonical
schema; nothing here talks to connectors directly.

Operational endpoints follow the usual split: /healthz is liveness (is the
process up), /readyz is readiness (can it reach its dependencies), and /metrics
is Prometheus exposition. A liveness probe that touches the database would
restart the API every time Postgres hiccups, which is the opposite of helpful.
"""

import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Annotated, Any
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from reachset.config import load_settings
from reachset.db import make_engine, make_session_factory
from reachset.logging import configure_logging, get_logger
from reachset.models import Principal, ReachEdge, Resource
from reachset.observability import (
    CONTENT_TYPE,
    HTTP_DURATION,
    HTTP_REQUESTS,
    render_metrics,
)

log = get_logger(__name__)


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = load_settings()
    configure_logging(settings.log_level)
    engine = make_engine(settings.database_url)
    app.state.engine = engine
    app.state.session_factory = make_session_factory(engine)
    try:
        yield
    finally:
        await engine.dispose()


app = FastAPI(title="reachset", lifespan=_lifespan)


async def _session(  # pragma: no cover - overridden by the test fixture
) -> AsyncIterator[AsyncSession]:
    factory: async_sessionmaker[AsyncSession] = app.state.session_factory
    async with factory() as session:
        yield session


@app.middleware("http")
async def _observe(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    """Record latency and outcome per route.

    Labels use the route *template*
    (`/tenants/{tenant_id}/principals/{principal_id}/reach`), not the
    concrete path, so a tenant with 10k principals produces one time series
    instead of 10k — the cardinality mistake that eventually kills a
    Prometheus instance.
    """
    started = time.perf_counter()
    response = await call_next(request)
    route = request.scope.get("route")
    template = getattr(route, "path", request.url.path)
    elapsed = time.perf_counter() - started
    HTTP_REQUESTS.inc(method=request.method, route=template, status=str(response.status_code))
    HTTP_DURATION.observe(elapsed, method=request.method, route=template)
    return response


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    """Liveness: the process is running. Deliberately touches nothing."""
    return {"status": "ok"}


@app.get("/readyz")
async def readyz(session: Annotated[AsyncSession, Depends(_session)]) -> Response:
    """Readiness: dependencies actually answer.

    Returns 503 on failure so a load balancer drains this instance rather than
    routing traffic into errors, and reports which check failed rather than a
    bare status — a probe that only says "not ready" wastes the first ten
    minutes of every incident.
    """
    checks: dict[str, str] = {}
    ok = True
    try:
        await session.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as exc:
        ok = False
        checks["database"] = f"error: {type(exc).__name__}"
        log.warning("readiness_check_failed", check="database", error=str(exc))

    body = {"status": "ready" if ok else "not ready", "checks": checks}
    return JSONResponse(content=body, status_code=200 if ok else 503)


@app.get("/metrics")
async def metrics() -> Response:
    return Response(content=render_metrics(), media_type=CONTENT_TYPE)


@app.get("/tenants/{tenant_id}/principals/{principal_id}/reach")
async def principal_reach(
    tenant_id: str,
    principal_id: UUID,
    session: Annotated[AsyncSession, Depends(_session)],
) -> dict[str, Any]:
    """Materialized reach set for one principal, ranked by sensitivity then
    confidence. Scoped by tenant_id like every other endpoint here — a
    principal UUID is effectively unguessable, but this endpoint had drifted
    to being the one place in the file that didn't check tenancy at all,
    which is the wrong pattern to leave lying around even where it's not
    currently exploitable.
    """
    principal = (
        await session.execute(
            select(Principal).where(Principal.id == principal_id, Principal.tenant_id == tenant_id)
        )
    ).scalar_one_or_none()
    if principal is None:
        raise HTTPException(status_code=404, detail="principal not found")
    rows = (
        await session.execute(
            select(ReachEdge, Resource)
            .join(Resource, ReachEdge.resource_id == Resource.id)
            .where(ReachEdge.principal_id == principal_id, ReachEdge.tenant_id == tenant_id)
            .order_by(Resource.sensitivity.desc(), ReachEdge.confidence.desc())
        )
    ).all()
    return {
        "principal": {
            "id": str(principal.id),
            "external_id": principal.external_id,
            "kind": principal.kind.value,
            "display_name": principal.display_name,
        },
        "reach": [
            {
                "resource": edge_resource.path,
                "resource_kind": edge_resource.kind.value,
                "sensitivity": edge_resource.sensitivity,
                "capability": edge.capability.value,
                "confidence": edge.confidence,
                "path": edge.path_json,
            }
            for edge, edge_resource in rows
        ],
    }


@app.get("/tenants/{tenant_id}/summary")
async def tenant_summary(
    tenant_id: str, session: Annotated[AsyncSession, Depends(_session)]
) -> dict[str, Any]:
    """Coarse counts for a tenant; the MCP layer builds on the same queries."""
    principal_count = (
        await session.execute(
            select(func.count()).select_from(Principal).where(Principal.tenant_id == tenant_id)
        )
    ).scalar_one()
    edge_count = (
        await session.execute(
            select(func.count()).select_from(ReachEdge).where(ReachEdge.tenant_id == tenant_id)
        )
    ).scalar_one()
    return {"tenant_id": tenant_id, "principals": principal_count, "reach_edges": edge_count}
