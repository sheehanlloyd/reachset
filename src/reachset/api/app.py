"""Owns the HTTP API. Endpoints return computed conclusions from the canonical
schema; nothing here talks to connectors directly."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated, Any
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from reachset.config import load_settings
from reachset.db import make_engine, make_session_factory
from reachset.logging import configure_logging
from reachset.models import Principal, ReachEdge, Resource


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = load_settings()
    configure_logging(settings.log_level)
    engine = make_engine(settings.database_url)
    app.state.session_factory = make_session_factory(engine)
    try:
        yield
    finally:
        await engine.dispose()


app = FastAPI(title="reachset", lifespan=_lifespan)


async def _session(  # pragma: no cover - exercised via dependency override in tests
) -> AsyncIterator[AsyncSession]:
    factory: async_sessionmaker[AsyncSession] = app.state.session_factory
    async with factory() as session:
        yield session


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/principals/{principal_id}/reach")
async def principal_reach(
    principal_id: UUID, session: Annotated[AsyncSession, Depends(_session)]
) -> dict[str, Any]:
    """Materialized reach set for one principal, ranked by sensitivity then confidence."""
    principal = await session.get(Principal, principal_id)
    if principal is None:
        raise HTTPException(status_code=404, detail="principal not found")
    rows = (
        await session.execute(
            select(ReachEdge, Resource)
            .join(Resource, ReachEdge.resource_id == Resource.id)
            .where(ReachEdge.principal_id == principal_id)
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
