"""Owns the MCP tool logic: summaries and conclusions computed in SQL, sized for
a context window. assess_principal returns a reach summary and top risks with
evidence references — never the raw 4000-edge dump.

All free-text fields that originated in a connected app (display names, paths)
are wrapped as tagged untrusted values by reachset.triage.sanitize before they
leave this module.
"""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from reachset.detections.registry import run_all
from reachset.triage.sanitize import untrusted

TOP_EDGES = 15


async def assess_principal(
    session: AsyncSession, tenant_id: str, principal_id: uuid.UUID
) -> dict[str, Any]:
    principal = (
        await session.execute(
            text(
                "SELECT id, external_id, display_name, kind, status, last_active_at "
                "FROM principals WHERE tenant_id = :tenant AND id = :id"
            ),
            {"tenant": tenant_id, "id": principal_id},
        )
    ).one_or_none()
    if principal is None:
        return {"error": "principal not found"}

    summary = (
        await session.execute(
            text(
                "SELECT COUNT(*) AS total, "
                "COUNT(DISTINCT res.app_id) AS apps, "
                "MAX(res.sensitivity) AS max_sensitivity, "
                "COUNT(*) FILTER (WHERE re.capability IN ('write','admin','delete')) "
                "  AS privileged_edges "
                "FROM reach_edges re JOIN resources res ON res.id = re.resource_id "
                "WHERE re.tenant_id = :tenant AND re.principal_id = :id"
            ),
            {"tenant": tenant_id, "id": principal_id},
        )
    ).one()

    by_capability: dict[str, int] = {
        capability: count
        for capability, count in (
            await session.execute(
                text(
                    "SELECT capability, COUNT(*) FROM reach_edges "
                    "WHERE tenant_id = :tenant AND principal_id = :id GROUP BY capability"
                ),
                {"tenant": tenant_id, "id": principal_id},
            )
        ).tuples()
    }

    top_edges = (
        await session.execute(
            text(
                "SELECT res.path, res.app_id, res.sensitivity, re.capability, "
                "re.confidence, re.path_json "
                "FROM reach_edges re JOIN resources res ON res.id = re.resource_id "
                "WHERE re.tenant_id = :tenant AND re.principal_id = :id "
                "ORDER BY res.sensitivity DESC, re.confidence DESC LIMIT :n"
            ),
            {"tenant": tenant_id, "id": principal_id, "n": TOP_EDGES},
        )
    ).all()

    activity = (
        await session.execute(
            text(
                "SELECT COUNT(*) AS events_28d, MAX(ts) AS last_event "
                "FROM events WHERE tenant_id = :tenant AND actor_principal_id = :id "
                "AND ts >= :since"
            ),
            {
                "tenant": tenant_id,
                "id": principal_id,
                "since": datetime.now(UTC) - timedelta(days=28),
            },
        )
    ).one()

    findings = [
        f.as_dict()
        for f in await run_all(session, tenant_id, now=datetime.now(UTC))
        if f.principal_id == principal_id
    ]

    return {
        "principal": {
            "id": str(principal.id),
            "external_id": principal.external_id,
            "display_name": untrusted(principal.display_name, "app_profile"),
            "kind": principal.kind,
            "status": principal.status,
            "last_active_at": principal.last_active_at.isoformat()
            if principal.last_active_at
            else None,
        },
        "reach_summary": {
            "total_edges": summary.total,
            "apps": summary.apps,
            "max_sensitivity": summary.max_sensitivity,
            "privileged_edges": summary.privileged_edges,
            "by_capability": {k: v for k, v in sorted(by_capability.items())},
        },
        "top_risks": findings,
        "evidence_refs": [
            {
                "resource": untrusted(row.path, "app_inventory"),
                "app": row.app_id,
                "sensitivity": row.sensitivity,
                "capability": row.capability,
                "confidence": row.confidence,
                "derivation": row.path_json,
            }
            for row in top_edges
        ],
        "recent_activity": {
            "events_28d": activity.events_28d,
            "last_event": activity.last_event.isoformat() if activity.last_event else None,
        },
    }


async def find_risky_principals(
    session: AsyncSession, tenant_id: str, *, limit: int = 10
) -> list[dict[str, Any]]:
    """NHIs ranked by privileged reach onto sensitive resources."""
    rows = (
        await session.execute(
            text(
                "SELECT p.id, p.external_id, p.display_name, p.kind, "
                "COUNT(*) FILTER (WHERE re.capability IN ('write','admin','delete') "
                "  AND res.sensitivity >= 2) AS privileged_sensitive, "
                "COUNT(DISTINCT res.app_id) AS apps, MAX(res.sensitivity) AS max_sensitivity "
                "FROM reach_edges re "
                "JOIN principals p ON p.id = re.principal_id "
                "JOIN resources res ON res.id = re.resource_id "
                "WHERE re.tenant_id = :tenant AND p.kind IN ('service','agent','app') "
                "GROUP BY p.id, p.external_id, p.display_name, p.kind "
                "ORDER BY privileged_sensitive DESC, apps DESC LIMIT :limit"
            ),
            {"tenant": tenant_id, "limit": limit},
        )
    ).all()
    return [
        {
            "id": str(row.id),
            "external_id": row.external_id,
            "display_name": untrusted(row.display_name, "app_profile"),
            "kind": row.kind,
            "privileged_sensitive_edges": row.privileged_sensitive,
            "apps": row.apps,
            "max_sensitivity": row.max_sensitivity,
        }
        for row in rows
    ]


async def explain_edge(
    session: AsyncSession,
    tenant_id: str,
    principal_id: uuid.UUID,
    resource_path: str,
    capability: str,
) -> dict[str, Any]:
    row = (
        await session.execute(
            text(
                "SELECT re.path_json, re.confidence, re.computed_at "
                "FROM reach_edges re JOIN resources res ON res.id = re.resource_id "
                "WHERE re.tenant_id = :tenant AND re.principal_id = :id "
                "AND res.path = :path AND re.capability = :capability"
            ),
            {
                "tenant": tenant_id,
                "id": principal_id,
                "path": resource_path,
                "capability": capability,
            },
        )
    ).one_or_none()
    if row is None:
        return {"error": "no such edge; reach may need recomputation"}
    return {
        "resource": untrusted(resource_path, "app_inventory"),
        "capability": capability,
        "confidence": row.confidence,
        "computed_at": row.computed_at.isoformat(),
        "derivation": row.path_json,
    }
