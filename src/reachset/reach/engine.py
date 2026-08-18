"""Owns the recursive-CTE reachability computation and its materialization.

Semantics (mirrored exactly by reach.bfs, which is the executable spec):

- Start from every principal in the tenant (or one, for a point query).
- Hop 1: `impersonate` grants whose `principal:<glob>` selector matches another
  principal's external id — the origin inherits that principal's grants.
- Hop 2: identity links. Deterministic methods always traverse; `fuzzy_name`
  only when include_fuzzy is set, and then the path confidence is capped at 0.6.
- Terminal step: non-impersonate grants matched against resource paths.
- Confidence multiplies along the path (grants are 1.0, links carry their own).
- Simple paths only (visited set per path), bounded by depth_cap; grant steps do
  not consume depth, hops do.
- Result: the best edge per (origin, resource, capability) — highest effective
  confidence, then shortest path, then lexicographically smallest path for a
  deterministic tie-break.

`path_json` records every step, so any edge can be explained or replayed.
"""

import json
import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from reachset.reach.selectors import SQL_GLOB_TO_LIKE

_RESOURCE_GLOB = SQL_GLOB_TO_LIKE.format(expr="g.resource_selector")
_PRINCIPAL_GLOB = SQL_GLOB_TO_LIKE.format(expr="substr(g.resource_selector, 11)")

_REACH_SQL = f"""
WITH RECURSIVE hops AS (
    -- Postgres allows exactly one recursive term, so every way of hopping from
    -- one principal to another is flattened here first: impersonation grants,
    -- then identity links in both directions.
    SELECT g.principal_id AS from_id,
           tp.id AS to_id,
           1.0::float8 AS confidence,
           false AS is_fuzzy,
           jsonb_build_object(
               'step', 'impersonate',
               'grant_id', g.id::text,
               'from', fp.external_id,
               'to', tp.external_id,
               'selector', g.resource_selector,
               'scope', g.scope_raw) AS step
    FROM grants g
    JOIN principals fp ON fp.id = g.principal_id
    JOIN principals tp
      ON tp.tenant_id = :tenant
     AND tp.external_id LIKE {_PRINCIPAL_GLOB} ESCAPE '\\'
    WHERE g.tenant_id = :tenant
      AND 'impersonate' = ANY(g.capabilities)
      AND g.resource_selector LIKE 'principal:%'

  UNION ALL

    SELECT l.principal_a,
           l.principal_b,
           l.confidence,
           l.method = 'fuzzy_name',
           jsonb_build_object(
               'step', 'identity_link',
               'method', l.method,
               'confidence', l.confidence,
               'from', pa.external_id,
               'to', pb.external_id)
    FROM identity_links l
    JOIN principals pa ON pa.id = l.principal_a
    JOIN principals pb ON pb.id = l.principal_b
    WHERE l.tenant_id = :tenant
      AND (:include_fuzzy OR l.method <> 'fuzzy_name')

  UNION ALL

    SELECT l.principal_b,
           l.principal_a,
           l.confidence,
           l.method = 'fuzzy_name',
           jsonb_build_object(
               'step', 'identity_link',
               'method', l.method,
               'confidence', l.confidence,
               'from', pb.external_id,
               'to', pa.external_id)
    FROM identity_links l
    JOIN principals pa ON pa.id = l.principal_a
    JOIN principals pb ON pb.id = l.principal_b
    WHERE l.tenant_id = :tenant
      AND (:include_fuzzy OR l.method <> 'fuzzy_name')
),
reachable AS (
    SELECT p.id AS origin_id,
           p.id AS via_id,
           ARRAY[p.id] AS visited,
           1.0::float8 AS confidence,
           '[]'::jsonb AS path,
           0 AS depth,
           false AS has_fuzzy
    FROM principals p
    WHERE p.tenant_id = :tenant
      AND (CAST(:origin AS uuid) IS NULL OR p.id = :origin)

  UNION ALL

    SELECT r.origin_id,
           h.to_id,
           r.visited || h.to_id,
           r.confidence * h.confidence,
           r.path || jsonb_build_array(h.step),
           r.depth + 1,
           r.has_fuzzy OR h.is_fuzzy
    FROM reachable r
    JOIN hops h ON h.from_id = r.via_id
    WHERE r.depth < :depth_cap
      AND NOT (h.to_id = ANY(r.visited))
),
edges AS (
    SELECT r.origin_id,
           res.id AS resource_id,
           cap.capability,
           CASE WHEN r.has_fuzzy THEN LEAST(r.confidence, 0.6)
                ELSE r.confidence END AS confidence,
           r.path || jsonb_build_array(jsonb_build_object(
               'step', 'grant',
               'grant_id', g.id::text,
               'principal', vp.external_id,
               'selector', g.resource_selector,
               'scope', g.scope_raw,
               'capability', cap.capability,
               'resource', res.path)) AS path,
           r.depth,
           r.has_fuzzy
    FROM reachable r
    JOIN principals vp ON vp.id = r.via_id
    JOIN grants g
      ON g.principal_id = r.via_id
     AND g.tenant_id = :tenant
     AND NOT (g.resource_selector LIKE 'principal:%')
    JOIN LATERAL unnest(g.capabilities) AS cap(capability)
      ON cap.capability <> 'impersonate'
    JOIN resources res
      ON res.tenant_id = :tenant
     AND res.path LIKE {_RESOURCE_GLOB} ESCAPE '\\'
)
SELECT DISTINCT ON (origin_id, resource_id, capability)
       origin_id, resource_id, capability, confidence, path, has_fuzzy
FROM edges
ORDER BY origin_id, resource_id, capability,
         confidence DESC, jsonb_array_length(path) ASC, path::text ASC
"""


@dataclass(frozen=True)
class ReachRow:
    origin_id: uuid.UUID
    resource_id: uuid.UUID
    capability: str
    confidence: float
    path: list[dict[str, Any]]
    has_fuzzy: bool


async def compute_reach(
    session: AsyncSession,
    tenant_id: str,
    *,
    origin: uuid.UUID | None = None,
    depth_cap: int = 8,
    include_fuzzy: bool = False,
) -> list[ReachRow]:
    result = await session.execute(
        text(_REACH_SQL),
        {
            "tenant": tenant_id,
            "origin": origin,
            "depth_cap": depth_cap,
            "include_fuzzy": include_fuzzy,
        },
    )
    return [
        ReachRow(
            origin_id=row.origin_id,
            resource_id=row.resource_id,
            capability=row.capability,
            confidence=row.confidence,
            path=row.path,
            has_fuzzy=row.has_fuzzy,
        )
        for row in result
    ]


async def materialize(
    session: AsyncSession,
    tenant_id: str,
    *,
    origins: list[uuid.UUID] | None = None,
    depth_cap: int = 8,
) -> int:
    """Rebuild reach_edges for a tenant (or a subset of origins, incrementally).

    Fuzzy links are excluded on purpose: materialized reach is what detections
    trust, and fuzzy correlation must never expand it.
    """
    if origins is None:
        await session.execute(
            text("DELETE FROM reach_edges WHERE tenant_id = :tenant"), {"tenant": tenant_id}
        )
        rows = await compute_reach(session, tenant_id, depth_cap=depth_cap)
    else:
        if not origins:
            return 0
        await session.execute(
            text("DELETE FROM reach_edges WHERE tenant_id = :tenant AND principal_id = ANY(:ids)"),
            {"tenant": tenant_id, "ids": origins},
        )
        rows = []
        for origin in origins:
            rows.extend(await compute_reach(session, tenant_id, origin=origin, depth_cap=depth_cap))

    if rows:
        await session.execute(
            text(
                "INSERT INTO reach_edges "
                "(tenant_id, principal_id, resource_id, capability, path_json, confidence) "
                "VALUES (:tenant, :principal, :resource, :capability, "
                "CAST(:path AS jsonb), :confidence)"
            ),
            [
                {
                    "tenant": tenant_id,
                    "principal": row.origin_id,
                    "resource": row.resource_id,
                    "capability": row.capability,
                    "path": json.dumps(row.path),
                    "confidence": row.confidence,
                }
                for row in rows
            ],
        )
    return len(rows)
