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
import time
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from reachset.observability import REACH_DURATION, REACH_EDGES
from reachset.reach.selectors import sql_glob_to_ere

# A selector with none of *, ?, + is an exact string — no pattern match needed
# at all, just an equality join. This is the split described in NOTES.md
# ("Reach engine performance"): before it, every impersonation grant was
# cross-joined against every principal in the tenant with a five-deep
# replace()+LIKE evaluated per pair, which profiled as the single most
# expensive node in the query plan (179 grants x 5,000 principals on the
# profiled tenant, 894,821 of those rows discarded by the join filter).
# Selectors written as literal principal ids or literal paths — the common
# case — now join by equality against an index instead of paying for a scan;
# only selectors that actually use glob syntax pay for the pattern match.
_HAS_WILDCARD = "({expr} ~ '[*?+]')"
_RESOURCE_GLOB = sql_glob_to_ere("g.resource_selector")
_PRINCIPAL_GLOB = sql_glob_to_ere("substr(g.resource_selector, 11)")
_PRINCIPAL_TARGET = "substr(g.resource_selector, 11)"

# Grants suppressed for this query — the mechanism behind what-if revocation.
# COALESCE keeps the expression valid when nothing is excluded.
_EXCLUDED = "COALESCE(CAST(:excluded_grants AS uuid[]), ARRAY[]::uuid[])"

_REACH_SQL = f"""
WITH RECURSIVE hops AS MATERIALIZED (
    -- Postgres allows exactly one recursive term, so every way of hopping from
    -- one principal to another is flattened here first: impersonation grants
    -- (split into an exact-match arm and a glob-match arm — see above), then
    -- identity links in both directions.
    --
    -- MATERIALIZED is load-bearing. `hops` is referenced once, from inside the
    -- recursive term, so Postgres inlines it by default and re-derives the
    -- whole relation on every iteration of the walk. Computing it once cut
    -- single-origin latency by ~30% on a 5k-principal tenant.
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
     AND tp.external_id = {_PRINCIPAL_TARGET}
    WHERE g.tenant_id = :tenant
      AND 'impersonate' = ANY(g.capabilities)
      AND g.resource_selector LIKE 'principal:%'
      AND NOT {_HAS_WILDCARD.format(expr=_PRINCIPAL_TARGET)}
      AND NOT (g.id = ANY({_EXCLUDED}))

  UNION ALL

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
     AND tp.external_id ~ {_PRINCIPAL_GLOB}
    WHERE g.tenant_id = :tenant
      AND 'impersonate' = ANY(g.capabilities)
      AND g.resource_selector LIKE 'principal:%'
      AND {_HAS_WILDCARD.format(expr=_PRINCIPAL_TARGET)}
      AND NOT (g.id = ANY({_EXCLUDED}))

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
    -- Same exact-vs-glob split as the impersonation hop above: a resource
    -- selector with no wildcard syntax joins resources by equality (index-
    -- backed on (tenant_id, path)) instead of paying for a pattern match.
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
     AND NOT {_HAS_WILDCARD.format(expr="g.resource_selector")}
     AND NOT (g.id = ANY({_EXCLUDED}))
    JOIN LATERAL unnest(g.capabilities) AS cap(capability)
      ON cap.capability <> 'impersonate'
    JOIN resources res
      ON res.tenant_id = :tenant
     -- A grant only reaches resources in the app that issued it. A Vault
     -- policy of `path "*"` is sudo over Vault, not over every repo in the
     -- org; cross-app reach comes from identity links, never from a selector
     -- that happens to match another app's path shape.
     AND res.app_id = g.source_app_id
     AND res.path = g.resource_selector

  UNION ALL

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
     AND {_HAS_WILDCARD.format(expr="g.resource_selector")}
     AND NOT (g.id = ANY({_EXCLUDED}))
    JOIN LATERAL unnest(g.capabilities) AS cap(capability)
      ON cap.capability <> 'impersonate'
    JOIN resources res
      ON res.tenant_id = :tenant
     AND res.app_id = g.source_app_id
     AND res.path ~ {_RESOURCE_GLOB}
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
    exclude_grant_ids: Sequence[uuid.UUID] | None = None,
) -> list[ReachRow]:
    """Reach rows for a tenant.

    `exclude_grant_ids` suppresses grants as if they had been revoked, without
    touching the database — that is what makes what-if revocation a read-only
    query instead of a transaction someone has to remember to roll back.
    """
    result = await session.execute(
        text(_REACH_SQL),
        {
            "tenant": tenant_id,
            "origin": origin,
            "depth_cap": depth_cap,
            "include_fuzzy": include_fuzzy,
            "excluded_grants": list(exclude_grant_ids) if exclude_grant_ids else None,
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


_INSERT_EDGE_SQL = (
    "INSERT INTO reach_edges "
    "(tenant_id, principal_id, resource_id, capability, path_json, confidence) "
    "VALUES (:tenant, :principal, :resource, :capability, CAST(:path AS jsonb), :confidence)"
)

# Rows per round trip while streaming a full materialization. Holding the
# entire result set in Python before the insert was what drove peak RSS to
# 4.3 GB on a 2M-edge tenant (see NOTES.md, "Reach engine performance"); this
# bounds how much of the result set is ever live in the process at once,
# independent of tenant size. It is a tuning knob, not a correctness
# parameter — smaller trades memory for more round trips, larger the reverse.
_MATERIALIZE_CHUNK = 2000


async def _stream_materialize(
    session: AsyncSession,
    tenant_id: str,
    *,
    origin: uuid.UUID | None,
    depth_cap: int,
) -> int:
    """Compute one origin's reach (or the whole tenant's, if origin is None)
    and insert it into reach_edges without ever holding the full result set
    in Python. `session.stream()` opens a server-side cursor; `partitions()`
    pulls bounded-size chunks from it lazily, and each chunk is inserted and
    discarded before the next one is fetched — so process memory is bounded
    by _MATERIALIZE_CHUNK, not by the tenant's edge count.
    """
    result = await session.stream(
        text(_REACH_SQL),
        {
            "tenant": tenant_id,
            "origin": origin,
            "depth_cap": depth_cap,
            "include_fuzzy": False,
            "excluded_grants": None,
        },
    )
    total = 0
    async for chunk in result.partitions(_MATERIALIZE_CHUNK):
        # partitions() never yields an empty chunk — it stops as soon as a
        # fetch returns zero rows rather than yielding one — so every chunk
        # reaching here is safe to insert unconditionally.
        await session.execute(
            text(_INSERT_EDGE_SQL),
            [
                {
                    "tenant": tenant_id,
                    "principal": row.origin_id,
                    "resource": row.resource_id,
                    "capability": row.capability,
                    "path": json.dumps(row.path),
                    "confidence": row.confidence,
                }
                for row in chunk
            ],
        )
        total += len(chunk)
    return total


async def materialize(
    session: AsyncSession,
    tenant_id: str,
    *,
    origins: list[uuid.UUID] | None = None,
    depth_cap: int = 8,
) -> int:
    """Rebuild reach_edges for a tenant (or a subset of origins, incrementally).

    Fuzzy links are excluded on purpose: materialized reach is what detections
    trust, and fuzzy correlation must never expand it. Streamed chunk by chunk
    rather than buffered — see _stream_materialize.
    """
    started = time.perf_counter()
    if origins is None:
        await session.execute(
            text("DELETE FROM reach_edges WHERE tenant_id = :tenant"), {"tenant": tenant_id}
        )
        total = await _stream_materialize(session, tenant_id, origin=None, depth_cap=depth_cap)
    else:
        if not origins:
            return 0
        await session.execute(
            text("DELETE FROM reach_edges WHERE tenant_id = :tenant AND principal_id = ANY(:ids)"),
            {"tenant": tenant_id, "ids": origins},
        )
        total = 0
        for origin in origins:
            total += await _stream_materialize(
                session, tenant_id, origin=origin, depth_cap=depth_cap
            )

    REACH_DURATION.observe(
        time.perf_counter() - started, mode="full" if origins is None else "incremental"
    )
    if origins is None:
        # Only a full recompute knows the tenant's true edge total; an
        # incremental pass would report a misleading partial number.
        REACH_EDGES.set(total, tenant=tenant_id)
    return total
