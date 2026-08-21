"""Owns the naive in-Python reachability reference.

This is the executable specification for reach.engine: dumb on purpose, no SQL,
no cleverness — enumerate every simple path and take the best edge. The
Hypothesis property test asserts the CTE agrees with this on random graphs.
Correct before fast; this file is the "correct".
"""

import uuid
from collections.abc import Collection
from dataclasses import dataclass, field

from reachset.reach.selectors import (
    glob_match,
    is_principal_selector,
    principal_pattern,
)

FUZZY = "fuzzy_name"


@dataclass(frozen=True)
class GraphPrincipal:
    id: uuid.UUID
    external_id: str


@dataclass(frozen=True)
class GraphGrant:
    id: uuid.UUID
    principal_id: uuid.UUID
    resource_selector: str
    capabilities: frozenset[str]
    scope_raw: str = ""
    # The app that issued this grant. A grant never reaches outside it.
    source_app_id: str = "synth"


@dataclass(frozen=True)
class GraphResource:
    id: uuid.UUID
    path: str
    app_id: str = "synth"


@dataclass(frozen=True)
class GraphLink:
    principal_a: uuid.UUID
    principal_b: uuid.UUID
    method: str
    confidence: float


@dataclass(frozen=True)
class Graph:
    principals: list[GraphPrincipal]
    grants: list[GraphGrant]
    resources: list[GraphResource]
    links: list[GraphLink] = field(default_factory=list)


@dataclass(frozen=True)
class BfsEdge:
    origin_id: uuid.UUID
    resource_id: uuid.UUID
    capability: str
    confidence: float
    hops: int


def compute_reach_bfs(
    graph: Graph,
    *,
    origin: uuid.UUID | None = None,
    depth_cap: int = 8,
    include_fuzzy: bool = False,
    exclude_grant_ids: Collection[uuid.UUID] = (),
) -> dict[tuple[uuid.UUID, uuid.UUID, str], BfsEdge]:
    """Best edge per (origin, resource, capability), enumerating simple paths."""
    excluded = frozenset(exclude_grant_ids)
    by_principal: dict[uuid.UUID, list[GraphGrant]] = {}
    for grant in graph.grants:
        if grant.id in excluded:
            continue
        by_principal.setdefault(grant.principal_id, []).append(grant)
    principals_by_id = {p.id: p for p in graph.principals}

    best: dict[tuple[uuid.UUID, uuid.UUID, str], BfsEdge] = {}

    origins = [p for p in graph.principals if origin is None or p.id == origin]
    for start in origins:
        # frontier entries: (current principal, visited, confidence, depth, has_fuzzy)
        frontier: list[tuple[uuid.UUID, frozenset[uuid.UUID], float, int, bool]] = [
            (start.id, frozenset({start.id}), 1.0, 0, False)
        ]
        while frontier:
            current, visited, confidence, depth, has_fuzzy = frontier.pop()

            for grant in by_principal.get(current, []):
                if is_principal_selector(grant.resource_selector):
                    continue
                effective = min(confidence, 0.6) if has_fuzzy else confidence
                for capability in grant.capabilities - {"impersonate"}:
                    for resource in graph.resources:
                        if resource.app_id != grant.source_app_id:
                            continue
                        if not glob_match(grant.resource_selector, resource.path):
                            continue
                        key = (start.id, resource.id, capability)
                        candidate = BfsEdge(
                            origin_id=start.id,
                            resource_id=resource.id,
                            capability=capability,
                            confidence=effective,
                            hops=depth,
                        )
                        held = best.get(key)
                        if held is None or candidate.confidence > held.confidence + 1e-12:
                            best[key] = candidate

            if depth >= depth_cap:
                continue

            for grant in by_principal.get(current, []):
                if "impersonate" not in grant.capabilities:
                    continue
                if not is_principal_selector(grant.resource_selector):
                    continue
                pattern = principal_pattern(grant.resource_selector)
                for target in graph.principals:
                    if target.id in visited:
                        continue
                    if glob_match(pattern, target.external_id):
                        frontier.append(
                            (target.id, visited | {target.id}, confidence, depth + 1, has_fuzzy)
                        )

            for link in graph.links:
                if link.method == FUZZY and not include_fuzzy:
                    continue
                other: uuid.UUID | None = None
                if link.principal_a == current:
                    other = link.principal_b
                elif link.principal_b == current:
                    other = link.principal_a
                if other is None or other in visited or other not in principals_by_id:
                    continue
                frontier.append(
                    (
                        other,
                        visited | {other},
                        confidence * link.confidence,
                        depth + 1,
                        has_fuzzy or link.method == FUZZY,
                    )
                )
    return best
