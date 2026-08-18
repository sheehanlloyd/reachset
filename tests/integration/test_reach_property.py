"""The single most important test in the repo: on random small graphs, the
recursive CTE must produce exactly the same reach set — same (origin, resource,
capability) triples, same best confidences — as the naive Python BFS.

The BFS is the executable spec; if these two ever disagree, trust the BFS."""

import uuid

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from reachset.models import Capability
from reachset.reach.bfs import (
    Graph,
    GraphGrant,
    GraphLink,
    GraphPrincipal,
    GraphResource,
    compute_reach_bfs,
)
from reachset.reach.engine import compute_reach

pytestmark = pytest.mark.integration

N_PRINCIPALS = 5

RESOURCE_PATHS = st.sampled_from(
    ["a/b", "a/c", "b/x", "a/b/c", "z", "a_b", "a%b", "π/prod", "a/b\nc"]
)
SELECTORS = st.sampled_from(
    ["*", "a/*", "a/?", "a/b", "b/x", "?/*", "a*", "z", "a_b", "a%b", "π/*", "nomatch/*"]
)
PRINCIPAL_SELECTORS = st.sampled_from(
    ["principal:p0", "principal:p1", "principal:p*", "principal:p?", "principal:nobody"]
)
CAPS = st.frozensets(
    st.sampled_from([c.value for c in Capability if c is not Capability.IMPERSONATE]),
    min_size=1,
    max_size=3,
)
LINK_METHODS = st.sampled_from(
    [("external_id_exact", 1.0), ("email_exact", 0.95), ("sso_subject", 0.95), ("fuzzy_name", 0.6)]
)


@st.composite
def graphs(draw: st.DrawFn) -> Graph:
    n_principals = draw(st.integers(2, N_PRINCIPALS))
    principals = [GraphPrincipal(id=uuid.uuid4(), external_id=f"p{i}") for i in range(n_principals)]
    resources = [
        GraphResource(id=uuid.uuid4(), path=path)
        for path in draw(st.lists(RESOURCE_PATHS, min_size=1, max_size=4, unique=True))
    ]
    grants = []
    n_grants = draw(st.integers(1, 7))
    for i in range(n_grants):
        owner = draw(st.integers(0, n_principals - 1))
        if draw(st.booleans()):
            grants.append(
                GraphGrant(
                    id=uuid.uuid4(),
                    principal_id=principals[owner].id,
                    resource_selector=draw(SELECTORS),
                    capabilities=draw(CAPS),
                    scope_raw=f"s{i}",
                )
            )
        else:
            grants.append(
                GraphGrant(
                    id=uuid.uuid4(),
                    principal_id=principals[owner].id,
                    resource_selector=draw(PRINCIPAL_SELECTORS),
                    capabilities=frozenset({"impersonate"}),
                    scope_raw=f"s{i}",
                )
            )
    links = []
    for a_index, b_index in draw(
        st.lists(
            st.tuples(st.integers(0, n_principals - 1), st.integers(0, n_principals - 1)).filter(
                lambda pair: pair[0] < pair[1]
            ),
            max_size=4,
            unique=True,
        )
    ):
        method, confidence = draw(LINK_METHODS)
        links.append(
            GraphLink(
                principal_a=principals[a_index].id,
                principal_b=principals[b_index].id,
                method=method,
                confidence=confidence,
            )
        )
    return Graph(principals=principals, grants=grants, resources=resources, links=links)


async def _load_graph(db: AsyncSession, tenant: str, graph: Graph) -> None:
    for p in graph.principals:
        await db.execute(
            text(
                "INSERT INTO principals (id, tenant_id, app_id, external_id, kind, status) "
                "VALUES (:id, :tenant, 'synth', :external_id, 'service', 'active')"
            ),
            {"id": p.id, "tenant": tenant, "external_id": p.external_id},
        )
    for r in graph.resources:
        await db.execute(
            text(
                "INSERT INTO resources (id, tenant_id, app_id, external_id, kind, path, "
                "sensitivity) VALUES (:id, :tenant, 'synth', :ext, 'secret_path', :path, 1)"
            ),
            {"id": r.id, "tenant": tenant, "ext": f"res-{r.id}", "path": r.path},
        )
    for g in graph.grants:
        await db.execute(
            text(
                "INSERT INTO grants (id, tenant_id, principal_id, resource_selector, "
                "scope_raw, capabilities, source_app_id, dedupe_key) "
                "VALUES (:id, :tenant, :pid, :selector, :scope, :caps, 'synth', :key)"
            ),
            {
                "id": g.id,
                "tenant": tenant,
                "pid": g.principal_id,
                "selector": g.resource_selector,
                "scope": g.scope_raw,
                "caps": sorted(g.capabilities),
                "key": str(g.id),
            },
        )
    for link in graph.links:
        await db.execute(
            text(
                "INSERT INTO identity_links (tenant_id, principal_a, principal_b, method, "
                "confidence, evidence_json) "
                "VALUES (:tenant, :a, :b, :method, :confidence, '{}')"
            ),
            {
                "tenant": tenant,
                "a": link.principal_a,
                "b": link.principal_b,
                "method": link.method,
                "confidence": link.confidence,
            },
        )
    await db.commit()


async def _drop_tenant(db: AsyncSession, tenant: str) -> None:
    for table in ("identity_links", "grants", "resources", "principals"):
        await db.execute(text(f"DELETE FROM {table} WHERE tenant_id = :tenant"), {"tenant": tenant})
    await db.commit()


@settings(
    max_examples=40,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(graph=graphs(), depth_cap=st.integers(1, 4), include_fuzzy=st.booleans())
async def test_cte_equals_bfs(
    db: AsyncSession, graph: Graph, depth_cap: int, include_fuzzy: bool
) -> None:
    tenant = f"prop-{uuid.uuid4().hex[:10]}"
    await _load_graph(db, tenant, graph)
    try:
        cte_rows = await compute_reach(db, tenant, depth_cap=depth_cap, include_fuzzy=include_fuzzy)
        bfs_edges = compute_reach_bfs(graph, depth_cap=depth_cap, include_fuzzy=include_fuzzy)

        ext = {p.id: p.external_id for p in graph.principals}
        paths = {r.id: r.path for r in graph.resources}

        cte_map = {
            (ext[row.origin_id], paths[row.resource_id], row.capability): row.confidence
            for row in cte_rows
        }
        bfs_map = {(ext[k[0]], paths[k[1]], k[2]): edge.confidence for k, edge in bfs_edges.items()}
        assert set(cte_map) == set(bfs_map)
        for key, confidence in bfs_map.items():
            assert cte_map[key] == pytest.approx(confidence, abs=1e-12), key

        # Every CTE edge must be explainable: its path replays to its endpoint.
        for row in cte_rows:
            assert row.path, "edge without derivation"
            last = row.path[-1]
            assert last["step"] == "grant"
            assert last["resource"] == paths[row.resource_id]
            assert row.path[0].get("from", ext[row.origin_id]) == ext[row.origin_id]
    finally:
        await _drop_tenant(db, tenant)
