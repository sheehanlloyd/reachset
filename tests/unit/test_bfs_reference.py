"""The BFS reference implementation, exercised directly.

The property test compares it against the CTE on random graphs; this file pins
the behaviours a random graph rarely produces — a revoked grant, a cycle, and a
depth cap that bites.
"""

import uuid

from reachset.reach.bfs import (
    Graph,
    GraphGrant,
    GraphLink,
    GraphPrincipal,
    GraphResource,
    compute_reach_bfs,
)


def _graph_with_cycle() -> tuple[Graph, dict[str, uuid.UUID]]:
    """a impersonates b, b impersonates a, and b can read a secret."""
    a = GraphPrincipal(id=uuid.uuid4(), external_id="a")
    b = GraphPrincipal(id=uuid.uuid4(), external_id="b")
    resource = GraphResource(id=uuid.uuid4(), path="secret/x", app_id="vault")
    grants = [
        GraphGrant(
            id=uuid.uuid4(),
            principal_id=a.id,
            resource_selector="principal:b",
            capabilities=frozenset({"impersonate"}),
            source_app_id="vault",
        ),
        GraphGrant(
            id=uuid.uuid4(),
            principal_id=b.id,
            resource_selector="principal:a",
            capabilities=frozenset({"impersonate"}),
            source_app_id="vault",
        ),
        GraphGrant(
            id=uuid.uuid4(),
            principal_id=b.id,
            resource_selector="secret/x",
            capabilities=frozenset({"read"}),
            source_app_id="vault",
        ),
    ]
    graph = Graph(principals=[a, b], grants=grants, resources=[resource])
    return graph, {"a": a.id, "b": b.id, "resource": resource.id}


def test_cycles_terminate_and_still_yield_reach() -> None:
    graph, ids = _graph_with_cycle()
    edges = compute_reach_bfs(graph)
    assert (ids["a"], ids["resource"], "read") in edges
    assert (ids["b"], ids["resource"], "read") in edges
    # a reaches it in one hop through b; b holds it directly.
    assert edges[(ids["a"], ids["resource"], "read")].hops == 1
    assert edges[(ids["b"], ids["resource"], "read")].hops == 0


def test_depth_cap_stops_the_walk() -> None:
    graph, ids = _graph_with_cycle()
    edges = compute_reach_bfs(graph, depth_cap=0)
    assert (ids["b"], ids["resource"], "read") in edges  # no hop needed
    assert (ids["a"], ids["resource"], "read") not in edges  # needs one hop


def test_excluded_grants_are_invisible_to_the_walk() -> None:
    """This is what the what-if revocation simulation relies on."""
    graph, _ = _graph_with_cycle()
    terminal = next(g for g in graph.grants if g.resource_selector == "secret/x")
    edges = compute_reach_bfs(graph, exclude_grant_ids=[terminal.id])
    assert edges == {}


def test_origin_filter_limits_the_result() -> None:
    graph, ids = _graph_with_cycle()
    edges = compute_reach_bfs(graph, origin=ids["b"])
    assert {key[0] for key in edges} == {ids["b"]}


def test_a_grant_never_reaches_another_apps_resources() -> None:
    principal = GraphPrincipal(id=uuid.uuid4(), external_id="p")
    vault_resource = GraphResource(id=uuid.uuid4(), path="shared/path", app_id="vault")
    github_resource = GraphResource(id=uuid.uuid4(), path="shared/path", app_id="github")
    grant = GraphGrant(
        id=uuid.uuid4(),
        principal_id=principal.id,
        resource_selector="*",
        capabilities=frozenset({"read"}),
        source_app_id="vault",
    )
    edges = compute_reach_bfs(
        Graph(
            principals=[principal],
            grants=[grant],
            resources=[vault_resource, github_resource],
        )
    )
    assert {key[1] for key in edges} == {vault_resource.id}


def test_fuzzy_links_are_excluded_unless_asked_for_and_then_capped() -> None:
    a = GraphPrincipal(id=uuid.uuid4(), external_id="a")
    b = GraphPrincipal(id=uuid.uuid4(), external_id="b")
    resource = GraphResource(id=uuid.uuid4(), path="secret/x", app_id="vault")
    graph = Graph(
        principals=[a, b],
        grants=[
            GraphGrant(
                id=uuid.uuid4(),
                principal_id=b.id,
                resource_selector="secret/x",
                capabilities=frozenset({"read"}),
                source_app_id="vault",
            )
        ],
        resources=[resource],
        links=[GraphLink(principal_a=a.id, principal_b=b.id, method="fuzzy_name", confidence=0.6)],
    )

    assert (a.id, resource.id, "read") not in compute_reach_bfs(graph)
    with_fuzzy = compute_reach_bfs(graph, include_fuzzy=True)
    assert with_fuzzy[(a.id, resource.id, "read")].confidence == 0.6


def test_impersonate_capability_on_a_resource_path_is_not_a_principal_hop() -> None:
    """Vault's `sudo` maps to the impersonate capability while its selector is
    still a path. That must not be mistaken for a hop into another principal —
    only `principal:` selectors delegate."""
    actor = GraphPrincipal(id=uuid.uuid4(), external_id="root-token")
    other = GraphPrincipal(id=uuid.uuid4(), external_id="victim")
    secret = GraphResource(id=uuid.uuid4(), path="secret/x", app_id="vault")
    graph = Graph(
        principals=[actor, other],
        grants=[
            # sudo over a path: impersonate capability, resource selector
            GraphGrant(
                id=uuid.uuid4(),
                principal_id=actor.id,
                resource_selector="secret/*",
                capabilities=frozenset({"read", "impersonate"}),
                source_app_id="vault",
            ),
            GraphGrant(
                id=uuid.uuid4(),
                principal_id=other.id,
                resource_selector="secret/x",
                capabilities=frozenset({"write"}),
                source_app_id="vault",
            ),
        ],
        resources=[secret],
    )
    edges = compute_reach_bfs(graph)
    # The actor reads the secret directly...
    assert (actor.id, secret.id, "read") in edges
    # ...but does not inherit the other principal's write through a phantom hop.
    assert (actor.id, secret.id, "write") not in edges
