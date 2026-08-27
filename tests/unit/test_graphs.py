"""Mermaid/DOT rendering — pure string formatting, no database."""

from reachset.reach.graphs import (
    ReachEdgeView,
    path_to_dot,
    path_to_mermaid,
    reach_to_dot,
    reach_to_mermaid,
)

GRANT_ONLY_PATH = [
    {
        "step": "grant",
        "principal": "token:acc-1",
        "scope": "policy:ro",
        "selector": "secret/data/prod/*",
        "resource": "secret/data/prod/db",
        "capability": "read",
    }
]

LINKED_PATH = [
    {
        "step": "identity_link",
        "method": "email_exact",
        "confidence": 0.95,
        "from": "user:502",
        "to": "entity-jortega",
    },
    {
        "step": "grant",
        "principal": "entity-jortega",
        "scope": "policy:payments-ro",
        "selector": "secret/data/prod/*",
        "resource": "secret/data/prod/payments",
        "capability": "read",
    },
]

IMPERSONATE_PATH = [
    {"step": "impersonate", "grant_id": "g1", "from": "svc-a", "to": "svc-b", "selector": "s"},
    {
        "step": "grant",
        "principal": "svc-b",
        "scope": "policy:rw",
        "selector": "secret/*",
        "resource": "secret/x",
        "capability": "write",
    },
]


def test_path_to_mermaid_single_grant_hop() -> None:
    out = path_to_mermaid("token:acc-1", GRANT_ONLY_PATH)
    assert out.startswith("flowchart LR")
    assert 'n0["token:acc-1"]' in out
    assert 'n1["secret/data/prod/db"]' in out
    assert "n0 -->|read| n1" in out


def test_path_to_mermaid_identity_link_then_grant() -> None:
    out = path_to_mermaid("user:502", LINKED_PATH)
    assert "user:502" in out
    assert "entity-jortega" in out
    assert "email_exact 0.95" in out
    assert "secret/data/prod/payments" in out
    # three distinct nodes: origin, linked entity, resource
    assert out.count('["') == 3


def test_path_to_mermaid_impersonate_hop() -> None:
    out = path_to_mermaid("svc-a", IMPERSONATE_PATH)
    assert "impersonate" in out
    assert "svc-b" in out
    assert "secret/x" in out


def test_path_to_mermaid_reuses_the_origin_node_for_the_grant_step() -> None:
    """The grant step's `principal` field is the same identity as the path's
    origin at depth 0 - that must resolve to one node declaration, not two,
    or Mermaid would see a redeclared node id."""
    path = [
        {
            "step": "grant",
            "principal": "p",
            "scope": "s",
            "selector": "*",
            "resource": "r",
            "capability": "read",
        }
    ]
    out = path_to_mermaid("p", path)
    assert out.count('["p"]') == 1


def test_path_to_mermaid_escapes_quotes_and_newlines() -> None:
    path = [
        {
            "step": "grant",
            "principal": 'weird"name',
            "scope": "s",
            "selector": "*",
            "resource": "r\nwith\nnewlines",
            "capability": "read",
        }
    ]
    out = path_to_mermaid('weird"name', path)
    assert 'n0["weird&quot;name"]' in out
    assert "r with newlines" in out
    assert "\nwith\n" not in out


def test_path_to_dot_single_grant_hop() -> None:
    out = path_to_dot("token:acc-1", GRANT_ONLY_PATH)
    assert out.startswith("digraph reach {")
    assert out.endswith("}")
    assert '"token:acc-1" -> "secret/data/prod/db" [label="read"];' in out


def test_path_to_dot_escapes_quotes_and_backslashes() -> None:
    path = [
        {
            "step": "grant",
            "principal": 'a"b\\c',
            "scope": "s",
            "selector": "*",
            "resource": "r",
            "capability": "read",
        }
    ]
    out = path_to_dot('a"b\\c', path)
    assert '"a\\"b\\\\c"' in out


def test_path_hops_skips_unknown_step_kinds() -> None:
    path = [
        {"step": "some-future-step", "detail": "?"},
        {
            "step": "grant",
            "principal": "p",
            "scope": "s",
            "selector": "*",
            "resource": "r",
            "capability": "read",
        },
    ]
    out = path_to_mermaid("p", path)
    assert out.count("-->") == 1


def test_reach_to_mermaid_groups_by_app_and_dedupes_capabilities() -> None:
    rows = [
        ReachEdgeView(resource="acme/repo", app="github", capability="read"),
        ReachEdgeView(resource="acme/repo", app="github", capability="write"),
        ReachEdgeView(resource="secret/data/x", app="vault", capability="read"),
    ]
    out = reach_to_mermaid("installation:42", rows)
    assert 'origin["installation:42"]' in out
    assert 'subgraph github ["github"]' in out
    assert 'subgraph vault ["vault"]' in out
    assert "read,write" in out  # sorted, deduped, one edge for acme/repo
    assert out.count("-->") == 2  # one edge per distinct resource, not per row


def test_reach_to_mermaid_with_no_rows_is_just_the_origin() -> None:
    out = reach_to_mermaid("svc-idle", [])
    assert out == 'flowchart LR\n    origin["svc-idle"]'


def test_reach_to_dot_groups_by_app_in_clusters() -> None:
    rows = [
        ReachEdgeView(resource="acme/repo", app="github", capability="read"),
        ReachEdgeView(resource="secret/data/x", app="vault", capability="admin"),
    ]
    out = reach_to_dot("installation:42", rows)
    assert out.count("subgraph cluster_") == 2
    assert 'label="github";' in out
    assert 'label="vault";' in out
    assert '[label="admin"];' in out
