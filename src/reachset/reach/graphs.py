"""Renders derivation paths and reach sets as Mermaid or DOT, for pasting into
an incident doc, a PR description, or a GitHub issue (Mermaid renders natively
in GitHub markdown). Pure string formatting over data reach/engine.py and the
CLI already produce — no new queries, no I/O, and nothing here decides what
counts as reachable.

Two shapes:

- `path_to_mermaid` / `path_to_dot`: one derivation path (`reachset explain`'s
  output) as a small directed graph, one node per hop — identity links,
  impersonation, and the terminal grant, in order.
- `reach_to_mermaid` / `reach_to_dot`: a principal's whole materialized reach
  as a fan-out from the origin to every resource it can touch, grouped by
  app, edges labeled with capability. This is deliberately NOT one subgraph
  per distinct derivation path — at real tenant scale that would be an
  unreadable tangle. It answers "what does this identity touch", which is
  what `reach` reports; "how does one specific edge derive" is `explain`'s
  job and path_to_mermaid/path_to_dot answer it.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ReachEdgeView:
    """The columns `reachset reach` already selects — reused here rather than
    re-querying, so rendering can never disagree with the table it renders."""

    resource: str
    app: str
    capability: str


def _mermaid_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', "&quot;").replace("\n", " ")


def _dot_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def _path_hops(path: Sequence[dict[str, Any]]) -> list[tuple[str, str, str]]:
    """Flatten a derivation path into (from_label, edge_label, to_label)
    triples. Unrecognized step kinds are skipped rather than raising — the
    same defensiveness `cli._render_path` uses, since path_json is data the
    engine wrote and a future step kind should degrade gracefully here too.
    """
    hops: list[tuple[str, str, str]] = []
    for step in path:
        kind = step.get("step")
        if kind == "identity_link":
            hops.append((step["from"], f"{step['method']} {step['confidence']:.2f}", step["to"]))
        elif kind == "impersonate":
            hops.append((step["from"], "impersonate", step["to"]))
        elif kind == "grant":
            hops.append((step["principal"], step["capability"], step["resource"]))
    return hops


def path_to_mermaid(principal_external_id: str, path: Sequence[dict[str, Any]]) -> str:
    hops = _path_hops(path)
    lines = ["flowchart LR"]
    node_ids: dict[str, str] = {}

    def node(label: str) -> str:
        if label not in node_ids:
            node_ids[label] = f"n{len(node_ids)}"
            lines.append(f'    {node_ids[label]}["{_mermaid_escape(label)}"]')
        return node_ids[label]

    node(principal_external_id)
    for from_label, edge_label, to_label in hops:
        lines.append(f"    {node(from_label)} -->|{_mermaid_escape(edge_label)}| {node(to_label)}")
    return "\n".join(lines)


def path_to_dot(principal_external_id: str, path: Sequence[dict[str, Any]]) -> str:
    hops = _path_hops(path)
    lines = ["digraph reach {", "    rankdir=LR;"]
    declared: set[str] = set()

    def declare(label: str) -> None:
        if label not in declared:
            declared.add(label)
            lines.append(f'    "{_dot_escape(label)}";')

    declare(principal_external_id)
    for from_label, edge_label, to_label in hops:
        declare(from_label)
        declare(to_label)
        lines.append(
            f'    "{_dot_escape(from_label)}" -> "{_dot_escape(to_label)}" '
            f'[label="{_dot_escape(edge_label)}"];'
        )
    lines.append("}")
    return "\n".join(lines)


def _grouped_by_app(rows: Sequence[ReachEdgeView]) -> dict[str, dict[str, set[str]]]:
    """app -> resource -> capabilities, deduplicated and stable-ordered by the
    caller iterating dict insertion order (rows already arrive sorted by the
    CLI's own query)."""
    grouped: dict[str, dict[str, set[str]]] = {}
    for row in rows:
        grouped.setdefault(row.app, {}).setdefault(row.resource, set()).add(row.capability)
    return grouped


def reach_to_mermaid(principal_external_id: str, rows: Sequence[ReachEdgeView]) -> str:
    lines = ["flowchart LR", f'    origin["{_mermaid_escape(principal_external_id)}"]']
    counter = 0
    for app, resources in _grouped_by_app(rows).items():
        lines.append(f'    subgraph {_mermaid_escape(app)} ["{_mermaid_escape(app)}"]')
        node_ids = []
        for resource, _caps in resources.items():
            node_id = f"r{counter}"
            counter += 1
            node_ids.append(node_id)
            lines.append(f'        {node_id}["{_mermaid_escape(resource)}"]')
        lines.append("    end")
        for node_id, (_resource, caps) in zip(node_ids, resources.items(), strict=True):
            lines.append(f"    origin -->|{_mermaid_escape(','.join(sorted(caps)))}| {node_id}")
    return "\n".join(lines)


def reach_to_dot(principal_external_id: str, rows: Sequence[ReachEdgeView]) -> str:
    lines = ["digraph reach {", "    rankdir=LR;", f'    "{_dot_escape(principal_external_id)}";']
    counter = 0
    for app, resources in _grouped_by_app(rows).items():
        lines.append(f"    subgraph cluster_{counter} {{")
        lines.append(f'        label="{_dot_escape(app)}";')
        counter += 1
        for resource, caps in resources.items():
            node_id = f"r{counter}"
            counter += 1
            lines.append(f'        {node_id} [label="{_dot_escape(resource)}"];')
            lines.append(
                f'        "{_dot_escape(principal_external_id)}" -> {node_id} '
                f'[label="{_dot_escape(",".join(sorted(caps)))}"];'
            )
        lines.append("    }")
    lines.append("}")
    return "\n".join(lines)
