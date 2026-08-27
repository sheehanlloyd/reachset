"""Owns the `reachset` command-line interface.

Every subcommand is a thin shell over a library function — the CLI parses,
formats, and exits with a meaningful status code; it never contains analysis
logic of its own. That split is why the commands are testable without a
subprocess: `main(["reach", "--tenant", "t"])` returns an exit code.

Exit codes follow the convention that makes this usable in CI:
    0  success, nothing notable found
    1  usage or runtime error
    2  the command found something the caller asked to be told about
       (`detect --fail-on-findings`, `diff --fail-on-change`)

Built on argparse rather than a CLI framework: the dependency isn't worth it
for ten subcommands, and argparse's `--help` output is what people expect.
"""

import argparse
import asyncio
import json
import sys
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from reachset.analysis import blast, invariants, least_privilege, snapshots
from reachset.config import load_settings
from reachset.db import make_engine, make_session_factory, session_scope
from reachset.detections.registry import run_all
from reachset.logging import configure_logging
from reachset.reach import graphs

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_FOUND = 2

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


# ----------------------------------------------------------------- formatting


def _table(headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    """Minimal fixed-width table. Cells are stringified and never wrapped —
    truncation belongs to the caller, which knows what matters in each column."""
    if not rows:
        return "(no rows)"
    cells = [[str(c) for c in row] for row in rows]
    widths = [len(h) for h in headers]
    for row in cells:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)).rstrip()
    rule = "  ".join("-" * widths[i] for i in range(len(headers)))
    body = [
        "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)).rstrip() for row in cells
    ]
    return "\n".join([line, rule, *body])


def _truncate(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[: limit - 1] + "…"


def _emit(payload: dict[str, Any] | list[Any], as_json: bool, human: str) -> None:
    print(json.dumps(payload, indent=2, default=str) if as_json else human)


def _render_path(path: list[dict[str, Any]]) -> str:
    """One derivation rendered as an arrow chain, for terminal reading."""
    parts: list[str] = []
    for step in path:
        kind = step.get("step")
        if kind == "identity_link":
            parts.append(f"--[{step['method']} {step['confidence']}]--> {step['to']}")
        elif kind == "impersonate":
            parts.append(f"--[impersonate]--> {step['to']}")
        elif kind == "grant":
            parts.append(
                f"--[{step['capability']} via {step['scope']} ({step['selector']})]--> "
                f"{step['resource']}"
            )
    return " ".join(parts)


# ------------------------------------------------------------------- plumbing


async def _with_session(func: Any, *args: Any, **kwargs: Any) -> int:
    settings = load_settings()
    configure_logging(settings.log_level)
    engine = make_engine(settings.database_url)
    factory = make_session_factory(engine)
    try:
        async with session_scope(factory) as session:
            return await func(session, *args, **kwargs)  # type: ignore[no-any-return]
    finally:
        await engine.dispose()


async def _resolve_principal(
    session: AsyncSession, tenant: str, identifier: str
) -> uuid.UUID | None:
    """Accept either a row UUID or an app-scoped external id, because nobody
    memorizes UUIDs but everybody can copy an external id out of a report."""
    try:
        candidate = uuid.UUID(identifier)
    except ValueError:
        candidate = None
    if candidate is not None:
        found = (
            await session.execute(
                text("SELECT id FROM principals WHERE tenant_id = :t AND id = :i"),
                {"t": tenant, "i": candidate},
            )
        ).scalar_one_or_none()
        if found is not None:
            return candidate
    return (
        await session.execute(
            text("SELECT id FROM principals WHERE tenant_id = :t AND external_id = :e"),
            {"t": tenant, "e": identifier},
        )
    ).scalar_one_or_none()


# ------------------------------------------------------------------- commands


async def _cmd_reach(session: AsyncSession, args: argparse.Namespace) -> int:
    principal_id = await _resolve_principal(session, args.tenant, args.principal)
    if principal_id is None:
        print(f"error: no principal {args.principal!r} in tenant {args.tenant!r}", file=sys.stderr)
        return EXIT_ERROR

    rows = (
        await session.execute(
            text(
                "SELECT res.path, res.app_id, res.sensitivity, re.capability, re.confidence "
                "FROM reach_edges re JOIN resources res ON res.id = re.resource_id "
                "WHERE re.tenant_id = :t AND re.principal_id = :p "
                "ORDER BY res.sensitivity DESC, res.path, re.capability LIMIT :n"
            ),
            {"t": args.tenant, "p": principal_id, "n": args.limit},
        )
    ).all()

    if args.format in ("mermaid", "dot"):
        edges = [
            graphs.ReachEdgeView(resource=r.path, app=r.app_id, capability=r.capability)
            for r in rows
        ]
        render = graphs.reach_to_mermaid if args.format == "mermaid" else graphs.reach_to_dot
        print(render(args.principal, edges))
        return EXIT_OK

    payload = [
        {
            "resource": r.path,
            "app": r.app_id,
            "sensitivity": r.sensitivity,
            "capability": r.capability,
            "confidence": r.confidence,
        }
        for r in rows
    ]
    human = _table(
        ["RESOURCE", "APP", "SENS", "CAPABILITY", "CONF"],
        [
            [_truncate(r.path, 60), r.app_id, r.sensitivity, r.capability, f"{r.confidence:.2f}"]
            for r in rows
        ],
    )
    _emit(payload, args.json, human)
    return EXIT_OK


async def _cmd_explain(session: AsyncSession, args: argparse.Namespace) -> int:
    principal_id = await _resolve_principal(session, args.tenant, args.principal)
    if principal_id is None:
        print(f"error: no principal {args.principal!r}", file=sys.stderr)
        return EXIT_ERROR
    row = (
        await session.execute(
            text(
                "SELECT re.path_json, re.confidence FROM reach_edges re "
                "JOIN resources res ON res.id = re.resource_id "
                "WHERE re.tenant_id = :t AND re.principal_id = :p AND res.path = :r "
                "AND re.capability = :c"
            ),
            {"t": args.tenant, "p": principal_id, "r": args.resource, "c": args.capability},
        )
    ).one_or_none()
    if row is None:
        print(
            f"no {args.capability} edge from {args.principal} to {args.resource}",
            file=sys.stderr,
        )
        return EXIT_ERROR

    if args.format in ("mermaid", "dot"):
        render = graphs.path_to_mermaid if args.format == "mermaid" else graphs.path_to_dot
        print(render(args.principal, row.path_json))
        return EXIT_OK

    payload = {
        "principal": args.principal,
        "resource": args.resource,
        "capability": args.capability,
        "confidence": row.confidence,
        "derivation": row.path_json,
    }
    human = "\n".join(
        [
            f"{args.principal} {_render_path(row.path_json)}",
            f"confidence: {row.confidence}",
        ]
    )
    _emit(payload, args.json, human)
    return EXIT_OK


async def _cmd_detect(session: AsyncSession, args: argparse.Namespace) -> int:
    findings = await run_all(session, args.tenant, now=datetime.now(UTC))
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    payload = [f.as_dict() for f in findings]
    human = _table(
        ["SEVERITY", "RULE", "SUMMARY"],
        [[f.severity, f.rule_id, _truncate(f.summary, 88)] for f in findings],
    )
    _emit(payload, args.json, human)
    if findings and args.fail_on_findings:
        return EXIT_FOUND
    return EXIT_OK


async def _cmd_blast(session: AsyncSession, args: argparse.Namespace) -> int:
    if args.credential:
        report = await blast.blast_radius_for_credential(
            session, args.tenant, args.credential, limit=args.limit
        )
        missing = f"credential {args.credential!r}"
    else:
        principal_id = await _resolve_principal(session, args.tenant, args.principal)
        report = (
            None
            if principal_id is None
            else await blast.blast_radius_for_principal(
                session, args.tenant, principal_id, limit=args.limit
            )
        )
        missing = f"principal {args.principal!r}"
    if report is None:
        print(f"error: no {missing} in tenant {args.tenant!r}", file=sys.stderr)
        return EXIT_ERROR

    human = "\n".join(
        [
            report.headline(),
            "",
            _table(
                ["SCORE", "RESOURCE", "APP", "SENS", "CAPABILITIES"],
                [
                    [
                        r.score,
                        _truncate(r.path, 52),
                        r.app_id,
                        r.sensitivity,
                        ",".join(r.capabilities),
                    ]
                    for r in report.top_resources
                ],
            ),
        ]
    )
    if report.truncated:
        human += f"\n\n(+{report.truncated} more resources; raise --limit to see them)"
    _emit(report.as_dict(), args.json, human)
    return EXIT_OK


async def _cmd_simulate(session: AsyncSession, args: argparse.Namespace) -> int:
    try:
        grant_ids = [uuid.UUID(g) for g in args.grant]
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    impact = await blast.simulate_revocation(session, args.tenant, grant_ids)
    human = "\n".join(
        [
            impact.headline(),
            "",
            _table(
                ["REMOVED RESOURCE"],
                [[_truncate(r, 80)] for r in impact.removed_resources[:20]],
            ),
        ]
    )
    if impact.collateral:
        human += "\n\ncollateral: " + ", ".join(impact.collateral)
    if impact.still_reachable_resources:
        human += "\n\nstill reachable another way: " + ", ".join(
            impact.still_reachable_resources[:10]
        )
    _emit(impact.as_dict(), args.json, human)
    return EXIT_OK


async def _cmd_recommend(session: AsyncSession, args: argparse.Namespace) -> int:
    recs = await least_privilege.recommend(
        session, args.tenant, now=datetime.now(UTC), window_days=args.window
    )
    payload = [r.as_dict() for r in recs]
    human = _table(
        ["SEVERITY", "PRINCIPAL", "GRANTED", "USED", "UNUSED CAPS", "SUGGESTED SELECTOR"],
        [
            [
                r.severity,
                _truncate(r.display_name or r.external_id, 28),
                r.granted_resources,
                r.used_resources,
                ",".join(r.unused_capabilities) or "-",
                _truncate(r.suggested_selector, 34),
            ]
            for r in recs
        ],
    )
    _emit(payload, args.json, human)
    return EXIT_OK


async def _cmd_snapshot(session: AsyncSession, args: argparse.Namespace) -> int:
    if args.list:
        snaps = await snapshots.list_snapshots(session, args.tenant)
        _emit(
            [s.as_dict() for s in snaps],
            args.json,
            _table(
                ["LABEL", "EDGES", "DIGEST"],
                [[s.label, s.edge_count, s.digest[:12]] for s in snaps],
            ),
        )
        return EXIT_OK
    if not args.label:
        print("error: --label is required unless --list is given", file=sys.stderr)
        return EXIT_ERROR
    try:
        snap = await snapshots.take_snapshot(session, args.tenant, args.label)
    except snapshots.SnapshotExistsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    _emit(
        snap.as_dict(),
        args.json,
        f"snapshot {snap.label!r}: {snap.edge_count} edge(s), digest {snap.digest[:12]}",
    )
    return EXIT_OK


async def _cmd_diff(session: AsyncSession, args: argparse.Namespace) -> int:
    try:
        result = await snapshots.diff_snapshots(
            session, args.tenant, args.from_label, args.to_label
        )
    except KeyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    rows: list[tuple[str, snapshots.EdgeChange]] = (
        [("+", e) for e in result.added]
        + [("-", e) for e in result.removed]
        + [("~", e) for e in result.changed]
    )
    human = "\n".join(
        [
            result.headline(),
            "",
            _table(
                ["", "PRINCIPAL", "RESOURCE", "CAP", "SENS"],
                [
                    [
                        sign,
                        _truncate(e.principal, 26),
                        _truncate(e.resource, 46),
                        e.capability,
                        e.sensitivity,
                    ]
                    for sign, e in rows[:60]
                ],
            ),
        ]
    )
    _emit(result.as_dict(), args.json, human)
    if args.fail_on_change and not result.is_empty:
        return EXIT_FOUND
    return EXIT_OK


async def _cmd_invariants(session: AsyncSession, args: argparse.Namespace) -> int:
    config_path = Path(args.config)
    try:
        rules = invariants.load_rules(config_path)
    except invariants.InvariantConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    violations = await invariants.evaluate(session, args.tenant, rules)
    payload = [v.as_dict() for v in violations]
    human = _table(
        ["SEVERITY", "RULE", "DETAIL"],
        [[v.severity, v.rule_id, _truncate(v.detail, 88)] for v in violations],
    )
    _emit(payload, args.json, human)

    if args.sarif:
        sarif_report = invariants.to_sarif(violations, rules, str(config_path))
        await asyncio.to_thread(
            Path(args.sarif).write_text, json.dumps(sarif_report, indent=2) + "\n"
        )

    if violations and args.fail_on_violation:
        return EXIT_FOUND
    return EXIT_OK


async def _cmd_sync(session: AsyncSession, args: argparse.Namespace) -> int:
    """Fixture-backed sync. Live sync runs through the worker, which owns rate
    limiting and dead-lettering; this exists to load a demo tenant in one step."""
    from reachset.connectors.transports import FixtureTransport
    from reachset.ingest.pipeline import upsert_batch
    from reachset.linking.linker import link_tenant
    from reachset.reach.engine import materialize

    fixture_dir = Path(args.fixtures)
    if not (fixture_dir / "routes.json").exists():
        print(f"error: no routes.json under {fixture_dir}", file=sys.stderr)
        return EXIT_ERROR

    transport = FixtureTransport(fixture_dir)
    if args.app == "vault":
        from reachset.connectors.vault.connector import VaultConnector

        audit = fixture_dir / "audit_sample.jsonl"
        connector = VaultConnector(
            transport,
            read_audit_lines=(lambda: audit.read_text().splitlines()) if audit.exists() else None,
        )
        batch = await connector.sync()
    else:
        from reachset.connectors.github.connector import GitHubConnector

        batch = await GitHubConnector(transport, org=args.org).sync()

    stats = await upsert_batch(session, args.tenant, args.app, batch)
    await link_tenant(session, args.tenant)
    edges = await materialize(session, args.tenant)
    payload = {"app": args.app, "tenant": args.tenant, **stats.as_dict(), "reach_edges": edges}
    human = _table(["METRIC", "COUNT"], [[k, v] for k, v in payload.items() if isinstance(v, int)])
    _emit(payload, args.json, human)
    return EXIT_OK


# --------------------------------------------------------------------- parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reachset",
        description="Effective reachability for human and non-human identities.",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    sub = parser.add_subparsers(dest="command", required=True)

    def tenant_arg(p: argparse.ArgumentParser) -> None:
        p.add_argument("--tenant", required=True, help="tenant id")

    p_sync = sub.add_parser("sync", help="ingest a connector's fixtures and compute reach")
    tenant_arg(p_sync)
    p_sync.add_argument("--app", choices=("vault", "github"), required=True)
    p_sync.add_argument("--fixtures", required=True, help="directory holding routes.json")
    p_sync.add_argument("--org", default="acme", help="GitHub org (github only)")
    p_sync.set_defaults(func=_cmd_sync)

    p_reach = sub.add_parser("reach", help="what a principal can reach")
    tenant_arg(p_reach)
    p_reach.add_argument("--principal", required=True, help="external id or row UUID")
    p_reach.add_argument("--limit", type=int, default=50)
    p_reach.add_argument(
        "--format",
        choices=("table", "mermaid", "dot"),
        default="table",
        help="mermaid/dot render the whole reach set as a graph instead of a table",
    )
    p_reach.set_defaults(func=_cmd_reach)

    p_explain = sub.add_parser("explain", help="why a principal can reach a resource")
    tenant_arg(p_explain)
    p_explain.add_argument("--principal", required=True)
    p_explain.add_argument("--resource", required=True)
    p_explain.add_argument("--capability", required=True)
    p_explain.add_argument(
        "--format",
        choices=("table", "mermaid", "dot"),
        default="table",
        help="mermaid/dot render the derivation path as a graph instead of text",
    )
    p_explain.set_defaults(func=_cmd_explain)

    p_detect = sub.add_parser("detect", help="run every detection over a tenant")
    tenant_arg(p_detect)
    p_detect.add_argument(
        "--fail-on-findings",
        action="store_true",
        help=f"exit {EXIT_FOUND} when anything fires (for CI gates)",
    )
    p_detect.set_defaults(func=_cmd_detect)

    p_blast = sub.add_parser("blast-radius", help="what a compromised identity reaches")
    tenant_arg(p_blast)
    group = p_blast.add_mutually_exclusive_group(required=True)
    group.add_argument("--principal", help="external id or row UUID")
    group.add_argument("--credential", help="credential external id (e.g. a Vault accessor)")
    p_blast.add_argument("--limit", type=int, default=blast.TOP_RESOURCES)
    p_blast.set_defaults(func=_cmd_blast)

    p_sim = sub.add_parser("simulate-revoke", help="what reach disappears if grants are revoked")
    tenant_arg(p_sim)
    p_sim.add_argument("--grant", action="append", required=True, help="grant UUID (repeatable)")
    p_sim.set_defaults(func=_cmd_simulate)

    p_rec = sub.add_parser("recommend", help="least-privilege recommendations")
    tenant_arg(p_rec)
    p_rec.add_argument("--window", type=int, default=least_privilege.DEFAULT_WINDOW_DAYS)
    p_rec.set_defaults(func=_cmd_recommend)

    p_snap = sub.add_parser("snapshot", help="capture or list reach snapshots")
    tenant_arg(p_snap)
    p_snap.add_argument("--label", help="snapshot name")
    p_snap.add_argument("--list", action="store_true", help="list snapshots instead of taking one")
    p_snap.set_defaults(func=_cmd_snapshot)

    p_diff = sub.add_parser("diff", help="diff two reach snapshots")
    tenant_arg(p_diff)
    p_diff.add_argument("--from", dest="from_label", required=True)
    p_diff.add_argument("--to", dest="to_label", required=True)
    p_diff.add_argument(
        "--fail-on-change",
        action="store_true",
        help=f"exit {EXIT_FOUND} when the diff is non-empty",
    )
    p_diff.set_defaults(func=_cmd_diff)

    p_inv = sub.add_parser("check-invariants", help="evaluate policy-as-code invariants over reach")
    tenant_arg(p_inv)
    p_inv.add_argument("--config", required=True, help="TOML file of [[rule]] invariants")
    p_inv.add_argument("--sarif", help="write SARIF 2.1.0 results to this path")
    p_inv.add_argument(
        "--fail-on-violation",
        action="store_true",
        help=f"exit {EXIT_FOUND} when any invariant is violated (for CI gates)",
    )
    p_inv.set_defaults(func=_cmd_invariants)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return asyncio.run(_with_session(args.func, args))
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover - module entry point
    sys.exit(main())
