"""The CLI, driven in-process.

`main()` returns an exit code rather than calling sys.exit, so every command is
testable without spawning a subprocess — which is also why the exit codes are
worth asserting: they are the contract for using this in CI.
"""

import asyncio
import json
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from reachset import cli
from reachset.models import Capability, Grant, Principal, PrincipalKind, Resource, ResourceKind
from reachset.reach.engine import materialize

pytestmark = pytest.mark.integration

FIXTURES = Path(__file__).parent.parent / "fixtures"
EXAMPLE_INVARIANTS = Path(__file__).parent.parent.parent / "examples" / "invariants.toml"


@pytest.fixture
def cli_env(
    migrated_pg_url: str, pg_engine: object, monkeypatch: pytest.MonkeyPatch
) -> Iterator[None]:
    """Point the CLI's own settings at the test database.

    `pg_engine` is requested purely for its truncation side effect, so each CLI
    test starts from a clean tenant space.
    """
    monkeypatch.setenv("REACHSET_DATABASE_URL", migrated_pg_url)
    monkeypatch.setenv("REACHSET_LOG_LEVEL", "CRITICAL")
    yield


def run(*argv: str) -> int:
    return cli.main(list(argv))


async def run_async(*argv: str) -> int:
    """`main()` owns its own event loop, so an async test has to hand it a
    thread rather than nesting asyncio.run() inside the running loop."""
    return await asyncio.to_thread(cli.main, list(argv))


# ------------------------------------------------------------------ formatting


def test_table_renders_aligned_columns() -> None:
    rendered = cli._table(["A", "LONGER"], [["1", "x"], ["22", "yy"]])
    lines = rendered.splitlines()
    assert lines[0] == "A   LONGER"
    assert lines[1] == "--  ------"
    assert lines[2] == "1   x"


def test_table_handles_no_rows() -> None:
    assert cli._table(["A"], []) == "(no rows)"


def test_truncate() -> None:
    assert cli._truncate("short", 10) == "short"
    assert cli._truncate("abcdefghij", 5) == "abcd…"


def test_render_path_reads_as_a_chain() -> None:
    rendered = cli._render_path(
        [
            {"step": "identity_link", "method": "email_exact", "confidence": 0.95, "to": "e-1"},
            {"step": "impersonate", "to": "svc-2"},
            {
                "step": "grant",
                "capability": "read",
                "scope": "policy:ro",
                "selector": "secret/*",
                "resource": "secret/data/x",
            },
        ]
    )
    assert "email_exact" in rendered
    assert "impersonate" in rendered
    assert rendered.endswith("secret/data/x")


def test_parser_rejects_unknown_command() -> None:
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["nonsense"])


def test_blast_radius_requires_a_subject() -> None:
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["blast-radius", "--tenant", "t"])


# -------------------------------------------------------------------- commands


def test_sync_vault_then_query(cli_env: None, capsys: pytest.CaptureFixture[str]) -> None:
    tenant = f"cli-{uuid.uuid4().hex[:8]}"
    assert (
        run("sync", "--tenant", tenant, "--app", "vault", "--fixtures", str(FIXTURES / "vault"))
        == 0
    )
    assert "principals" in capsys.readouterr().out

    assert run("--json", "reach", "--tenant", tenant, "--principal", "token:acc-null-display") == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload
    assert {row["app"] for row in payload} == {"vault"}
    assert any(row["resource"] == "secret/data/prod/db" for row in payload)


def test_sync_github_and_blast_radius(cli_env: None, capsys: pytest.CaptureFixture[str]) -> None:
    tenant = f"cli-{uuid.uuid4().hex[:8]}"
    assert (
        run("sync", "--tenant", tenant, "--app", "github", "--fixtures", str(FIXTURES / "github"))
        == 0
    )
    capsys.readouterr()

    assert run("blast-radius", "--tenant", tenant, "--principal", "installation:42") == 0
    out = capsys.readouterr().out
    assert "reaches" in out
    assert "acme/prod-infra" in out


def test_sync_rejects_a_missing_fixture_dir(
    cli_env: None, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run("sync", "--tenant", "t", "--app", "vault", "--fixtures", "/nonexistent") == 1
    assert "no routes.json" in capsys.readouterr().err


def test_reach_unknown_principal_errors(cli_env: None, capsys: pytest.CaptureFixture[str]) -> None:
    assert run("reach", "--tenant", "empty", "--principal", "ghost") == 1
    assert "no principal" in capsys.readouterr().err


def test_explain_renders_derivation(cli_env: None, capsys: pytest.CaptureFixture[str]) -> None:
    tenant = f"cli-{uuid.uuid4().hex[:8]}"
    run("sync", "--tenant", tenant, "--app", "vault", "--fixtures", str(FIXTURES / "vault"))
    capsys.readouterr()

    assert (
        run(
            "explain",
            "--tenant",
            tenant,
            "--principal",
            "token:acc-null-display",
            "--resource",
            "secret/data/prod/db",
            "--capability",
            "admin",
        )
        == 0
    )
    out = capsys.readouterr().out
    assert "policy:admin-sudo" in out
    assert "confidence: 1.0" in out


def test_explain_format_mermaid_renders_a_graph(
    cli_env: None, capsys: pytest.CaptureFixture[str]
) -> None:
    tenant = f"cli-{uuid.uuid4().hex[:8]}"
    run("sync", "--tenant", tenant, "--app", "vault", "--fixtures", str(FIXTURES / "vault"))
    capsys.readouterr()

    assert (
        run(
            "explain",
            "--tenant",
            tenant,
            "--principal",
            "token:acc-null-display",
            "--resource",
            "secret/data/prod/db",
            "--capability",
            "admin",
            "--format",
            "mermaid",
        )
        == 0
    )
    out = capsys.readouterr().out
    assert out.startswith("flowchart LR")
    assert "token:acc-null-display" in out
    assert "secret/data/prod/db" in out


def test_explain_format_dot_renders_a_graph(
    cli_env: None, capsys: pytest.CaptureFixture[str]
) -> None:
    tenant = f"cli-{uuid.uuid4().hex[:8]}"
    run("sync", "--tenant", tenant, "--app", "vault", "--fixtures", str(FIXTURES / "vault"))
    capsys.readouterr()

    assert (
        run(
            "explain",
            "--tenant",
            tenant,
            "--principal",
            "token:acc-null-display",
            "--resource",
            "secret/data/prod/db",
            "--capability",
            "admin",
            "--format",
            "dot",
        )
        == 0
    )
    out = capsys.readouterr().out
    assert out.startswith("digraph reach {")
    assert out.rstrip().endswith("}")


def test_reach_format_mermaid_renders_the_whole_fan_out(
    cli_env: None, capsys: pytest.CaptureFixture[str]
) -> None:
    tenant = f"cli-{uuid.uuid4().hex[:8]}"
    run("sync", "--tenant", tenant, "--app", "github", "--fixtures", str(FIXTURES / "github"))
    capsys.readouterr()

    assert (
        run(
            "reach",
            "--tenant",
            tenant,
            "--principal",
            "installation:42",
            "--format",
            "mermaid",
        )
        == 0
    )
    out = capsys.readouterr().out
    assert out.startswith("flowchart LR")
    assert 'subgraph github ["github"]' in out
    assert "acme/prod-infra" in out


def test_explain_missing_edge_errors(cli_env: None, capsys: pytest.CaptureFixture[str]) -> None:
    tenant = f"cli-{uuid.uuid4().hex[:8]}"
    run("sync", "--tenant", tenant, "--app", "vault", "--fixtures", str(FIXTURES / "vault"))
    capsys.readouterr()
    assert (
        run(
            "explain",
            "--tenant",
            tenant,
            "--principal",
            "token:acc-null-display",
            "--resource",
            "nope",
            "--capability",
            "admin",
        )
        == 1
    )
    assert "no admin edge" in capsys.readouterr().err


def test_explain_unknown_principal_errors(
    cli_env: None, capsys: pytest.CaptureFixture[str]
) -> None:
    assert (
        run(
            "explain",
            "--tenant",
            "t",
            "--principal",
            "ghost",
            "--resource",
            "x",
            "--capability",
            "read",
        )
        == 1
    )
    assert "no principal" in capsys.readouterr().err


async def test_detect_exit_code_gates_ci(
    cli_env: None, db: AsyncSession, tenant: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """A tenant with an obvious finding exits 2 under --fail-on-findings, which
    is what makes `reachset detect` usable as a pipeline gate."""
    principal = Principal(
        tenant_id=tenant,
        app_id="github",
        external_id="installation:99",
        kind=PrincipalKind.APP,
        display_name="summarize-ai",
    )
    resource = Resource(
        tenant_id=tenant,
        app_id="github",
        external_id="repo:1",
        kind=ResourceKind.REPO,
        path="acme/prod-infra",
        sensitivity=3,
    )
    db.add_all([principal, resource])
    await db.flush()
    db.add(
        Grant(
            tenant_id=tenant,
            principal_id=principal.id,
            resource_selector="acme/*",
            scope_raw="installation:contents=read",
            capabilities=[Capability.READ.value],
            source_app_id="github",
            dedupe_key=uuid.uuid4().hex,
        )
    )
    await db.flush()
    await materialize(db, tenant)
    await db.commit()

    assert await run_async("detect", "--tenant", tenant) == 0
    assert "shadow_ai_integration" in capsys.readouterr().out

    assert await run_async("detect", "--tenant", tenant, "--fail-on-findings") == 2
    capsys.readouterr()

    # A tenant with nothing to report exits 0 even with the gate on.
    assert await run_async("detect", "--tenant", f"{tenant}-empty", "--fail-on-findings") == 0


async def test_snapshot_and_diff_round_trip(
    cli_env: None, db: AsyncSession, tenant: str, capsys: pytest.CaptureFixture[str]
) -> None:
    principal = Principal(
        tenant_id=tenant,
        app_id="vault",
        external_id="svc-a",
        kind=PrincipalKind.SERVICE,
        display_name="svc-a",
    )
    resource = Resource(
        tenant_id=tenant,
        app_id="vault",
        external_id="secret/data/prod/db",
        kind=ResourceKind.SECRET_PATH,
        path="secret/data/prod/db",
        sensitivity=3,
    )
    db.add_all([principal, resource])
    await db.flush()
    grant = Grant(
        tenant_id=tenant,
        principal_id=principal.id,
        resource_selector="secret/data/prod/*",
        scope_raw="policy:ro",
        capabilities=[Capability.READ.value],
        source_app_id="vault",
        dedupe_key=uuid.uuid4().hex,
    )
    db.add(grant)
    await db.flush()
    await materialize(db, tenant)
    await db.commit()

    assert await run_async("snapshot", "--tenant", tenant, "--label", "before") == 0
    assert "1 edge(s)" in capsys.readouterr().out

    # Duplicate labels are refused rather than silently overwriting history.
    assert await run_async("snapshot", "--tenant", tenant, "--label", "before") == 1
    assert "already exists" in capsys.readouterr().err

    # Widen the grant, re-materialize, snapshot again.
    await db.execute(
        text("UPDATE grants SET capabilities = :caps WHERE id = :id"),
        {"caps": [Capability.READ.value, Capability.WRITE.value], "id": grant.id},
    )
    await materialize(db, tenant)
    await db.commit()
    assert await run_async("snapshot", "--tenant", tenant, "--label", "after") == 0
    capsys.readouterr()

    assert await run_async("snapshot", "--tenant", tenant, "--list") == 0
    listing = capsys.readouterr().out
    assert "before" in listing and "after" in listing

    assert await run_async("diff", "--tenant", tenant, "--from", "before", "--to", "after") == 0
    out = capsys.readouterr().out
    assert "1 edge(s) added" in out

    # The CI gate flips the exit code without changing the output.
    assert (
        await run_async(
            "diff", "--tenant", tenant, "--from", "before", "--to", "after", "--fail-on-change"
        )
        == 2
    )
    capsys.readouterr()
    assert (
        await run_async(
            "diff", "--tenant", tenant, "--from", "before", "--to", "before", "--fail-on-change"
        )
        == 0
    )


def test_snapshot_requires_label_or_list(cli_env: None, capsys: pytest.CaptureFixture[str]) -> None:
    assert run("snapshot", "--tenant", "t") == 1
    assert "--label is required" in capsys.readouterr().err


def test_diff_unknown_label_errors(cli_env: None, capsys: pytest.CaptureFixture[str]) -> None:
    assert run("diff", "--tenant", "t", "--from", "a", "--to", "b") == 1
    assert "no snapshot" in capsys.readouterr().err


async def test_recommend_and_simulate(
    cli_env: None, db: AsyncSession, tenant: str, capsys: pytest.CaptureFixture[str]
) -> None:
    principal = Principal(
        tenant_id=tenant,
        app_id="vault",
        external_id="idle-svc",
        kind=PrincipalKind.SERVICE,
        display_name="idle-svc",
    )
    db.add(principal)
    await db.flush()
    for i in range(3):
        resource = Resource(
            tenant_id=tenant,
            app_id="vault",
            external_id=f"secret/data/prod/{i}",
            kind=ResourceKind.SECRET_PATH,
            path=f"secret/data/prod/{i}",
            sensitivity=3,
        )
        db.add(resource)
    grant = Grant(
        tenant_id=tenant,
        principal_id=principal.id,
        resource_selector="secret/data/prod/*",
        scope_raw="policy:rw",
        capabilities=[Capability.READ.value, Capability.WRITE.value],
        source_app_id="vault",
        dedupe_key=uuid.uuid4().hex,
    )
    db.add(grant)
    await db.flush()
    await materialize(db, tenant)
    await db.commit()

    assert await run_async("recommend", "--tenant", tenant) == 0
    out = capsys.readouterr().out
    assert "idle-svc" in out
    assert "(revoke)" in out  # never used anything

    assert (
        await run_async("--json", "simulate-revoke", "--tenant", tenant, "--grant", str(grant.id))
        == 0
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["removed_edges"] == 6  # 3 resources x read+write
    assert payload["affected_principals"] == ["idle-svc"]


def test_simulate_rejects_a_non_uuid_grant(
    cli_env: None, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run("simulate-revoke", "--tenant", "t", "--grant", "not-a-uuid") == 1
    assert "error" in capsys.readouterr().err


async def test_principal_can_be_addressed_by_row_uuid(
    cli_env: None, db: AsyncSession, tenant: str, capsys: pytest.CaptureFixture[str]
) -> None:
    principal = Principal(
        tenant_id=tenant,
        app_id="vault",
        external_id="svc-uuid",
        kind=PrincipalKind.SERVICE,
    )
    db.add(principal)
    await db.commit()

    assert await run_async("reach", "--tenant", tenant, "--principal", str(principal.id)) == 0
    assert "(no rows)" in capsys.readouterr().out

    # A well-formed UUID that isn't a principal in this tenant still fails.
    assert await run_async("reach", "--tenant", tenant, "--principal", str(uuid.uuid4())) == 1
    assert "no principal" in capsys.readouterr().err


async def test_blast_radius_by_credential_and_its_extras(
    cli_env: None, db: AsyncSession, tenant: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Covers the credential subject, the truncation notice, and the collateral
    line — the parts of the output an operator actually acts on."""
    from reachset.models import Credential, CredentialKind

    owner = Principal(
        tenant_id=tenant,
        app_id="vault",
        external_id="deploy-bot",
        kind=PrincipalKind.AGENT,
        display_name="deploy-bot",
    )
    downstream = Principal(
        tenant_id=tenant,
        app_id="vault",
        external_id="release-svc",
        kind=PrincipalKind.SERVICE,
        display_name="release-svc",
    )
    db.add_all([owner, downstream])
    await db.flush()
    for i in range(3):
        db.add(
            Resource(
                tenant_id=tenant,
                app_id="vault",
                external_id=f"secret/data/prod/{i}",
                kind=ResourceKind.SECRET_PATH,
                path=f"secret/data/prod/{i}",
                sensitivity=3,
            )
        )
    credential = Credential(
        tenant_id=tenant,
        principal_id=owner.id,
        kind=CredentialKind.VAULT_TOKEN,
        external_id="acc-deploy",
    )
    db.add(credential)
    await db.flush()
    impersonation = Grant(
        tenant_id=tenant,
        principal_id=owner.id,
        credential_id=credential.id,
        resource_selector="principal:release-svc",
        scope_raw="policy:sudo",
        capabilities=[Capability.IMPERSONATE.value],
        source_app_id="vault",
        dedupe_key=uuid.uuid4().hex,
    )
    db.add(impersonation)
    db.add(
        Grant(
            tenant_id=tenant,
            principal_id=downstream.id,
            resource_selector="secret/data/prod/*",
            scope_raw="policy:rw",
            capabilities=[Capability.READ.value, Capability.WRITE.value],
            source_app_id="vault",
            dedupe_key=uuid.uuid4().hex,
        )
    )
    await db.flush()
    await materialize(db, tenant)
    await db.commit()

    # Credential subject, with the resource list deliberately truncated.
    assert (
        await run_async(
            "blast-radius", "--tenant", tenant, "--credential", "acc-deploy", "--limit", "1"
        )
        == 0
    )
    out = capsys.readouterr().out
    assert "deploy-bot reaches" in out
    assert "more resources" in out

    # An unknown credential is an error, not an empty report.
    assert await run_async("blast-radius", "--tenant", tenant, "--credential", "nope") == 1
    assert "no credential" in capsys.readouterr().err

    # Revoking the bot's impersonation grant costs the bot its borrowed reach.
    assert (
        await run_async("simulate-revoke", "--tenant", tenant, "--grant", str(impersonation.id))
        == 0
    )
    simulated = capsys.readouterr().out
    assert "removes" in simulated
    assert "secret/data/prod/0" in simulated


async def test_simulate_revoke_reports_collateral_principals(
    cli_env: None, db: AsyncSession, tenant: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Revoking a grant owned by one principal can cost a *different* principal
    its reach. That surprise is the whole reason the command exists, so it gets
    its own line in the output."""
    borrower = Principal(
        tenant_id=tenant,
        app_id="vault",
        external_id="borrower",
        kind=PrincipalKind.AGENT,
        display_name="borrower",
    )
    owner = Principal(
        tenant_id=tenant,
        app_id="vault",
        external_id="owner-svc",
        kind=PrincipalKind.SERVICE,
        display_name="owner-svc",
    )
    resource = Resource(
        tenant_id=tenant,
        app_id="vault",
        external_id="secret/data/prod/db",
        kind=ResourceKind.SECRET_PATH,
        path="secret/data/prod/db",
        sensitivity=3,
    )
    db.add_all([borrower, owner, resource])
    await db.flush()
    db.add(
        Grant(
            tenant_id=tenant,
            principal_id=borrower.id,
            resource_selector="principal:owner-svc",
            scope_raw="policy:sudo",
            capabilities=[Capability.IMPERSONATE.value],
            source_app_id="vault",
            dedupe_key=uuid.uuid4().hex,
        )
    )
    owned = Grant(
        tenant_id=tenant,
        principal_id=owner.id,
        resource_selector="secret/data/prod/*",
        scope_raw="policy:rw",
        capabilities=[Capability.READ.value],
        source_app_id="vault",
        dedupe_key=uuid.uuid4().hex,
    )
    db.add(owned)
    await db.flush()
    await materialize(db, tenant)
    await db.commit()

    assert await run_async("simulate-revoke", "--tenant", tenant, "--grant", str(owned.id)) == 0
    out = capsys.readouterr().out
    assert "collateral: borrower" in out


def test_check_invariants_flags_the_fixture_ai_integration(
    cli_env: None, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """End to end against the real example config shipped in examples/: the
    GitHub fixtures' summarize-ai installation reads sensitive repos, which
    is exactly the shape the vendor rule exists to catch."""
    tenant = f"cli-{uuid.uuid4().hex[:8]}"
    assert (
        run("sync", "--tenant", tenant, "--app", "github", "--fixtures", str(FIXTURES / "github"))
        == 0
    )
    capsys.readouterr()

    sarif_path = tmp_path / "results.sarif"
    exit_code = run(
        "check-invariants",
        "--tenant",
        tenant,
        "--config",
        str(EXAMPLE_INVARIANTS),
        "--sarif",
        str(sarif_path),
        "--fail-on-violation",
    )
    out = capsys.readouterr().out
    assert "no-ai-vendor-sensitive-read" in out
    assert exit_code == 2

    sarif = json.loads(sarif_path.read_text())
    assert sarif["version"] == "2.1.0"
    rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert {"no-ai-vendor-sensitive-read", "nhi-app-sprawl"} <= rule_ids
    assert any(
        result["ruleId"] == "no-ai-vendor-sensitive-read" for result in sarif["runs"][0]["results"]
    )


def test_check_invariants_without_fail_flag_still_exits_zero(
    cli_env: None, capsys: pytest.CaptureFixture[str]
) -> None:
    tenant = f"cli-{uuid.uuid4().hex[:8]}"
    assert (
        run("sync", "--tenant", tenant, "--app", "github", "--fixtures", str(FIXTURES / "github"))
        == 0
    )
    capsys.readouterr()
    assert run("check-invariants", "--tenant", tenant, "--config", str(EXAMPLE_INVARIANTS)) == 0


def test_check_invariants_rejects_a_bad_config(
    cli_env: None, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run("check-invariants", "--tenant", "t", "--config", "/nonexistent.toml") == 1
    assert "error" in capsys.readouterr().err


def test_render_path_ignores_step_kinds_it_does_not_know() -> None:
    """path_json is data written by the engine; a future step type should
    render as nothing rather than crashing an operator's terminal."""
    rendered = cli._render_path(
        [
            {"step": "some-future-step", "detail": "?"},
            {
                "step": "grant",
                "capability": "read",
                "scope": "policy:ro",
                "selector": "secret/*",
                "resource": "secret/data/x",
            },
        ]
    )
    assert rendered.count("-->") == 1
    assert rendered.endswith("secret/data/x")
