"""Least-privilege recommendations: granted reach versus reach actually used."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from reachset.analysis.least_privilege import (
    capabilities_for_action,
    common_path_prefix,
    recommend,
)
from reachset.models import (
    Capability,
    Event,
    Principal,
    PrincipalKind,
    Provenance,
    ReachEdge,
    Resource,
    ResourceKind,
)

pytestmark = pytest.mark.integration

NOW = datetime(2026, 8, 15, 12, 0, tzinfo=UTC)


def test_common_path_prefix() -> None:
    assert common_path_prefix([]) == "*"
    assert common_path_prefix(["a/b/c"]) == "a/b/c"
    assert common_path_prefix(["a/b/c", "a/b/d"]) == "a/b/*"
    assert common_path_prefix(["a/b/c", "a/x/d"]) == "a/*"
    assert common_path_prefix(["a/b", "x/y"]) == "*"


def test_capabilities_for_action() -> None:
    assert capabilities_for_action("vault.read") == frozenset({"read"})
    assert capabilities_for_action("github.git.push") == frozenset({"read", "write"})
    assert capabilities_for_action("vault.delete") == frozenset({"delete"})
    assert capabilities_for_action("vault.login") == frozenset()
    # An unrecognized verb claims nothing rather than guessing.
    assert capabilities_for_action("vault.frobnicate") == frozenset()


async def _seed_principal(
    db: AsyncSession,
    tenant: str,
    external_id: str,
    *,
    kind: PrincipalKind = PrincipalKind.SERVICE,
    granted_paths: list[str],
    capabilities: list[Capability],
    used: list[tuple[str, str]] | None = None,
    sensitivity: int = 3,
) -> Principal:
    """`used` is a list of (path, action) pairs recorded inside the window."""
    used = used or []
    principal = Principal(
        tenant_id=tenant,
        app_id="vault",
        external_id=external_id,
        kind=kind,
        display_name=external_id,
    )
    db.add(principal)
    await db.flush()

    resources: dict[str, Resource] = {}
    for path in granted_paths:
        resource = Resource(
            tenant_id=tenant,
            app_id="vault",
            external_id=f"{external_id}:{path}",
            kind=ResourceKind.SECRET_PATH,
            path=path,
            sensitivity=sensitivity,
        )
        db.add(resource)
        await db.flush()
        resources[path] = resource
        for capability in capabilities:
            db.add(
                ReachEdge(
                    tenant_id=tenant,
                    principal_id=principal.id,
                    resource_id=resource.id,
                    capability=capability,
                    path_json=[{"step": "grant", "resource": path}],
                    confidence=1.0,
                )
            )

    for index, (path, action) in enumerate(used):
        db.add(
            Event(
                tenant_id=tenant,
                app_id="vault",
                actor_principal_id=principal.id,
                target_resource_id=resources[path].id,
                action=action,
                ts=NOW - timedelta(days=1, minutes=index),
                raw_ref=f"{external_id}-{index}-{uuid.uuid4().hex[:8]}",
                provenance=Provenance.AUDIT_LOG,
            )
        )
    return principal


async def test_flags_broad_grant_with_narrow_usage(db: AsyncSession, tenant: str) -> None:
    await _seed_principal(
        db,
        tenant,
        "etl-runner",
        granted_paths=[f"secret/data/prod/team-a/{i}" for i in range(10)],
        capabilities=[Capability.READ, Capability.WRITE, Capability.DELETE],
        used=[
            ("secret/data/prod/team-a/0", "vault.read"),
            ("secret/data/prod/team-a/1", "vault.read"),
        ],
    )
    await db.commit()

    (rec,) = await recommend(db, tenant, now=NOW)
    assert rec.external_id == "etl-runner"
    assert rec.granted_resources == 10
    assert rec.used_resources == 2
    assert rec.unused_ratio == pytest.approx(0.8)
    # Only read was exercised, so write and delete are the unused privileges.
    assert rec.unused_capabilities == ("delete", "write")
    assert rec.used_capabilities == ("read",)
    assert rec.suggested_selector == "secret/data/prod/team-a/*"
    assert rec.severity == "high"  # unused write on sensitivity-3 resources
    assert "80% unused" in rec.summary()
    assert rec.evidence_resources == (
        "secret/data/prod/team-a/0",
        "secret/data/prod/team-a/1",
    )


async def test_never_used_principal_is_told_to_revoke(db: AsyncSession, tenant: str) -> None:
    await _seed_principal(
        db,
        tenant,
        "forgotten-svc",
        granted_paths=["secret/data/prod/x", "secret/data/prod/y"],
        capabilities=[Capability.READ],
        used=[],
    )
    await db.commit()

    (rec,) = await recommend(db, tenant, now=NOW)
    assert rec.events_observed == 0
    assert rec.used_resources == 0
    assert rec.suggested_selector == "(revoke)"
    assert "has not touched any of them" in rec.summary()


async def test_well_scoped_principal_is_not_reported(db: AsyncSession, tenant: str) -> None:
    """Uses everything it holds, with no unused capability: nothing to say."""
    await _seed_principal(
        db,
        tenant,
        "tidy-svc",
        granted_paths=["secret/data/prod/a", "secret/data/prod/b"],
        capabilities=[Capability.READ],
        used=[
            ("secret/data/prod/a", "vault.read"),
            ("secret/data/prod/b", "vault.read"),
        ],
    )
    await db.commit()
    assert await recommend(db, tenant, now=NOW) == []


async def test_humans_are_out_of_scope(db: AsyncSession, tenant: str) -> None:
    await _seed_principal(
        db,
        tenant,
        "a-person",
        kind=PrincipalKind.HUMAN,
        granted_paths=[f"secret/data/prod/{i}" for i in range(5)],
        capabilities=[Capability.ADMIN],
        used=[],
    )
    await db.commit()
    assert await recommend(db, tenant, now=NOW) == []


async def test_usage_outside_the_window_does_not_count(db: AsyncSession, tenant: str) -> None:
    principal = await _seed_principal(
        db,
        tenant,
        "seasonal-svc",
        granted_paths=["secret/data/prod/a"],
        capabilities=[Capability.READ],
        used=[],
    )
    resource_id = (
        await db.execute(
            text("SELECT id FROM resources WHERE tenant_id = :t LIMIT 1"), {"t": tenant}
        )
    ).scalar_one()
    db.add(
        Event(
            tenant_id=tenant,
            app_id="vault",
            actor_principal_id=principal.id,
            target_resource_id=resource_id,
            action="vault.read",
            ts=NOW - timedelta(days=200),
            raw_ref=f"old-{uuid.uuid4().hex[:8]}",
            provenance=Provenance.AUDIT_LOG,
        )
    )
    await db.commit()

    (rec,) = await recommend(db, tenant, now=NOW, window_days=90)
    assert rec.events_observed == 0

    # Widen the window past the event and it stops being a finding.
    assert await recommend(db, tenant, now=NOW, window_days=365) == []


async def test_severity_ordering_puts_privileged_first(db: AsyncSession, tenant: str) -> None:
    await _seed_principal(
        db,
        tenant,
        "low-risk",
        granted_paths=[f"secret/data/dev/{i}" for i in range(4)],
        capabilities=[Capability.READ],
        used=[("secret/data/dev/0", "vault.read")],
        sensitivity=0,
    )
    await _seed_principal(
        db,
        tenant,
        "high-risk",
        granted_paths=[f"secret/data/prod/{i}" for i in range(4)],
        capabilities=[Capability.READ, Capability.ADMIN],
        used=[("secret/data/prod/0", "vault.read")],
        sensitivity=3,
    )
    await db.commit()

    recs = await recommend(db, tenant, now=NOW)
    assert [r.external_id for r in recs] == ["high-risk", "low-risk"]
    assert recs[0].severity == "high"
    # read-only, insensitive, and not extreme enough to clear the 90% bar
    assert recs[1].severity == "low"
    payload = recs[0].as_dict()
    assert payload["unused_capabilities"] == ["admin"]
    assert payload["max_sensitivity_granted"] == 3


async def test_empty_tenant_returns_nothing(db: AsyncSession, tenant: str) -> None:
    assert await recommend(db, tenant, now=NOW) == []


def test_unused_ratio_is_zero_when_nothing_is_granted() -> None:
    """Guard against a divide-by-zero on a principal with no reach at all."""
    from reachset.analysis.least_privilege import Recommendation

    rec = Recommendation(
        principal_id=uuid.uuid4(),
        external_id="empty",
        display_name=None,
        kind="service",
        granted_resources=0,
        used_resources=0,
        granted_capabilities=(),
        used_capabilities=(),
        unused_capabilities=(),
        suggested_selector="(revoke)",
        max_sensitivity_granted=0,
        max_sensitivity_used=0,
        window_days=90,
        events_observed=0,
        evidence_resources=(),
    )
    assert rec.unused_ratio == 0.0
    assert rec.severity == "low"


def test_common_prefix_of_identical_paths_is_that_path() -> None:
    """Every segment matches, so the scan runs to the end rather than breaking
    early — the boundary case of the prefix walk."""
    assert common_path_prefix(["a/b/c", "a/b/c"]) == "a/b/c/*"
