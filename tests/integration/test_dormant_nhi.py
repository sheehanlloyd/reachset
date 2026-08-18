"""Dormant privileged NHI: one positive and one negative fixture, as required
for every detection."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from reachset.detections.dormant_nhi import DormantPrivilegedNHI
from reachset.models import (
    Capability,
    Credential,
    CredentialKind,
    Principal,
    PrincipalKind,
    ReachEdge,
    Resource,
    ResourceKind,
)

pytestmark = pytest.mark.integration

NOW = datetime(2026, 8, 15, tzinfo=UTC)


async def _seed_principal(
    db: AsyncSession,
    tenant: str,
    *,
    external_id: str,
    kind: PrincipalKind,
    last_active_at: datetime | None,
    capability: Capability,
    credential_last_used: datetime | None = None,
    first_seen_days_ago: int = 400,
) -> Principal:
    principal = Principal(
        tenant_id=tenant,
        app_id="vault",
        external_id=external_id,
        kind=kind,
        display_name=external_id,
        last_active_at=last_active_at,
        created_at=NOW - timedelta(days=first_seen_days_ago),
        first_seen_at=NOW - timedelta(days=first_seen_days_ago),
    )
    resource = Resource(
        tenant_id=tenant,
        app_id="vault",
        external_id=f"secret/data/prod/{external_id}",
        kind=ResourceKind.SECRET_PATH,
        path=f"secret/data/prod/{external_id}",
        sensitivity=3,
    )
    db.add_all([principal, resource])
    await db.flush()
    db.add(
        Credential(
            tenant_id=tenant,
            principal_id=principal.id,
            kind=CredentialKind.VAULT_TOKEN,
            external_id=f"acc-{external_id}-{uuid.uuid4().hex[:6]}",
            last_used_at=credential_last_used,
        )
    )
    db.add(
        ReachEdge(
            tenant_id=tenant,
            principal_id=principal.id,
            resource_id=resource.id,
            capability=capability,
            path_json=[{"step": "grant", "selector": "secret/data/prod/*"}],
            confidence=1.0,
        )
    )
    return principal


async def test_positive_dormant_privileged_service(db: AsyncSession, tenant: str) -> None:
    dormant = await _seed_principal(
        db,
        tenant,
        external_id="old-deployer",
        kind=PrincipalKind.SERVICE,
        last_active_at=NOW - timedelta(days=200),
        capability=Capability.WRITE,
    )
    await db.commit()

    findings = await DormantPrivilegedNHI().run(db, tenant, now=NOW)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.principal_id == dormant.id
    assert finding.severity == "high"  # sensitivity-3 resource
    assert "200 days" in finding.summary
    assert finding.evidence["edges"][0]["resource"] == "secret/data/prod/old-deployer"
    assert finding.evidence["edges"][0]["path"]  # derivation travels with the finding


async def test_negative_cases_do_not_fire(db: AsyncSession, tenant: str) -> None:
    # Recently active, privileged: not dormant.
    await _seed_principal(
        db,
        tenant,
        external_id="busy-deployer",
        kind=PrincipalKind.SERVICE,
        last_active_at=NOW - timedelta(days=3),
        capability=Capability.WRITE,
    )
    # Long idle but read-only: not privileged.
    await _seed_principal(
        db,
        tenant,
        external_id="stale-reader",
        kind=PrincipalKind.SERVICE,
        last_active_at=NOW - timedelta(days=300),
        capability=Capability.READ,
    )
    # Human, idle, privileged: humans are out of scope for this rule.
    await _seed_principal(
        db,
        tenant,
        external_id="sabbatical-admin",
        kind=PrincipalKind.HUMAN,
        last_active_at=NOW - timedelta(days=300),
        capability=Capability.ADMIN,
    )
    # Idle principal whose credential was used recently: the credential's
    # activity counts as the principal's.
    await _seed_principal(
        db,
        tenant,
        external_id="cred-active",
        kind=PrincipalKind.AGENT,
        last_active_at=None,
        capability=Capability.DELETE,
        credential_last_used=NOW - timedelta(days=5),
    )
    # Brand new, no activity yet: existed less than the window, not dormant.
    await _seed_principal(
        db,
        tenant,
        external_id="newborn-agent",
        kind=PrincipalKind.AGENT,
        last_active_at=None,
        capability=Capability.WRITE,
        first_seen_days_ago=10,
    )
    await db.commit()

    findings = await DormantPrivilegedNHI().run(db, tenant, now=NOW)
    assert findings == []


async def test_never_used_but_old_fires(db: AsyncSession, tenant: str) -> None:
    await _seed_principal(
        db,
        tenant,
        external_id="forgotten-agent",
        kind=PrincipalKind.AGENT,
        last_active_at=None,
        capability=Capability.ADMIN,
    )
    await db.commit()
    findings = await DormantPrivilegedNHI().run(db, tenant, now=NOW)
    assert len(findings) == 1
    assert "whole recorded life" in findings[0].summary
