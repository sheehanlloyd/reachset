"""Policy-as-code invariants evaluated against real materialized reach."""

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from reachset.analysis.invariants import (
    MaxAppsPerPrincipalRule,
    VendorCapabilitySensitivityRule,
    evaluate,
)
from reachset.models import Capability, Grant, Principal, PrincipalKind, Resource, ResourceKind
from reachset.reach.engine import materialize

pytestmark = pytest.mark.integration


async def _principal(db: AsyncSession, tenant: str, external_id: str, **kw: object) -> Principal:
    kw.setdefault("kind", PrincipalKind.APP)
    principal = Principal(tenant_id=tenant, app_id="github", external_id=external_id, **kw)
    db.add(principal)
    await db.flush()
    return principal


async def _grant_read(
    db: AsyncSession,
    tenant: str,
    principal: Principal,
    resource_path: str,
    *,
    app: str = "github",
    sensitivity: int = 3,
    capabilities: list[str] | None = None,
) -> None:
    resource = Resource(
        tenant_id=tenant,
        app_id=app,
        external_id=resource_path,
        kind=ResourceKind.REPO,
        path=resource_path,
        sensitivity=sensitivity,
    )
    db.add(resource)
    await db.flush()
    db.add(
        Grant(
            tenant_id=tenant,
            principal_id=principal.id,
            resource_selector=resource_path,
            scope_raw="policy:ro",
            capabilities=capabilities or [Capability.READ.value],
            source_app_id=app,
            dedupe_key=uuid.uuid4().hex,
        )
    )
    await db.flush()


async def test_vendor_rule_fires_on_matching_display_name(db: AsyncSession, tenant: str) -> None:
    ai_app = await _principal(db, tenant, "installation:1", display_name="summarize-ai")
    other_app = await _principal(db, tenant, "installation:2", display_name="internal-tool")
    await _grant_read(db, tenant, ai_app, "acme/payments-api", sensitivity=3)
    await _grant_read(db, tenant, other_app, "acme/payments-api-2", sensitivity=3)
    await materialize(db, tenant)
    await db.commit()

    rule = VendorCapabilitySensitivityRule(
        id="no-ai-read",
        description="no AI vendor reads sensitive data",
        principal_patterns=("*summarize-ai*", "*openai*"),
        capability="read",
        min_sensitivity=2,
    )
    violations = await evaluate(db, tenant, [rule])
    assert len(violations) == 1
    assert violations[0].external_id == "installation:1"
    assert violations[0].rule_id == "no-ai-read"


async def test_vendor_rule_is_silent_when_sensitivity_is_below_threshold(
    db: AsyncSession, tenant: str
) -> None:
    ai_app = await _principal(db, tenant, "installation:1", display_name="summarize-ai")
    await _grant_read(db, tenant, ai_app, "acme/low-sensitivity", sensitivity=1)
    await materialize(db, tenant)
    await db.commit()

    rule = VendorCapabilitySensitivityRule(
        id="no-ai-read",
        description="d",
        principal_patterns=("*summarize-ai*",),
        capability="read",
        min_sensitivity=2,
    )
    assert await evaluate(db, tenant, [rule]) == []


async def test_vendor_rule_is_silent_for_write_when_rule_targets_read(
    db: AsyncSession, tenant: str
) -> None:
    ai_app = await _principal(db, tenant, "installation:1", display_name="summarize-ai")
    await _grant_read(
        db, tenant, ai_app, "acme/prod", sensitivity=3, capabilities=[Capability.WRITE.value]
    )
    await materialize(db, tenant)
    await db.commit()

    rule = VendorCapabilitySensitivityRule(
        id="no-ai-read",
        description="d",
        principal_patterns=("*summarize-ai*",),
        capability="read",
        min_sensitivity=1,
    )
    assert await evaluate(db, tenant, [rule]) == []


async def test_max_apps_rule_fires_on_sprawl(db: AsyncSession, tenant: str) -> None:
    svc = await _principal(db, tenant, "svc-1", kind=PrincipalKind.SERVICE)
    await _grant_read(db, tenant, svc, "acme/repo-a", app="github")
    await _grant_read(db, tenant, svc, "secret/data/x", app="vault")
    await _grant_read(db, tenant, svc, "sobject/Custom1", app="salesforce")
    await materialize(db, tenant)
    await db.commit()

    rule = MaxAppsPerPrincipalRule(
        id="app-sprawl",
        description="d",
        principal_kinds=("service",),
        max_apps=2,
    )
    violations = await evaluate(db, tenant, [rule])
    assert len(violations) == 1
    assert violations[0].external_id == "svc-1"
    assert "3 apps" in violations[0].detail


async def test_max_apps_rule_ignores_kinds_not_listed(db: AsyncSession, tenant: str) -> None:
    human = await _principal(db, tenant, "u-1", kind=PrincipalKind.HUMAN)
    await _grant_read(db, tenant, human, "acme/repo-a", app="github")
    await _grant_read(db, tenant, human, "secret/data/x", app="vault")
    await _grant_read(db, tenant, human, "sobject/Custom1", app="salesforce")
    await materialize(db, tenant)
    await db.commit()

    rule = MaxAppsPerPrincipalRule(
        id="app-sprawl", description="d", principal_kinds=("service", "agent"), max_apps=1
    )
    assert await evaluate(db, tenant, [rule]) == []


async def test_multiple_rules_accumulate_violations(db: AsyncSession, tenant: str) -> None:
    ai_app = await _principal(db, tenant, "installation:1", display_name="summarize-ai")
    await _grant_read(db, tenant, ai_app, "acme/payments-api", sensitivity=3)
    svc = await _principal(db, tenant, "svc-1", kind=PrincipalKind.SERVICE)
    await _grant_read(db, tenant, svc, "acme/repo-a", app="github")
    await _grant_read(db, tenant, svc, "secret/data/x", app="vault")
    await _grant_read(db, tenant, svc, "sobject/Custom1", app="salesforce")
    await materialize(db, tenant)
    await db.commit()

    rules = [
        VendorCapabilitySensitivityRule(
            id="no-ai-read",
            description="d",
            principal_patterns=("*summarize-ai*",),
            capability="read",
            min_sensitivity=2,
        ),
        MaxAppsPerPrincipalRule(
            id="app-sprawl", description="d", principal_kinds=("service",), max_apps=2
        ),
    ]
    violations = await evaluate(db, tenant, rules)
    assert {v.rule_id for v in violations} == {"no-ai-read", "app-sprawl"}
