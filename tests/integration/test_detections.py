"""Positive and negative fixtures for the five Phase 3 detections. (The sixth,
dormant privileged NHI, has its own file from Phase 1.)"""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from reachset.detections.concentration import CrossAppConcentration
from reachset.detections.off_hours import OffHoursBulkRead
from reachset.detections.orphaned_grant import OrphanedGrant
from reachset.detections.registry import ALL_DETECTIONS
from reachset.detections.scope_expansion import ScopeExpansion
from reachset.detections.shadow_ai import ShadowAIIntegration, match_vendor
from reachset.ingest.pipeline import upsert_batch
from reachset.models import (
    Capability,
    Event,
    Grant,
    Principal,
    PrincipalKind,
    PrincipalStatus,
    Provenance,
    ReachEdge,
    Resource,
    ResourceKind,
)
from reachset.records import ExtractBatch, GrantRecord, PrincipalRecord

pytestmark = pytest.mark.integration

NOW = datetime(2026, 8, 15, 12, 0, tzinfo=UTC)


async def _mk_principal(
    db: AsyncSession,
    tenant: str,
    external_id: str,
    kind: PrincipalKind,
    *,
    app: str = "vault",
    status: PrincipalStatus = PrincipalStatus.ACTIVE,
    display_name: str | None = None,
) -> Principal:
    p = Principal(
        tenant_id=tenant,
        app_id=app,
        external_id=external_id,
        kind=kind,
        status=status,
        display_name=display_name or external_id,
    )
    db.add(p)
    await db.flush()
    return p


async def _mk_resource(
    db: AsyncSession, tenant: str, path: str, *, app: str, sensitivity: int
) -> Resource:
    r = Resource(
        tenant_id=tenant,
        app_id=app,
        external_id=path,
        kind=ResourceKind.SECRET_PATH if app == "vault" else ResourceKind.REPO,
        path=path,
        sensitivity=sensitivity,
    )
    db.add(r)
    await db.flush()
    return r


async def _mk_edge(
    db: AsyncSession, tenant: str, p: Principal, r: Resource, capability: Capability
) -> None:
    db.add(
        ReachEdge(
            tenant_id=tenant,
            principal_id=p.id,
            resource_id=r.id,
            capability=capability,
            path_json=[{"step": "grant", "resource": r.path}],
            confidence=1.0,
        )
    )


# ------------------------------------------------------------------ orphaned grant


async def test_orphaned_grant_positive_and_negative(db: AsyncSession, tenant: str) -> None:
    svc = await _mk_principal(db, tenant, "svc-runner", PrincipalKind.SERVICE)
    gone = await _mk_principal(
        db, tenant, "user-gone", PrincipalKind.HUMAN, status=PrincipalStatus.DEACTIVATED
    )
    here = await _mk_principal(db, tenant, "user-here", PrincipalKind.HUMAN)

    def grant(granter: Principal, scope: str) -> Grant:
        return Grant(
            tenant_id=tenant,
            principal_id=svc.id,
            resource_selector="secret/data/*",
            scope_raw=scope,
            capabilities=[Capability.ADMIN.value],
            granted_by_principal_id=granter.id,
            source_app_id="vault",
            dedupe_key=uuid.uuid4().hex,
        )

    db.add_all([grant(gone, "policy:a"), grant(here, "policy:b")])
    await db.commit()

    findings = await OrphanedGrant().run(db, tenant, now=NOW)
    assert len(findings) == 1
    assert findings[0].severity == "high"  # admin capability
    assert findings[0].evidence["granter"]["status"] == "deactivated"
    assert findings[0].evidence["scope_raw"] == "policy:a"


# ---------------------------------------------------------------- scope expansion


def _grant_record(caps: set[Capability]) -> GrantRecord:
    return GrantRecord(
        principal_external_id="svc-expander",
        resource_selector="secret/data/x",
        scope_raw="policy:x",
        capabilities=frozenset(caps),
    )


async def test_scope_expansion_positive(db: AsyncSession, tenant: str) -> None:
    batch1 = ExtractBatch(
        principals=[PrincipalRecord(external_id="svc-expander", kind=PrincipalKind.SERVICE)],
        grants=[_grant_record({Capability.READ})],
    )
    await upsert_batch(db, tenant, "vault", batch1)
    await db.commit()

    batch2 = ExtractBatch(grants=[_grant_record({Capability.READ, Capability.ADMIN})])
    await upsert_batch(db, tenant, "vault", batch2)
    await db.commit()

    findings = await ScopeExpansion().run(db, tenant, now=NOW)
    assert len(findings) == 1
    assert "widened" in findings[0].summary
    assert findings[0].evidence["app_id"] == "vault"

    # Replaying the widened batch does not double-report.
    await upsert_batch(db, tenant, "vault", batch2)
    await db.commit()
    assert len(await ScopeExpansion().run(db, tenant, now=NOW)) == 1


async def test_scope_expansion_negative_when_audited(db: AsyncSession, tenant: str) -> None:
    batch1 = ExtractBatch(
        principals=[PrincipalRecord(external_id="svc-expander", kind=PrincipalKind.SERVICE)],
        grants=[_grant_record({Capability.READ})],
    )
    await upsert_batch(db, tenant, "vault", batch1)
    await db.commit()
    widened = ExtractBatch(grants=[_grant_record({Capability.READ, Capability.WRITE})])
    await upsert_batch(db, tenant, "vault", widened)
    # A matching change event in the audit stream within the window.
    db.add(
        Event(
            tenant_id=tenant,
            app_id="vault",
            action="vault.update",
            ts=datetime.now(UTC) - timedelta(hours=2),
            raw_ref=f"audit-{uuid.uuid4().hex}",
            provenance=Provenance.AUDIT_LOG,
        )
    )
    await db.commit()

    assert await ScopeExpansion().run(db, tenant, now=NOW) == []


async def test_capability_shrink_is_not_expansion(db: AsyncSession, tenant: str) -> None:
    await upsert_batch(
        db,
        tenant,
        "vault",
        ExtractBatch(
            principals=[PrincipalRecord(external_id="svc-expander", kind=PrincipalKind.SERVICE)],
            grants=[_grant_record({Capability.READ, Capability.WRITE})],
        ),
    )
    await upsert_batch(db, tenant, "vault", ExtractBatch(grants=[_grant_record({Capability.READ})]))
    await db.commit()
    assert await ScopeExpansion().run(db, tenant, now=NOW) == []


# ------------------------------------------------------- cross-app concentration


async def test_concentration_positive_and_negative(db: AsyncSession, tenant: str) -> None:
    octopus = await _mk_principal(db, tenant, "agent-octopus", PrincipalKind.AGENT)
    modest = await _mk_principal(db, tenant, "svc-modest", PrincipalKind.SERVICE)
    human = await _mk_principal(db, tenant, "user-widest", PrincipalKind.HUMAN)

    r_vault = await _mk_resource(db, tenant, "secret/data/prod/db", app="vault", sensitivity=3)
    r_github = await _mk_resource(db, tenant, "acme/prod-infra", app="github", sensitivity=3)
    r_sf = await _mk_resource(db, tenant, "sobject/Payment", app="salesforce", sensitivity=2)
    r_low = await _mk_resource(db, tenant, "acme/website", app="github", sensitivity=1)

    # positive: three apps at sensitivity >= 2
    for resource in (r_vault, r_github, r_sf):
        await _mk_edge(db, tenant, octopus, resource, Capability.READ)
    # negative: two apps only
    await _mk_edge(db, tenant, modest, r_vault, Capability.READ)
    await _mk_edge(db, tenant, modest, r_sf, Capability.READ)
    # negative: humans are out of scope for this rule
    for resource in (r_vault, r_github, r_sf):
        await _mk_edge(db, tenant, human, resource, Capability.READ)
    # low-sensitivity edges never count
    await _mk_edge(db, tenant, modest, r_low, Capability.READ)
    await db.commit()

    findings = await CrossAppConcentration().run(db, tenant, now=NOW)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.principal_id == octopus.id
    assert finding.severity == "critical"
    assert finding.evidence["app_count"] == 3


# ----------------------------------------------------------------- shadow AI


def test_vendor_matcher() -> None:
    assert match_vendor("Summarize-AI", "installation:42") == "generic-summarizer"
    assert match_vendor(None, "app:openai-connector") == "openai"
    assert match_vendor("Claude for Sheets", "app:123") == "anthropic"
    assert match_vendor("ci-deployer", "installation:41") is None


async def test_shadow_ai_positive_and_negative(db: AsyncSession, tenant: str) -> None:
    ai = await _mk_principal(
        db, tenant, "installation:42", PrincipalKind.APP, app="github", display_name="summarize-ai"
    )
    ci = await _mk_principal(
        db, tenant, "installation:41", PrincipalKind.APP, app="github", display_name="ci-deployer"
    )
    ai_low = await _mk_principal(
        db, tenant, "installation:43", PrincipalKind.APP, app="github", display_name="gpt-notes"
    )
    sensitive = await _mk_resource(db, tenant, "acme/prod-infra", app="github", sensitivity=3)
    public = await _mk_resource(db, tenant, "acme/website", app="github", sensitivity=1)

    await _mk_edge(db, tenant, ai, sensitive, Capability.READ)  # positive
    await _mk_edge(db, tenant, ci, sensitive, Capability.READ)  # not an AI vendor
    await _mk_edge(db, tenant, ai_low, public, Capability.READ)  # AI vendor, low sensitivity
    await db.commit()

    findings = await ShadowAIIntegration().run(db, tenant, now=NOW)
    assert len(findings) == 1
    assert findings[0].principal_id == ai.id
    assert findings[0].evidence["vendor"] == "generic-summarizer"
    assert findings[0].evidence["edges"][0]["resource"] == "acme/prod-infra"


# ------------------------------------------------------------- off-hours bulk read


async def _seed_events(
    db: AsyncSession,
    tenant: str,
    principal: Principal,
    *,
    baseline_daily: int,
    baseline_hours: tuple[int, ...],
    burst: int,
    burst_hour: int,
) -> None:
    rows = []
    for day in range(2, 30):  # baseline period: 28 days before the last 24h
        for i in range(baseline_daily):
            hour = baseline_hours[i % len(baseline_hours)]
            rows.append(
                Event(
                    tenant_id=tenant,
                    app_id="vault",
                    actor_principal_id=principal.id,
                    action="vault.read",
                    ts=(NOW - timedelta(days=day)).replace(hour=hour, minute=i % 60),
                    raw_ref=f"{principal.external_id}-base-{day}-{i}",
                    provenance=Provenance.AUDIT_LOG,
                )
            )
    # burst hours in these tests are all before NOW's hour (12:00 UTC), so the
    # burst lands inside the trailing 24h window.
    assert burst_hour < NOW.hour
    for i in range(burst):
        rows.append(
            Event(
                tenant_id=tenant,
                app_id="vault",
                actor_principal_id=principal.id,
                action="vault.read",
                ts=NOW.replace(hour=burst_hour, minute=i % 60, second=i % 50),
                raw_ref=f"{principal.external_id}-burst-{i}",
                provenance=Provenance.AUDIT_LOG,
            )
        )
    db.add_all(rows)


async def test_off_hours_bulk_read_positive_and_negative(db: AsyncSession, tenant: str) -> None:
    # positive: daytime service suddenly reads 60 objects at 03:00
    burster = await _mk_principal(db, tenant, "svc-burster", PrincipalKind.SERVICE)
    await _seed_events(
        db, tenant, burster, baseline_daily=5, baseline_hours=(9, 10, 11), burst=60, burst_hour=3
    )
    # negative: same burst volume, but inside its usual hours
    routine = await _mk_principal(db, tenant, "svc-night-batch", PrincipalKind.SERVICE)
    await _seed_events(
        db, tenant, routine, baseline_daily=40, baseline_hours=(3, 4), burst=50, burst_hour=3
    )
    # negative: off-hours but tiny volume
    trickle = await _mk_principal(db, tenant, "svc-trickle", PrincipalKind.SERVICE)
    await _seed_events(
        db, tenant, trickle, baseline_daily=5, baseline_hours=(9, 10), burst=3, burst_hour=2
    )
    # negative: humans are out of scope
    person = await _mk_principal(db, tenant, "user-oncall", PrincipalKind.HUMAN)
    await _seed_events(
        db, tenant, person, baseline_daily=5, baseline_hours=(9, 10), burst=60, burst_hour=3
    )
    await db.commit()

    findings = await OffHoursBulkRead().run(db, tenant, now=NOW)
    assert [f.principal_id for f in findings] == [burster.id]
    evidence = findings[0].evidence
    assert evidence["reads_24h"] >= 60
    assert evidence["off_hours_reads"] > 0
    assert 3 not in evidence["baseline_active_hours_utc"]


# -------------------------------------------------------------------- registry


async def test_registry_runs_every_detection(db: AsyncSession, tenant: str) -> None:
    rule_ids = {d.rule_id for d in ALL_DETECTIONS}
    assert rule_ids == {
        "cross_app_concentration",
        "shadow_ai_integration",
        "scope_expansion",
        "dormant_privileged_nhi",
        "orphaned_grant",
        "off_hours_bulk_read",
    }
