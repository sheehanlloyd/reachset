"""Blast radius and what-if revocation.

The scenario under test is the one an IR responder actually has: a deploy token
whose reach runs through an impersonation chain, so revoking the obvious grant
does not remove the obvious access.
"""

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from reachset.analysis import blast
from reachset.models import (
    Capability,
    Credential,
    CredentialKind,
    Grant,
    Principal,
    PrincipalKind,
    Resource,
    ResourceKind,
)
from reachset.reach.engine import materialize

pytestmark = pytest.mark.integration


async def _seed(db: AsyncSession, tenant: str) -> dict[str, object]:
    """deploy-bot --impersonate--> release-svc --write--> prod secrets.

    deploy-bot also reads one low-sensitivity path directly, so the ranking has
    something to sort.
    """
    bot = Principal(
        tenant_id=tenant,
        app_id="vault",
        external_id="deploy-bot",
        kind=PrincipalKind.AGENT,
        display_name="deploy-bot",
    )
    svc = Principal(
        tenant_id=tenant,
        app_id="vault",
        external_id="release-svc",
        kind=PrincipalKind.SERVICE,
        display_name="release-svc",
    )
    bystander = Principal(
        tenant_id=tenant,
        app_id="vault",
        external_id="unrelated",
        kind=PrincipalKind.SERVICE,
        display_name="unrelated",
    )
    db.add_all([bot, svc, bystander])
    await db.flush()

    resources = {}
    for path, sensitivity in [
        ("secret/data/prod/db", 3),
        ("secret/data/prod/api", 3),
        ("secret/data/dev/notes", 0),
    ]:
        resource = Resource(
            tenant_id=tenant,
            app_id="vault",
            external_id=path,
            kind=ResourceKind.SECRET_PATH,
            path=path,
            sensitivity=sensitivity,
        )
        db.add(resource)
        await db.flush()
        resources[path] = resource

    credential = Credential(
        tenant_id=tenant,
        principal_id=bot.id,
        kind=CredentialKind.VAULT_TOKEN,
        external_id="acc-deploy-bot",
    )
    db.add(credential)
    await db.flush()

    def grant(
        principal: Principal,
        selector: str,
        caps: list[Capability],
        *,
        credential_id: uuid.UUID | None = None,
        scope: str = "policy:x",
    ) -> Grant:
        row = Grant(
            tenant_id=tenant,
            principal_id=principal.id,
            credential_id=credential_id,
            resource_selector=selector,
            scope_raw=scope,
            capabilities=[c.value for c in caps],
            source_app_id="vault",
            dedupe_key=uuid.uuid4().hex,
        )
        db.add(row)
        return row

    impersonation = grant(
        bot,
        "principal:release-svc",
        [Capability.IMPERSONATE],
        credential_id=credential.id,
        scope="policy:sudo",
    )
    direct = grant(
        bot,
        "secret/data/dev/*",
        [Capability.READ],
        credential_id=credential.id,
        scope="policy:dev-ro",
    )
    downstream = grant(
        svc, "secret/data/prod/*", [Capability.READ, Capability.WRITE], scope="policy:prod-rw"
    )
    # The bystander reaches prod through its own grant, so revoking the
    # impersonation chain must not claim to remove *its* access.
    grant(bystander, "secret/data/prod/db", [Capability.READ], scope="policy:audit-ro")
    await db.flush()
    await materialize(db, tenant)
    await db.commit()
    return {
        "bot": bot,
        "svc": svc,
        "bystander": bystander,
        "impersonation": impersonation,
        "direct": direct,
        "downstream": downstream,
    }


async def test_blast_radius_ranks_worst_first(db: AsyncSession, tenant: str) -> None:
    seeded = await _seed(db, tenant)
    bot: Principal = seeded["bot"]  # type: ignore[assignment]

    report = await blast.blast_radius_for_principal(db, tenant, bot.id)
    assert report is not None

    paths = [r.path for r in report.top_resources]
    # Writable sensitive resources outrank a readable insensitive one.
    assert paths[0] in {"secret/data/prod/api", "secret/data/prod/db"}
    assert paths[-1] == "secret/data/dev/notes"
    assert report.total_resources == 3
    assert report.writable_sensitive == 2
    assert report.apps == ("vault",)
    assert report.by_sensitivity == {3: 2, 0: 1}
    assert "2 of them are sensitive and writable" in report.headline()

    # Reach through impersonation carries its full derivation.
    prod = next(r for r in report.top_resources if r.path == "secret/data/prod/db")
    assert [step["step"] for step in prod.derivation] == ["impersonate", "grant"]


async def test_blast_radius_unknown_principal_returns_none(db: AsyncSession, tenant: str) -> None:
    assert await blast.blast_radius_for_principal(db, tenant, uuid.uuid4()) is None


async def test_blast_radius_truncates_and_reports_the_remainder(
    db: AsyncSession, tenant: str
) -> None:
    seeded = await _seed(db, tenant)
    bot: Principal = seeded["bot"]  # type: ignore[assignment]
    report = await blast.blast_radius_for_principal(db, tenant, bot.id, limit=1)
    assert report is not None
    assert len(report.top_resources) == 1
    assert report.truncated == 2


async def test_credential_blast_radius_is_scoped_to_that_credential(
    db: AsyncSession, tenant: str
) -> None:
    """The deploy token's own grants are what leak with the token — not every
    grant its owning principal happens to hold."""
    seeded = await _seed(db, tenant)
    svc: Principal = seeded["svc"]  # type: ignore[assignment]

    # Give the principal a second, credential-less grant. It must not appear.
    db.add(
        Grant(
            tenant_id=tenant,
            principal_id=svc.id,
            resource_selector="secret/data/dev/notes",
            scope_raw="policy:unrelated",
            capabilities=[Capability.READ.value],
            source_app_id="vault",
            dedupe_key=uuid.uuid4().hex,
        )
    )
    await db.commit()

    report = await blast.blast_radius_for_credential(db, tenant, "acc-deploy-bot")
    assert report is not None
    assert report.subject["type"] == "credential"
    assert report.subject["grants"] == 2
    assert report.subject["revoked"] is False
    paths = {r.path for r in report.top_resources}
    # Reached via the token's impersonation grant and its dev read grant.
    assert "secret/data/prod/db" in paths
    assert "secret/data/dev/notes" in paths


async def test_credential_blast_radius_unknown_credential(db: AsyncSession, tenant: str) -> None:
    await _seed(db, tenant)
    assert await blast.blast_radius_for_credential(db, tenant, "acc-nope") is None


async def test_blast_radius_of_principal_with_no_reach(db: AsyncSession, tenant: str) -> None:
    lonely = Principal(
        tenant_id=tenant,
        app_id="vault",
        external_id="lonely",
        kind=PrincipalKind.SERVICE,
        display_name="lonely",
    )
    db.add(lonely)
    await db.commit()
    report = await blast.blast_radius_for_principal(db, tenant, lonely.id)
    assert report is not None
    assert report.total_resources == 0
    assert "reaches nothing" in report.headline()
    assert report.as_dict()["summary"]["resources"] == 0


async def test_simulate_revocation_finds_collateral(db: AsyncSession, tenant: str) -> None:
    """Revoking the impersonation grant is the interesting case: the grant
    belongs to the bot, but the reach it removes is the service's."""
    seeded = await _seed(db, tenant)
    impersonation: Grant = seeded["impersonation"]  # type: ignore[assignment]

    impact = await blast.simulate_revocation(db, tenant, [impersonation.id])
    assert impact.removed_edges > 0
    assert "secret/data/prod/api" in impact.removed_resources
    assert "deploy-bot" in impact.affected_principals
    # The service keeps its own access; only the bot's borrowed reach goes.
    assert "release-svc" not in impact.affected_principals
    # prod/db stays reachable because the bystander has its own grant.
    assert "secret/data/prod/db" in impact.still_reachable_resources
    assert "removes" in impact.headline()


async def test_simulate_revocation_of_a_redundant_grant_removes_nothing(
    db: AsyncSession, tenant: str
) -> None:
    """Two grants covering the same resource: revoking one changes nothing, and
    saying so plainly is the point of the simulation."""
    seeded = await _seed(db, tenant)
    svc: Principal = seeded["svc"]  # type: ignore[assignment]
    duplicate = Grant(
        tenant_id=tenant,
        principal_id=svc.id,
        resource_selector="secret/data/prod/*",
        scope_raw="policy:prod-rw-copy",
        capabilities=[Capability.READ.value, Capability.WRITE.value],
        source_app_id="vault",
        dedupe_key=uuid.uuid4().hex,
    )
    db.add(duplicate)
    await db.commit()

    impact = await blast.simulate_revocation(db, tenant, [duplicate.id])
    assert impact.removed_edges == 0
    assert impact.removed_resources == ()
    assert "removes no reach" in impact.headline()


async def test_simulate_revocation_can_focus_one_principal(db: AsyncSession, tenant: str) -> None:
    seeded = await _seed(db, tenant)
    bot: Principal = seeded["bot"]  # type: ignore[assignment]
    downstream: Grant = seeded["downstream"]  # type: ignore[assignment]

    impact = await blast.simulate_revocation(db, tenant, [downstream.id], focus_principal=bot.id)
    assert impact.affected_principals == ("deploy-bot",)
    payload = impact.as_dict()
    assert payload["revoked_grants"] == [str(downstream.id)]
    assert payload["removed_edges"] == impact.removed_edges


async def test_simulation_does_not_mutate_stored_reach(db: AsyncSession, tenant: str) -> None:
    """A what-if that quietly deleted rows would be a catastrophe in production;
    assert the read-only property directly."""
    seeded = await _seed(db, tenant)
    impersonation: Grant = seeded["impersonation"]  # type: ignore[assignment]

    def count_sql() -> str:
        return "SELECT COUNT(*) FROM reach_edges WHERE tenant_id = :t"

    before = (await db.execute(text(count_sql()), {"t": tenant})).scalar_one()
    await blast.simulate_revocation(db, tenant, [impersonation.id])
    after = (await db.execute(text(count_sql()), {"t": tenant})).scalar_one()
    assert before == after

    grants_left = (
        await db.execute(text("SELECT COUNT(*) FROM grants WHERE tenant_id = :t"), {"t": tenant})
    ).scalar_one()
    assert grants_left == 4  # impersonation, direct, downstream, bystander


def test_summary_skips_edges_whose_resource_vanished() -> None:
    """reach_edges is materialized; a resource can be deleted upstream between
    the recompute and the query. The report drops the orphan rather than
    raising in front of an on-call engineer."""
    from reachset.analysis.blast import _summarize
    from reachset.reach.engine import ReachRow

    live = uuid.uuid4()
    vanished = uuid.uuid4()
    rows = [
        ReachRow(
            origin_id=uuid.uuid4(),
            resource_id=live,
            capability="read",
            confidence=1.0,
            path=[{"step": "grant", "resource": "secret/data/live"}],
            has_fuzzy=False,
        ),
        ReachRow(
            origin_id=uuid.uuid4(),
            resource_id=vanished,
            capability="read",
            confidence=1.0,
            path=[{"step": "grant", "resource": "secret/data/gone"}],
            has_fuzzy=False,
        ),
    ]
    report = _summarize(
        "t",
        {"type": "principal", "external_id": "svc"},
        rows,
        {live: ("secret/data/live", "vault", 1)},
    )
    assert report.total_resources == 1
    assert report.top_resources[0].path == "secret/data/live"
