"""GitHub connector over fixtures: inventory, PAT/deploy-key/installation reach,
audit stream, and cross-app reach through a deterministic identity link."""

from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from reachset.connectors.github.connector import (
    GitHubConnector,
    audit_page,
    audit_stream_spec,
)
from reachset.connectors.transports import FixtureTransport
from reachset.ingest.engine import StreamSyncer
from reachset.ingest.pipeline import upsert_batch
from reachset.ingest.ratelimit import BackoffPolicy, BucketRegistry
from reachset.linking.linker import link_tenant
from reachset.models import (
    Capability,
    Event,
    Grant,
    Principal,
    PrincipalKind,
    PrincipalStatus,
    ReachEdge,
    Resource,
    ResourceKind,
)
from reachset.reach.engine import materialize

pytestmark = pytest.mark.integration

FIXTURES = Path(__file__).parent.parent / "fixtures" / "github"


@pytest.fixture
def transport() -> FixtureTransport:
    return FixtureTransport(FIXTURES)


async def _reach_paths(
    db: AsyncSession, tenant: str, external_id: str
) -> dict[tuple[str, str], ReachEdge]:
    principal = (
        await db.execute(
            select(Principal).where(
                Principal.tenant_id == tenant, Principal.external_id == external_id
            )
        )
    ).scalar_one()
    rows = (
        await db.execute(
            select(ReachEdge, Resource)
            .join(Resource, ReachEdge.resource_id == Resource.id)
            .where(ReachEdge.principal_id == principal.id)
        )
    ).all()
    return {(res.path, edge.capability.value): edge for edge, res in rows}


async def test_github_sync_reach(
    db: AsyncSession, tenant: str, transport: FixtureTransport
) -> None:
    batch = await GitHubConnector(transport, org="acme").sync()
    await upsert_batch(db, tenant, "github", batch)
    await materialize(db, tenant)
    await db.commit()

    # summarize-ai has repository_selection=all with contents:read -> it reads
    # every repo in the org, including the sensitivity-3 ones.
    ai_reach = await _reach_paths(db, tenant, "installation:42")
    assert ("acme/prod-infra", "read") in ai_reach
    assert ("acme/payments-api", "read") in ai_reach
    assert ("acme/website", "read") in ai_reach
    assert not any(cap != "read" for _, cap in ai_reach)

    # ci-deployer was granted two explicit repos, not the whole org.
    deployer_reach = await _reach_paths(db, tenant, "installation:41")
    assert ("acme/prod-infra", "write") in deployer_reach
    assert ("acme/website", "write") in deployer_reach
    assert not any(path == "acme/payments-api" for path, _ in deployer_reach)

    # The rw deploy key is a service principal that writes exactly one repo.
    key_reach = await _reach_paths(db, tenant, "deploy-key:9001")
    assert set(key_reach) == {("acme/prod-infra", "read"), ("acme/prod-infra", "write")}

    # dwu's subset PAT reaches only the selected repo.
    dwu_reach = await _reach_paths(db, tenant, "user:503")
    assert ("acme/data-tools", "write") in dwu_reach
    assert not any(path == "acme/prod-infra" and cap == "write" for path, cap in dwu_reach)

    # mkraft admin on prod-infra: role_name derivation is recorded in the path.
    mkraft_reach = await _reach_paths(db, tenant, "user:501")
    admin_edge = mkraft_reach[("acme/prod-infra", "admin")]
    assert admin_edge.path_json[-1]["scope"] == "permission:admin"

    # Sensitivity heuristic: prod/payments 3, private 2, public 1.
    sens = {
        r.path: r.sensitivity
        for r in (await db.execute(select(Resource).where(Resource.tenant_id == tenant))).scalars()
    }
    assert sens["acme/prod-infra"] == 3
    assert sens["acme/payments-api"] == 3
    assert sens["acme/data-tools"] == 2
    assert sens["acme/website"] == 1

    # Bot member classified as agent.
    bot = (
        await db.execute(
            select(Principal).where(
                Principal.tenant_id == tenant, Principal.external_id == "user:601"
            )
        )
    ).scalar_one()
    assert bot.kind is PrincipalKind.AGENT


async def test_github_audit_stream_and_ghost_actor(
    db: AsyncSession,
    tenant: str,
    transport: FixtureTransport,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    batch = await GitHubConnector(transport, org="acme").sync()
    await upsert_batch(db, tenant, "github", batch)
    await db.commit()

    syncer = StreamSyncer(
        session_factory=session_factory,
        transport=transport,
        limiter=BucketRegistry(1000.0, 1000.0),
        backoff=BackoffPolicy(base_seconds=0.001),
    )
    outcome = await syncer.sync_stream(tenant, "github", audit_stream_spec("acme"), audit_page)
    assert outcome.pages == 2
    assert not outcome.dead_lettered

    count = (
        await db.execute(select(func.count()).select_from(Event).where(Event.tenant_id == tenant))
    ).scalar_one()
    assert count == 5

    # Actor 599 left the org; the event still lands, pinned to a deleted stub.
    ghost = (
        await db.execute(
            select(Principal).where(
                Principal.tenant_id == tenant, Principal.external_id == "user:599"
            )
        )
    ).scalar_one()
    assert ghost.status is PrincipalStatus.DELETED

    # Attacker-controlled user_agent strings are stored verbatim as data.
    weird = (
        await db.execute(
            select(Event).where(
                Event.tenant_id == tenant, Event.action == "github.org.update_member"
            )
        )
    ).scalar_one()
    assert weird.user_agent is not None
    assert "gh auth refresh" in weird.user_agent

    # Replaying the whole stream is a no-op.
    await syncer.sync_stream(tenant, "github", audit_stream_spec("acme"), audit_page)
    count2 = (
        await db.execute(select(func.count()).select_from(Event).where(Event.tenant_id == tenant))
    ).scalar_one()
    assert count2 == 5


async def test_cross_app_reach_via_deterministic_link(
    db: AsyncSession, tenant: str, transport: FixtureTransport
) -> None:
    """jortega's GitHub account and a Vault entity share an email (modulo +tag);
    the email_exact link lets reach flow across apps at 0.95 confidence."""
    batch = await GitHubConnector(transport, org="acme").sync()
    await upsert_batch(db, tenant, "github", batch)

    vault_person = Principal(
        tenant_id=tenant,
        app_id="vault",
        external_id="entity-jortega",
        kind=PrincipalKind.HUMAN,
        display_name="Julián Ortega",
        email="j.ortega@acme.io",
    )
    secret = Resource(
        tenant_id=tenant,
        app_id="vault",
        external_id="secret/data/prod/payments",
        kind=ResourceKind.SECRET_PATH,
        path="secret/data/prod/payments",
        sensitivity=3,
    )
    db.add_all([vault_person, secret])
    await db.flush()
    db.add(
        Grant(
            tenant_id=tenant,
            principal_id=vault_person.id,
            resource_selector="secret/data/prod/*",
            scope_raw="policy:payments-ro",
            capabilities=[Capability.READ.value],
            source_app_id="vault",
            dedupe_key=Grant.compute_dedupe_key(
                "entity-jortega", None, "secret/data/prod/*", "policy:payments-ro", "vault"
            ),
        )
    )
    await db.commit()

    proposals = await link_tenant(db, tenant)
    await db.commit()
    assert any(p.method.value == "email_exact" for p in proposals)

    await materialize(db, tenant)
    await db.commit()

    jortega_reach = await _reach_paths(db, tenant, "user:502")
    edge = jortega_reach[("secret/data/prod/payments", "read")]
    assert edge.confidence == pytest.approx(0.95)
    steps = [s["step"] for s in edge.path_json]
    assert steps == ["identity_link", "grant"]
    assert edge.path_json[0]["method"] == "email_exact"


async def test_audit_page_without_entries_is_rejected() -> None:
    """A malformed audit page must fail the fetch, not sync zero events and
    quietly advance the watermark past real data."""
    with pytest.raises(ValueError, match="audit page missing entries"):
        audit_page({"after": None})


async def test_paged_list_walks_past_a_full_page(tmp_path: Path) -> None:
    """Classic page-numbered pagination stops on a short page; a full first
    page has to pull a second one."""
    import json as _json

    first = [{"login": f"u{i}", "id": i, "type": "User"} for i in range(100)]
    second = [{"login": "u100", "id": 100, "type": "User"}]
    (tmp_path / "page1.json").write_text(_json.dumps(first))
    (tmp_path / "page2.json").write_text(_json.dumps(second))
    (tmp_path / "routes.json").write_text(
        _json.dumps(
            [
                {
                    "path": "/orgs/acme/members",
                    "params": {"per_page": 100, "page": 1},
                    "body_file": "page1.json",
                },
                {
                    "path": "/orgs/acme/members",
                    "params": {"per_page": 100, "page": 2},
                    "body_file": "page2.json",
                },
            ]
        )
    )
    connector = GitHubConnector(FixtureTransport(tmp_path), org="acme")
    members = await connector._paged_list("/orgs/acme/members")
    assert len(members) == 101


async def test_a_page_that_is_not_a_list_is_rejected(tmp_path: Path) -> None:
    import json as _json

    (tmp_path / "routes.json").write_text(
        _json.dumps(
            [
                {
                    "path": "/orgs/acme/members",
                    "params": {"per_page": 100, "page": 1},
                    "body": {"message": "Not Found"},
                }
            ]
        )
    )
    connector = GitHubConnector(FixtureTransport(tmp_path), org="acme")
    with pytest.raises(ValueError, match="expected list page"):
        await connector._paged_list("/orgs/acme/members")
