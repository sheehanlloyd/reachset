"""Full connector pipeline over committed fixtures: replay-idempotent, stub
principals for dangling references, reach computed with explainable paths."""

from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from reachset.connectors.transports import FixtureTransport
from reachset.connectors.vault.connector import VaultConnector
from reachset.ingest.pipeline import upsert_batch
from reachset.models import (
    Capability,
    Event,
    Principal,
    PrincipalStatus,
    ReachEdge,
    Resource,
)
from reachset.reach.engine import materialize

pytestmark = pytest.mark.integration

FIXTURES = Path(__file__).parent.parent / "fixtures" / "vault"


@pytest.fixture
def connector() -> VaultConnector:
    audit_lines = (FIXTURES / "audit_sample.jsonl").read_text().splitlines()
    return VaultConnector(FixtureTransport(FIXTURES), read_audit_lines=lambda: audit_lines)


async def test_fixture_sync_replay_is_idempotent(
    connector: VaultConnector, db: AsyncSession, tenant: str
) -> None:
    batch = await connector.sync()
    await upsert_batch(db, tenant, "vault", batch)
    await db.commit()

    def _counts(model):  # type: ignore[no-untyped-def]  # helper over ORM models
        return select(func.count()).select_from(model).where(model.tenant_id == tenant)

    first = [
        (await db.execute(_counts(m))).scalar_one() for m in (Principal, Resource, Event, ReachEdge)
    ]

    batch2 = await connector.sync()
    stats = await upsert_batch(db, tenant, "vault", batch2)
    await db.commit()
    second = [
        (await db.execute(_counts(m))).scalar_one() for m in (Principal, Resource, Event, ReachEdge)
    ]
    assert first == second
    assert stats.events_inserted == 0
    assert stats.events_skipped == 4


async def test_fixture_sync_computes_agent_reach(
    connector: VaultConnector, db: AsyncSession, tenant: str
) -> None:
    batch = await connector.sync()
    await upsert_batch(db, tenant, "vault", batch)
    await materialize(db, tenant)
    await db.commit()

    agent = (
        await db.execute(
            select(Principal).where(
                Principal.tenant_id == tenant, Principal.external_id == "entity-9a8b7c6d"
            )
        )
    ).scalar_one()
    rows = (
        await db.execute(
            select(ReachEdge, Resource)
            .join(Resource, ReachEdge.resource_id == Resource.id)
            .where(ReachEdge.principal_id == agent.id)
        )
    ).all()
    # agent-scoped policy: corpus read only; no fixture resource matches it, but
    # default policy gives self-management reach over auth/token paths? No —
    # auth/token/lookup-self is not an ingested resource. The agent's only reach
    # comes from grants whose selectors match actual resources.
    reachable = {res.path for _, res in rows}
    assert "secret/data/prod/db" not in reachable

    # The admin-sudo token (null display name) reaches everything, including
    # the auth mounts, with the whole derivation recorded.
    admin = (
        await db.execute(
            select(Principal).where(
                Principal.tenant_id == tenant,
                Principal.external_id == "token:acc-null-display",
            )
        )
    ).scalar_one()
    admin_rows = (
        await db.execute(
            select(ReachEdge, Resource)
            .join(Resource, ReachEdge.resource_id == Resource.id)
            .where(
                ReachEdge.principal_id == admin.id,
                ReachEdge.capability == Capability.ADMIN,
            )
        )
    ).all()
    admin_paths = {res.path for _, res in admin_rows}
    assert {"auth/token", "auth/approle", "secret/data/prod/db"} <= admin_paths
    for edge, _ in admin_rows:
        assert edge.path_json[-1]["scope"] == "policy:admin-sudo"


async def test_dangling_audit_actor_becomes_deleted_stub(
    connector: VaultConnector, db: AsyncSession, tenant: str
) -> None:
    batch = await connector.sync()
    await upsert_batch(db, tenant, "vault", batch)
    await db.commit()

    # The hmac'd accessor in the audit log matches no known token; the pipeline
    # must keep the event and pin it to a deleted stub, not drop it.
    stub = (
        await db.execute(
            select(Principal).where(
                Principal.tenant_id == tenant,
                Principal.external_id == "token:hmac-sha256:9be2",
            )
        )
    ).scalar_one()
    assert stub.status is PrincipalStatus.DELETED
    events = (
        await db.execute(
            select(func.count()).select_from(Event).where(Event.actor_principal_id == stub.id)
        )
    ).scalar_one()
    assert events >= 1


async def test_empty_kv_tree_is_not_an_error() -> None:
    """A fresh Vault answers 404 for a KV mount with no secrets yet; that is an
    empty inventory, not a failed sync."""
    import json as _json
    import tempfile
    from pathlib import Path as _Path

    with tempfile.TemporaryDirectory() as tmp:
        directory = _Path(tmp)
        for name, body in {
            "sys_auth.json": {"data": {}},
            "policies.json": {"data": {"keys": []}},
            "accessors.json": {"data": {"keys": []}},
        }.items():
            (directory / name).write_text(_json.dumps(body))
        (directory / "routes.json").write_text(
            _json.dumps(
                [
                    {"path": "/v1/sys/auth", "body_file": "sys_auth.json"},
                    {
                        "path": "/v1/sys/policies/acl",
                        "params": {"list": "true"},
                        "body_file": "policies.json",
                    },
                    {
                        "path": "/v1/auth/token/accessors",
                        "params": {"list": "true"},
                        "body_file": "accessors.json",
                    },
                    {
                        "path": "/v1/secret/metadata",
                        "params": {"list": "true"},
                        "status": 404,
                        "body": {"errors": []},
                    },
                ]
            )
        )
        batch = await VaultConnector(FixtureTransport(directory)).sync()

    assert batch.resources == []
    assert batch.principals == []


async def test_a_non_404_error_while_walking_kv_propagates() -> None:
    """404 means "no secrets yet"; a 500 means Vault is unhealthy and the sync
    must fail loudly rather than reporting an empty inventory."""
    import json as _json
    import tempfile
    from pathlib import Path as _Path

    from reachset.connectors.base import TransportHTTPError

    with tempfile.TemporaryDirectory() as tmp:
        directory = _Path(tmp)
        (directory / "routes.json").write_text(
            _json.dumps(
                [
                    {"path": "/v1/sys/auth", "body": {"data": {}}},
                    {
                        "path": "/v1/sys/policies/acl",
                        "params": {"list": "true"},
                        "body": {"data": {"keys": []}},
                    },
                    {
                        "path": "/v1/auth/token/accessors",
                        "params": {"list": "true"},
                        "body": {"data": {"keys": []}},
                    },
                    {
                        "path": "/v1/secret/metadata",
                        "params": {"list": "true"},
                        "status": 500,
                        "body": {"errors": ["internal error"]},
                    },
                ]
            )
        )
        with pytest.raises(TransportHTTPError) as excinfo:
            await VaultConnector(FixtureTransport(directory)).sync()
    assert excinfo.value.status == 500
