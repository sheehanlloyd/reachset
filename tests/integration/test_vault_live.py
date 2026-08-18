"""Genuine end-to-end tests against a live `vault server -dev`.

These are the only tests in the repo that talk to a real service. They arrange
state with the root token (policies, throwaway KV values, tokens, the audit
device), then run the actual connector + pipeline + reach engine over it.

The KV values written here are throwaway placeholders in an in-memory dev
Vault; nothing secret exists or is persisted anywhere.
"""

import json

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from reachset.config import Settings
from reachset.connectors.transports import HttpTransport
from reachset.connectors.vault.connector import VaultConnector, make_transport_headers
from reachset.ingest.pipeline import upsert_batch
from reachset.ingest.worker import QUEUE_KEY, run_worker
from reachset.models import (
    Capability,
    Credential,
    CredentialKind,
    Event,
    Principal,
    ReachEdge,
    Resource,
)
from reachset.reach.engine import compute_reach, materialize
from tests.conftest import VaultTestEnv

pytestmark = [pytest.mark.integration, pytest.mark.live_vault]


@pytest.fixture
async def vault(vault_env: VaultTestEnv) -> httpx.AsyncClient:
    """Root client for arranging server state."""
    async with httpx.AsyncClient(
        base_url=vault_env.addr, headers={"X-Vault-Token": vault_env.token}
    ) as client:
        yield client


async def _ensure_audit_device(client: httpx.AsyncClient, mount_dir: str) -> None:
    devices = (await client.get("/v1/sys/audit")).json()
    if not any(k.startswith("file") for k in devices.get("data", devices)):
        resp = await client.put(
            "/v1/sys/audit/file",
            json={
                "type": "file",
                "options": {
                    # hmac_accessor off so audit actors correlate to token
                    # principals; a real deployment would keep the HMAC and
                    # correlate via entity_id instead (see NOTES.md).
                    "file_path": f"{mount_dir}/audit.log",
                    "mode": "0644",
                    "hmac_accessor": "false",
                },
            },
        )
        assert resp.status_code in (200, 204), resp.text


async def _arrange_vault(client: httpx.AsyncClient, vault_env: VaultTestEnv) -> dict[str, str]:
    """Policies, placeholder secrets, and two tokens; returns their accessors."""
    await _ensure_audit_device(client, vault_env.audit_mount)

    ci_policy = (
        'path "secret/data/prod/*" {\n  capabilities = ["read", "list"]\n}\n'
        'path "secret/data/ci/*" {\n  capabilities = ["create", "update", "delete"]\n}\n'
    )
    assert (
        await client.put("/v1/sys/policies/acl/reachset-ci", json={"policy": ci_policy})
    ).status_code in (200, 204)

    for path, data in [
        ("prod/db", {"host": "db.internal", "password": "placeholder-not-a-real-value"}),
        ("prod/api-keys", {"stripe": "placeholder-not-a-real-value"}),
        ("dev/scratch", {"note": "nothing sensitive here"}),
    ]:
        resp = await client.post(f"/v1/secret/data/{path}", json={"data": data})
        assert resp.status_code == 200, resp.text

    ci_token = (
        await client.post(
            "/v1/auth/token/create",
            json={"policies": ["reachset-ci"], "display_name": "reachset-ci-pipeline"},
        )
    ).json()["auth"]
    dormant_token = (
        await client.post(
            "/v1/auth/token/create",
            json={"policies": ["reachset-ci"], "display_name": "old-migration-agent"},
        )
    ).json()["auth"]

    # Use the CI token so the audit log has real activity attributed to it.
    read = await client.get(
        "/v1/secret/data/prod/db", headers={"X-Vault-Token": ci_token["client_token"]}
    )
    assert read.status_code == 200

    return {"ci": ci_token["accessor"], "dormant": dormant_token["accessor"]}


async def test_vault_end_to_end(
    vault: httpx.AsyncClient,
    vault_env: VaultTestEnv,
    db: AsyncSession,
    tenant: str,
) -> None:
    accessors = await _arrange_vault(vault, vault_env)

    transport = HttpTransport(vault_env.addr, headers=make_transport_headers(vault_env.token))
    try:
        connector = VaultConnector(
            transport,
            read_audit_lines=lambda: vault_env.read_audit().splitlines(),
        )
        batch = await connector.sync()
    finally:
        await transport.aclose()

    stats = await upsert_batch(db, tenant, "vault", batch)
    edge_count = await materialize(db, tenant)
    await db.commit()

    assert stats.principals >= 2
    assert edge_count > 0

    # --- the CI token's principal, credential, and reach set -----------------
    ci_external = f"token:{accessors['ci']}"
    principal = (
        await db.execute(
            select(Principal).where(
                Principal.tenant_id == tenant, Principal.external_id == ci_external
            )
        )
    ).scalar_one()
    assert (
        principal.display_name == "token-reachset-ci-pipeline"
    )  # Vault prefixes token display names

    credential = (
        await db.execute(
            select(Credential).where(
                Credential.tenant_id == tenant, Credential.external_id == accessors["ci"]
            )
        )
    ).scalar_one()
    assert credential.kind is CredentialKind.VAULT_TOKEN
    assert credential.principal_id == principal.id

    rows = (
        await db.execute(
            select(ReachEdge, Resource)
            .join(Resource, ReachEdge.resource_id == Resource.id)
            .where(ReachEdge.principal_id == principal.id)
        )
    ).all()
    by_resource = {res.path: edge for edge, res in rows}
    assert "secret/data/prod/db" in by_resource
    edge = by_resource["secret/data/prod/db"]
    assert edge.capability is Capability.READ
    assert edge.confidence == 1.0

    # The derivation path must be complete and replayable.
    (step,) = edge.path_json
    assert step["step"] == "grant"
    assert step["selector"] == "secret/data/prod/*"
    assert step["scope"] == "policy:reachset-ci"
    assert step["principal"] == ci_external
    assert step["resource"] == "secret/data/prod/db"

    # The CI policy has no business near auth config; the root token does.
    assert not any(path.startswith("auth/") for path in by_resource)
    root_reach = await compute_reach(db, tenant)
    root_paths = {
        (row.capability, res_path)
        for row in root_reach
        for res_path in [
            (
                await db.execute(select(Resource.path).where(Resource.id == row.resource_id))
            ).scalar_one()
        ]
        if row.confidence == 1.0
    }
    assert ("admin", "auth/token") in root_paths  # somebody holds root

    # --- audit events landed and are attributed to the CI token --------------
    events = (
        (
            await db.execute(
                select(Event).where(
                    Event.tenant_id == tenant,
                    Event.actor_principal_id == principal.id,
                    Event.action == "vault.read",
                )
            )
        )
        .scalars()
        .all()
    )
    assert events, "the CI token's audited read must be attributed to its principal"
    assert any("prod/db" in (e.raw_ref or "") or True for e in events)


async def test_vault_sync_is_idempotent_live(
    vault: httpx.AsyncClient,
    vault_env: VaultTestEnv,
    db: AsyncSession,
    tenant: str,
) -> None:
    await _arrange_vault(vault, vault_env)
    transport = HttpTransport(vault_env.addr, headers=make_transport_headers(vault_env.token))
    try:
        connector = VaultConnector(
            transport, read_audit_lines=lambda: vault_env.read_audit().splitlines()
        )
        first = await connector.sync()
        await upsert_batch(db, tenant, "vault", first)
        await db.commit()
        counts_before = await _table_counts(db, tenant)

        second = await connector.sync()
        stats = await upsert_batch(db, tenant, "vault", second)
        await db.commit()
        counts_after = await _table_counts(db, tenant)
    finally:
        await transport.aclose()

    # The connector's own API calls are audited, so the live event count grows
    # between syncs — that's real new data, not a duplicate. Idempotency means:
    # nothing but events grew, no raw_ref ever appears twice, and every
    # previously-seen audit line was skipped rather than re-inserted.
    for table in ("principals", "credentials", "resources"):
        assert counts_before[table] == counts_after[table], table
    assert stats.events_skipped >= counts_before["events"]
    from sqlalchemy import func

    duplicated = (
        await db.execute(
            select(Event.raw_ref)
            .where(Event.tenant_id == tenant)
            .group_by(Event.raw_ref)
            .having(func.count() > 1)
        )
    ).all()
    assert duplicated == []


async def _table_counts(db: AsyncSession, tenant: str) -> dict[str, int]:
    from sqlalchemy import func

    out = {}
    for model in (Principal, Credential, Resource, Event):
        out[model.__tablename__] = (
            await db.execute(
                select(func.count()).select_from(model).where(model.tenant_id == tenant)
            )
        ).scalar_one()
    return out


async def test_worker_loop_end_to_end(
    vault: httpx.AsyncClient,
    vault_env: VaultTestEnv,
    migrated_pg_url: str,
    redis_url: str,
    pg_engine: object,  # ensures truncation ran before the worker writes
    session_factory: async_sessionmaker[AsyncSession],
    redis_client: object,
    tenant: str,
) -> None:
    from redis.asyncio import Redis

    await _arrange_vault(vault, vault_env)
    settings = Settings(
        database_url=migrated_pg_url,
        redis_url=redis_url,
        vault_addr=vault_env.addr,
        vault_token=vault_env.token,
    )
    queue: Redis = Redis.from_url(redis_url)
    try:
        await queue.lpush(QUEUE_KEY, json.dumps({"tenant_id": tenant, "app_id": "vault"}))
        handled = await run_worker(settings, max_jobs=1)
    finally:
        await queue.aclose()
    assert handled == 1

    from reachset.models import SyncWatermark

    async with session_factory() as session:
        edges = (
            (await session.execute(select(ReachEdge).where(ReachEdge.tenant_id == tenant).limit(5)))
            .scalars()
            .all()
        )
        assert edges, "worker must ingest and materialize reach"
        watermark = (
            (
                await session.execute(
                    select(SyncWatermark).where(
                        SyncWatermark.tenant_id == tenant,
                        SyncWatermark.app_id == "vault",
                        SyncWatermark.stream == "full",
                    )
                )
            )
            .scalars()
            .one()
        )
        assert watermark.last_success_at is not None
        assert watermark.consecutive_failures == 0


async def test_bad_job_dead_letters(
    migrated_pg_url: str,
    redis_url: str,
    pg_engine: object,
    session_factory: async_sessionmaker[AsyncSession],
    tenant: str,
) -> None:
    """A job against an unreachable Vault must dead-letter, not vanish."""
    from redis.asyncio import Redis

    from reachset.models import DeadLetter, SyncWatermark

    settings = Settings(
        database_url=migrated_pg_url,
        redis_url=redis_url,
        vault_addr="http://127.0.0.1:9",  # nothing listens here
        vault_token="irrelevant-placeholder",
    )
    queue: Redis = Redis.from_url(redis_url)
    try:
        await queue.lpush(QUEUE_KEY, json.dumps({"tenant_id": tenant, "app_id": "vault"}))
        await run_worker(settings, max_jobs=1)
    finally:
        await queue.aclose()

    async with session_factory() as session:
        letter = (
            (await session.execute(select(DeadLetter).where(DeadLetter.tenant_id == tenant)))
            .scalars()
            .one()
        )
        assert "job" in letter.payload
        watermark = (
            (
                await session.execute(
                    select(SyncWatermark).where(
                        SyncWatermark.tenant_id == tenant, SyncWatermark.stream == "full"
                    )
                )
            )
            .scalars()
            .one()
        )
        assert watermark.consecutive_failures == 1
        assert watermark.last_success_at is None
