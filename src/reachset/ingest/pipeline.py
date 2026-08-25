"""Owns idempotent upserts from canonical records into Postgres.

Every write is ON CONFLICT against the table's idempotency key, so replaying a
page — after a retry, a chaos fault, or a full resync — can never duplicate a
row. That property is what the chaos tests pin down.
"""

import hashlib
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from reachset.models import (
    Credential,
    Event,
    Grant,
    Principal,
    PrincipalKind,
    PrincipalStatus,
    Provenance,
    Resource,
)
from reachset.observability import INGEST_DURATION, INGEST_RECORDS
from reachset.records import ExtractBatch, GrantRecord


@dataclass(frozen=True)
class UpsertStats:
    principals: int
    credentials: int
    resources: int
    grants: int
    events_inserted: int
    events_skipped: int

    def as_dict(self) -> dict[str, int]:
        return {
            "principals": self.principals,
            "credentials": self.credentials,
            "resources": self.resources,
            "grants": self.grants,
            "events_inserted": self.events_inserted,
            "events_skipped": self.events_skipped,
        }


async def _principal_ids(
    session: AsyncSession, tenant_id: str, app_id: str, external_ids: set[str]
) -> dict[str, uuid.UUID]:
    if not external_ids:
        return {}
    rows = await session.execute(
        select(Principal.external_id, Principal.id).where(
            Principal.tenant_id == tenant_id,
            Principal.app_id == app_id,
            Principal.external_id.in_(external_ids),
        )
    )
    return {external_id: row_id for external_id, row_id in rows.tuples()}


async def _ensure_stub_principal(
    session: AsyncSession, tenant_id: str, app_id: str, external_id: str
) -> uuid.UUID:
    """A grant or event references a principal the API no longer returns
    (deleted user, revoked app). Materialize it as a deleted stub so the
    reference — and the orphaned-grant signal — survives."""
    stmt = (
        insert(Principal)
        .values(
            tenant_id=tenant_id,
            app_id=app_id,
            external_id=external_id,
            kind=PrincipalKind.HUMAN,
            status=PrincipalStatus.DELETED,
        )
        .on_conflict_do_update(
            constraint="uq_principal_identity",
            set_={"last_seen_at": datetime.now(UTC)},
        )
        .returning(Principal.id)
    )
    return (await session.execute(stmt)).scalar_one()


async def upsert_batch(
    session: AsyncSession, tenant_id: str, app_id: str, batch: ExtractBatch
) -> UpsertStats:
    """Upsert one extracted page. Caller owns the transaction: commit together
    with the watermark advance or not at all."""
    started = time.perf_counter()
    now = datetime.now(UTC)

    for record in batch.principals:
        stmt = (
            insert(Principal)
            .values(
                tenant_id=tenant_id,
                app_id=app_id,
                external_id=record.external_id,
                kind=record.kind,
                display_name=record.display_name,
                email=record.email,
                status=record.status,
                created_at=record.created_at,
                last_active_at=record.last_active_at,
            )
            .on_conflict_do_update(
                constraint="uq_principal_identity",
                set_={
                    "kind": record.kind,
                    "display_name": record.display_name,
                    "email": record.email,
                    "status": record.status,
                    "last_active_at": record.last_active_at,
                    "last_seen_at": now,
                },
            )
        )
        await session.execute(stmt)

    for resource in batch.resources:
        await session.execute(
            insert(Resource)
            .values(
                tenant_id=tenant_id,
                app_id=app_id,
                external_id=resource.external_id,
                kind=resource.kind,
                path=resource.path,
                sensitivity=resource.sensitivity,
            )
            .on_conflict_do_update(
                constraint="uq_resource_identity",
                set_={
                    "kind": resource.kind,
                    "path": resource.path,
                    "sensitivity": resource.sensitivity,
                },
            )
        )

    principal_refs = {
        *(c.principal_external_id for c in batch.credentials if c.principal_external_id),
        *(g.principal_external_id for g in batch.grants),
        *(g.granted_by_external_id for g in batch.grants if g.granted_by_external_id),
        *(e.actor_external_id for e in batch.events if e.actor_external_id),
    }
    pid_map = await _principal_ids(session, tenant_id, app_id, principal_refs)
    for missing in sorted(principal_refs - pid_map.keys()):
        pid_map[missing] = await _ensure_stub_principal(session, tenant_id, app_id, missing)

    for credential in batch.credentials:
        await session.execute(
            insert(Credential)
            .values(
                tenant_id=tenant_id,
                principal_id=pid_map.get(credential.principal_external_id or ""),
                kind=credential.kind,
                external_id=credential.external_id,
                issued_at=credential.issued_at,
                last_used_at=credential.last_used_at,
                expires_at=credential.expires_at,
                revoked_at=credential.revoked_at,
            )
            .on_conflict_do_update(
                constraint="uq_credential_identity",
                set_={
                    "principal_id": pid_map.get(credential.principal_external_id or ""),
                    "last_used_at": credential.last_used_at,
                    "expires_at": credential.expires_at,
                    "revoked_at": credential.revoked_at,
                },
            )
        )

    credential_refs = {g.credential_external_id for g in batch.grants if g.credential_external_id}
    cred_map: dict[str, uuid.UUID] = {}
    if credential_refs:
        rows = await session.execute(
            select(Credential.external_id, Credential.id).where(
                Credential.tenant_id == tenant_id,
                Credential.external_id.in_(credential_refs),
            )
        )
        cred_map = {ext: row_id for ext, row_id in rows.tuples()}

    widened: list[tuple[GrantRecord, list[str], list[str]]] = []
    for grant in batch.grants:
        dedupe = Grant.compute_dedupe_key(
            grant.principal_external_id,
            grant.credential_external_id,
            grant.resource_selector,
            grant.scope_raw,
            app_id,
        )
        new_caps = sorted(c.value for c in grant.capabilities)
        previous = (
            await session.execute(
                select(Grant.capabilities).where(
                    Grant.tenant_id == tenant_id, Grant.dedupe_key == dedupe
                )
            )
        ).scalar_one_or_none()
        if previous is not None and set(new_caps) > set(previous):
            # A widened capability set is itself a fact worth recording: the
            # scope-expansion detection compares these inferred change events
            # against the app's own audit stream.
            widened.append((grant, sorted(previous), new_caps))
        await session.execute(
            insert(Grant)
            .values(
                tenant_id=tenant_id,
                principal_id=pid_map[grant.principal_external_id],
                credential_id=cred_map.get(grant.credential_external_id or ""),
                resource_selector=grant.resource_selector,
                scope_raw=grant.scope_raw,
                capabilities=new_caps,
                granted_by_principal_id=pid_map.get(grant.granted_by_external_id or ""),
                granted_at=grant.granted_at,
                source_app_id=app_id,
                dedupe_key=dedupe,
            )
            .on_conflict_do_update(
                constraint="uq_grant_dedupe",
                set_={
                    "capabilities": new_caps,
                    "granted_by_principal_id": pid_map.get(grant.granted_by_external_id or ""),
                    "last_seen_at": now,
                },
            )
        )

    for grant, old_caps, new_caps in widened:
        change_ref = hashlib.sha256(
            "\x1f".join(
                [
                    "grant_widened",
                    grant.principal_external_id,
                    grant.resource_selector,
                    grant.scope_raw,
                    ",".join(old_caps),
                    ",".join(new_caps),
                ]
            ).encode()
        ).hexdigest()
        await session.execute(
            insert(Event)
            .values(
                tenant_id=tenant_id,
                app_id=app_id,
                actor_principal_id=pid_map[grant.principal_external_id],
                action="reachset.grant_widened",
                ts=now,
                raw_ref=change_ref,
                provenance=Provenance.INFERRED,
            )
            .on_conflict_do_nothing(constraint="uq_event_identity")
        )

    resource_refs = {
        e.target_resource_external_id for e in batch.events if e.target_resource_external_id
    }
    res_map: dict[str, uuid.UUID] = {}
    if resource_refs:
        rows = await session.execute(
            select(Resource.external_id, Resource.id).where(
                Resource.tenant_id == tenant_id,
                Resource.app_id == app_id,
                Resource.external_id.in_(resource_refs),
            )
        )
        res_map = {ext: row_id for ext, row_id in rows.tuples()}

    inserted = 0
    skipped = 0
    for event in batch.events:
        result = await session.execute(
            insert(Event)
            .values(
                tenant_id=tenant_id,
                app_id=app_id,
                actor_principal_id=pid_map.get(event.actor_external_id or ""),
                action=event.action,
                target_resource_id=res_map.get(event.target_resource_external_id or ""),
                ts=event.ts,
                ip=event.ip,
                user_agent=event.user_agent,
                raw_ref=event.raw_ref,
                provenance=event.provenance,
            )
            .on_conflict_do_nothing(constraint="uq_event_identity")
            .returning(Event.id)
        )
        if result.scalar_one_or_none() is None:
            skipped += 1
        else:
            inserted += 1

    stats = UpsertStats(
        principals=len(batch.principals),
        credentials=len(batch.credentials),
        resources=len(batch.resources),
        grants=len(batch.grants),
        events_inserted=inserted,
        events_skipped=skipped,
    )
    INGEST_DURATION.observe(time.perf_counter() - started, app=app_id)
    for record_type, count in stats.as_dict().items():
        if count:
            INGEST_RECORDS.inc(count, tenant=tenant_id, app=app_id, record_type=record_type)
    return stats
