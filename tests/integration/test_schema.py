"""Schema-level invariants: migrations apply, idempotency keys hold, enums reject junk."""

from datetime import UTC, datetime

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from reachset.models import (
    Capability,
    Event,
    Grant,
    Principal,
    PrincipalKind,
    Provenance,
    Resource,
    ResourceKind,
)

pytestmark = pytest.mark.integration


async def test_principal_idempotency_key(db: AsyncSession, tenant: str) -> None:
    a = Principal(tenant_id=tenant, app_id="vault", external_id="p1", kind=PrincipalKind.SERVICE)
    b = Principal(tenant_id=tenant, app_id="vault", external_id="p1", kind=PrincipalKind.HUMAN)
    db.add(a)
    await db.commit()
    db.add(b)
    with pytest.raises(IntegrityError):
        await db.commit()
    await db.rollback()

    # Same external_id in a different app is a different principal.
    db.add(Principal(tenant_id=tenant, app_id="github", external_id="p1", kind=PrincipalKind.HUMAN))
    await db.commit()
    count = (
        await db.execute(
            select(func.count()).select_from(Principal).where(Principal.tenant_id == tenant)
        )
    ).scalar_one()
    assert count == 2


async def test_grant_dedupe_key_is_stable_and_capability_insensitive(
    db: AsyncSession, tenant: str
) -> None:
    key1 = Grant.compute_dedupe_key("p1", None, "secret/*", "policy:default", "vault")
    key2 = Grant.compute_dedupe_key("p1", None, "secret/*", "policy:default", "vault")
    key3 = Grant.compute_dedupe_key("p1", "cred", "secret/*", "policy:default", "vault")
    assert key1 == key2 != key3

    p = Principal(tenant_id=tenant, app_id="vault", external_id="p1", kind=PrincipalKind.SERVICE)
    db.add(p)
    await db.flush()
    db.add(
        Grant(
            tenant_id=tenant,
            principal_id=p.id,
            resource_selector="secret/*",
            scope_raw="policy:default",
            capabilities=[Capability.READ.value],
            source_app_id="vault",
            dedupe_key=key1,
        )
    )
    await db.commit()
    db.add(
        Grant(
            tenant_id=tenant,
            principal_id=p.id,
            resource_selector="secret/*",
            scope_raw="policy:default",
            capabilities=[Capability.READ.value, Capability.WRITE.value],
            source_app_id="vault",
            dedupe_key=key1,
        )
    )
    with pytest.raises(IntegrityError):
        await db.commit()
    await db.rollback()


async def test_event_idempotent_on_raw_ref(db: AsyncSession, tenant: str) -> None:
    ts = datetime(2026, 1, 1, tzinfo=UTC)
    for _ in range(2):
        db.add(
            Event(
                tenant_id=tenant,
                app_id="vault",
                action="read",
                ts=ts,
                raw_ref="hash-abc",
                provenance=Provenance.AUDIT_LOG,
            )
        )
        try:
            await db.commit()
        except IntegrityError:
            await db.rollback()
    count = (
        await db.execute(select(func.count()).select_from(Event).where(Event.tenant_id == tenant))
    ).scalar_one()
    assert count == 1


async def test_resource_sensitivity_and_enum_storage(db: AsyncSession, tenant: str) -> None:
    r = Resource(
        tenant_id=tenant,
        app_id="vault",
        external_id="secret/data/prod/db",
        kind=ResourceKind.SECRET_PATH,
        path="secret/data/prod/db",
        sensitivity=3,
    )
    db.add(r)
    await db.commit()
    loaded = (await db.execute(select(Resource).where(Resource.tenant_id == tenant))).scalar_one()
    assert loaded.kind is ResourceKind.SECRET_PATH
    assert loaded.sensitivity == 3
