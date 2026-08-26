"""Reach snapshots and diffs: the "what changed since Friday" query."""

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from reachset.analysis import snapshots
from reachset.models import (
    Capability,
    Grant,
    Principal,
    PrincipalKind,
    Resource,
    ResourceKind,
)
from reachset.reach.engine import materialize

pytestmark = pytest.mark.integration


async def _principal(db: AsyncSession, tenant: str, external_id: str) -> Principal:
    principal = Principal(
        tenant_id=tenant,
        app_id="vault",
        external_id=external_id,
        kind=PrincipalKind.SERVICE,
        display_name=external_id,
    )
    db.add(principal)
    await db.flush()
    return principal


async def _resource(db: AsyncSession, tenant: str, path: str, sensitivity: int = 2) -> Resource:
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
    return resource


async def _grant(
    db: AsyncSession,
    tenant: str,
    principal: Principal,
    selector: str,
    caps: list[Capability],
) -> Grant:
    grant = Grant(
        tenant_id=tenant,
        principal_id=principal.id,
        resource_selector=selector,
        scope_raw="policy:test",
        capabilities=[c.value for c in caps],
        source_app_id="vault",
        dedupe_key=uuid.uuid4().hex,
    )
    db.add(grant)
    await db.flush()
    return grant


async def test_snapshot_captures_and_lists(db: AsyncSession, tenant: str) -> None:
    svc = await _principal(db, tenant, "svc-a")
    await _resource(db, tenant, "secret/data/prod/db")
    await _grant(db, tenant, svc, "secret/data/prod/*", [Capability.READ])
    await materialize(db, tenant)
    await db.commit()

    snap = await snapshots.take_snapshot(db, tenant, "monday")
    await db.commit()
    assert snap.edge_count == 1
    assert snap.label == "monday"
    assert len(snap.digest) == 64

    listed = await snapshots.list_snapshots(db, tenant)
    assert [s.label for s in listed] == ["monday"]
    assert listed[0].as_dict()["edge_count"] == 1


async def test_duplicate_label_is_rejected(db: AsyncSession, tenant: str) -> None:
    await snapshots.take_snapshot(db, tenant, "dup")
    await db.commit()
    with pytest.raises(snapshots.SnapshotExistsError, match="already exists"):
        await snapshots.take_snapshot(db, tenant, "dup")


async def test_identical_reach_produces_identical_digest(db: AsyncSession, tenant: str) -> None:
    """The digest is what lets a nightly job skip a diff it doesn't need."""
    svc = await _principal(db, tenant, "svc-a")
    await _resource(db, tenant, "secret/data/prod/db")
    await _grant(db, tenant, svc, "secret/data/prod/*", [Capability.READ])
    await materialize(db, tenant)
    await db.commit()

    first = await snapshots.take_snapshot(db, tenant, "a")
    await db.commit()
    second = await snapshots.take_snapshot(db, tenant, "b")
    await db.commit()
    assert first.digest == second.digest

    diff = await snapshots.diff_snapshots(db, tenant, "a", "b")
    assert diff.is_empty
    assert "No reach changes" in diff.headline()


async def test_diff_reports_added_removed_and_changed(db: AsyncSession, tenant: str) -> None:
    svc = await _principal(db, tenant, "svc-a")
    other = await _principal(db, tenant, "svc-b")
    await _resource(db, tenant, "secret/data/prod/db", sensitivity=3)
    await _resource(db, tenant, "secret/data/dev/scratch", sensitivity=0)
    keep = await _grant(db, tenant, svc, "secret/data/prod/*", [Capability.READ])
    drop = await _grant(db, tenant, other, "secret/data/dev/*", [Capability.READ])
    await materialize(db, tenant)
    await db.commit()
    await snapshots.take_snapshot(db, tenant, "before")
    await db.commit()

    # Grant svc write on prod (added), revoke svc-b entirely (removed).
    await db.execute(
        text("UPDATE grants SET capabilities = :caps WHERE id = :id"),
        {"caps": [Capability.READ.value, Capability.WRITE.value], "id": keep.id},
    )
    await db.execute(text("DELETE FROM grants WHERE id = :id"), {"id": drop.id})
    await materialize(db, tenant)
    await db.commit()
    await snapshots.take_snapshot(db, tenant, "after")
    await db.commit()

    diff = await snapshots.diff_snapshots(db, tenant, "before", "after")
    assert not diff.is_empty
    added = {(e.principal, e.capability) for e in diff.added}
    removed = {(e.principal, e.capability) for e in diff.removed}
    assert ("svc-a", "write") in added
    assert ("svc-b", "read") in removed
    assert diff.added_sensitive == 1  # the new write is on a sensitivity-3 path
    assert "1 edge(s) added" in diff.headline()

    payload = diff.as_dict()
    assert payload["counts"] == {
        "added": 1,
        "removed": 1,
        "changed": 0,
        "added_sensitive": 1,
    }
    assert payload["from"] == "before"


async def test_diff_detects_confidence_change(db: AsyncSession, tenant: str) -> None:
    """Same edge, weaker evidence: worth surfacing, and neither an add nor a
    remove."""
    svc = await _principal(db, tenant, "svc-a")
    await _resource(db, tenant, "secret/data/prod/db")
    await _grant(db, tenant, svc, "secret/data/prod/*", [Capability.READ])
    await materialize(db, tenant)
    await db.commit()
    await snapshots.take_snapshot(db, tenant, "before")
    await db.commit()

    await db.execute(
        text("UPDATE reach_edges SET confidence = 0.6 WHERE tenant_id = :t"), {"t": tenant}
    )
    await db.commit()
    await snapshots.take_snapshot(db, tenant, "after")
    await db.commit()

    diff = await snapshots.diff_snapshots(db, tenant, "before", "after")
    assert diff.added == () and diff.removed == ()
    assert len(diff.changed) == 1
    assert diff.changed[0].detail == "confidence 1.0 -> 0.6"


async def test_diff_survives_deleted_principals(db: AsyncSession, tenant: str) -> None:
    """The denormalization pays off here: the principal is gone, but the diff
    still names it."""
    svc = await _principal(db, tenant, "doomed-svc")
    await _resource(db, tenant, "secret/data/prod/db")
    await _grant(db, tenant, svc, "secret/data/prod/*", [Capability.READ])
    await materialize(db, tenant)
    await db.commit()
    await snapshots.take_snapshot(db, tenant, "before")
    await db.commit()

    await db.execute(text("DELETE FROM principals WHERE id = :id"), {"id": svc.id})
    await materialize(db, tenant)
    await db.commit()
    await snapshots.take_snapshot(db, tenant, "after")
    await db.commit()

    diff = await snapshots.diff_snapshots(db, tenant, "before", "after")
    assert [e.principal for e in diff.removed] == ["doomed-svc"]


async def test_diff_with_unknown_label_raises(db: AsyncSession, tenant: str) -> None:
    await snapshots.take_snapshot(db, tenant, "only")
    await db.commit()
    with pytest.raises(KeyError, match="ghost"):
        await snapshots.diff_snapshots(db, tenant, "only", "ghost")


async def test_snapshots_are_tenant_isolated(db: AsyncSession, tenant: str) -> None:
    svc = await _principal(db, tenant, "svc-a")
    await _resource(db, tenant, "secret/data/prod/db")
    await _grant(db, tenant, svc, "secret/data/prod/*", [Capability.READ])
    await materialize(db, tenant)
    await snapshots.take_snapshot(db, tenant, "mine")
    await db.commit()

    other_tenant = f"{tenant}-other"
    other = await snapshots.take_snapshot(db, other_tenant, "mine")
    await db.commit()
    assert other.edge_count == 0
    assert [s.label for s in await snapshots.list_snapshots(db, other_tenant)] == ["mine"]


async def test_delete_snapshot(db: AsyncSession, tenant: str) -> None:
    await snapshots.take_snapshot(db, tenant, "temp")
    await db.commit()
    assert await snapshots.delete_snapshot(db, tenant, "temp") is True
    await db.commit()
    assert await snapshots.list_snapshots(db, tenant) == []
    assert await snapshots.delete_snapshot(db, tenant, "temp") is False


async def test_deleting_a_snapshot_removes_its_edges(db: AsyncSession, tenant: str) -> None:
    svc = await _principal(db, tenant, "svc-a")
    await _resource(db, tenant, "secret/data/prod/db")
    await _grant(db, tenant, svc, "secret/data/prod/*", [Capability.READ])
    await materialize(db, tenant)
    await db.commit()
    await snapshots.take_snapshot(db, tenant, "temp")
    await db.commit()

    await snapshots.delete_snapshot(db, tenant, "temp")
    await db.commit()
    remaining = (await db.execute(text("SELECT COUNT(*) FROM reach_snapshot_edges"))).scalar_one()
    assert remaining == 0


def test_edge_change_serialization_includes_detail_only_when_present() -> None:
    plain = snapshots.EdgeChange(
        principal="svc",
        resource="secret/x",
        capability="read",
        sensitivity=2,
        resource_app="vault",
    )
    assert "detail" not in plain.as_dict()

    annotated = snapshots.EdgeChange(
        principal="svc",
        resource="secret/x",
        capability="read",
        sensitivity=2,
        resource_app="vault",
        detail="confidence 1.0 -> 0.6",
    )
    assert annotated.as_dict()["detail"] == "confidence 1.0 -> 0.6"
