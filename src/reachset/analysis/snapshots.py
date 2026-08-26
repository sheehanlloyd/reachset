"""Owns reach snapshots and the diffs between them.

A detection tells you what is wrong now. A diff tells you what changed, which
is usually the more actionable question: nobody wants a nightly report listing
the same 400 known edges, they want the six that appeared since yesterday.

Snapshots denormalize external ids and paths rather than storing row
references, so a diff still renders correctly after the upstream principal has
been deleted — the case where you most want to read it.
"""

import hashlib
import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

_EDGE_SQL = """
SELECT p.external_id AS principal_external_id,
       p.app_id AS principal_app_id,
       res.path AS resource_path,
       res.app_id AS resource_app_id,
       res.sensitivity,
       re.capability,
       re.confidence
FROM reach_edges re
JOIN principals p ON p.id = re.principal_id
JOIN resources res ON res.id = re.resource_id
WHERE re.tenant_id = :tenant
ORDER BY p.external_id, res.path, re.capability
"""


class SnapshotExistsError(Exception):
    """A label is already taken. Labels are stable names, not timestamps."""


@dataclass(frozen=True)
class Snapshot:
    id: uuid.UUID
    tenant_id: str
    label: str
    edge_count: int
    digest: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": str(self.id),
            "tenant_id": self.tenant_id,
            "label": self.label,
            "edge_count": self.edge_count,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class EdgeChange:
    principal: str
    resource: str
    capability: str
    sensitivity: int
    resource_app: str
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        payload = {
            "principal": self.principal,
            "resource": self.resource,
            "capability": self.capability,
            "sensitivity": self.sensitivity,
            "app": self.resource_app,
        }
        if self.detail:
            payload["detail"] = self.detail
        return payload


@dataclass(frozen=True)
class SnapshotDiff:
    tenant_id: str
    from_label: str
    to_label: str
    added: tuple[EdgeChange, ...]
    removed: tuple[EdgeChange, ...]
    changed: tuple[EdgeChange, ...]

    @property
    def is_empty(self) -> bool:
        return not (self.added or self.removed or self.changed)

    @property
    def added_sensitive(self) -> int:
        return sum(1 for e in self.added if e.sensitivity >= 2)

    def headline(self) -> str:
        if self.is_empty:
            return f"No reach changes between {self.from_label!r} and {self.to_label!r}."
        return (
            f"{len(self.added)} edge(s) added ({self.added_sensitive} on sensitive "
            f"resources), {len(self.removed)} removed, {len(self.changed)} changed "
            f"between {self.from_label!r} and {self.to_label!r}."
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "from": self.from_label,
            "to": self.to_label,
            "headline": self.headline(),
            "added": [e.as_dict() for e in self.added],
            "removed": [e.as_dict() for e in self.removed],
            "changed": [e.as_dict() for e in self.changed],
            "counts": {
                "added": len(self.added),
                "removed": len(self.removed),
                "changed": len(self.changed),
                "added_sensitive": self.added_sensitive,
            },
        }


async def take_snapshot(session: AsyncSession, tenant_id: str, label: str) -> Snapshot:
    """Capture the tenant's current materialized reach under `label`."""
    rows = (await session.execute(text(_EDGE_SQL), {"tenant": tenant_id})).all()

    # Digest over the ordered edge tuples: two snapshots with the same digest
    # are the same reach set, regardless of when they were taken.
    hasher = hashlib.sha256()
    for row in rows:
        hasher.update(
            f"{row.principal_external_id}\x1f{row.resource_path}\x1f{row.capability}"
            f"\x1f{row.confidence}\x1e".encode()
        )
    digest = hasher.hexdigest()

    try:
        snapshot_id = (
            await session.execute(
                text(
                    "INSERT INTO reach_snapshots (tenant_id, label, edge_count, digest) "
                    "VALUES (:tenant, :label, :count, :digest) RETURNING id"
                ),
                {"tenant": tenant_id, "label": label, "count": len(rows), "digest": digest},
            )
        ).scalar_one()
    except IntegrityError as exc:
        await session.rollback()
        raise SnapshotExistsError(
            f"snapshot {label!r} already exists for tenant {tenant_id!r}"
        ) from exc

    if rows:
        await session.execute(
            text(
                "INSERT INTO reach_snapshot_edges (snapshot_id, principal_external_id, "
                "principal_app_id, resource_path, resource_app_id, sensitivity, capability, "
                "confidence) VALUES (:snapshot, :principal, :principal_app, :resource, "
                ":resource_app, :sensitivity, :capability, :confidence)"
            ),
            [
                {
                    "snapshot": snapshot_id,
                    "principal": row.principal_external_id,
                    "principal_app": row.principal_app_id,
                    "resource": row.resource_path,
                    "resource_app": row.resource_app_id,
                    "sensitivity": row.sensitivity,
                    "capability": row.capability,
                    "confidence": row.confidence,
                }
                for row in rows
            ],
        )

    return Snapshot(
        id=snapshot_id,
        tenant_id=tenant_id,
        label=label,
        edge_count=len(rows),
        digest=digest,
    )


async def list_snapshots(session: AsyncSession, tenant_id: str) -> list[Snapshot]:
    rows = (
        await session.execute(
            text(
                "SELECT id, label, edge_count, digest FROM reach_snapshots "
                "WHERE tenant_id = :tenant ORDER BY taken_at DESC"
            ),
            {"tenant": tenant_id},
        )
    ).all()
    return [
        Snapshot(
            id=row.id,
            tenant_id=tenant_id,
            label=row.label,
            edge_count=row.edge_count,
            digest=row.digest,
        )
        for row in rows
    ]


# FULL OUTER JOIN so a single pass yields added, removed, and confidence
# changes — the alternative is three round-trips over the same two sets.
_DIFF_SQL = """
SELECT COALESCE(a.principal_external_id, b.principal_external_id) AS principal,
       COALESCE(a.resource_path, b.resource_path) AS resource,
       COALESCE(a.capability, b.capability) AS capability,
       COALESCE(a.sensitivity, b.sensitivity) AS sensitivity,
       COALESCE(a.resource_app_id, b.resource_app_id) AS app,
       a.confidence AS old_confidence,
       b.confidence AS new_confidence,
       CASE
           WHEN a.id IS NULL THEN 'added'
           WHEN b.id IS NULL THEN 'removed'
           WHEN a.confidence IS DISTINCT FROM b.confidence THEN 'changed'
           ELSE 'same'
       END AS change
FROM (SELECT * FROM reach_snapshot_edges WHERE snapshot_id = :from_id) a
FULL OUTER JOIN (SELECT * FROM reach_snapshot_edges WHERE snapshot_id = :to_id) b
  ON a.principal_external_id = b.principal_external_id
 AND a.resource_path = b.resource_path
 AND a.capability = b.capability
ORDER BY sensitivity DESC, principal, resource, capability
"""


async def diff_snapshots(
    session: AsyncSession, tenant_id: str, from_label: str, to_label: str
) -> SnapshotDiff:
    ids = {
        row.label: row.id
        for row in (
            await session.execute(
                text(
                    "SELECT id, label FROM reach_snapshots "
                    "WHERE tenant_id = :tenant AND label = ANY(:labels)"
                ),
                {"tenant": tenant_id, "labels": [from_label, to_label]},
            )
        ).all()
    }
    missing = [label for label in (from_label, to_label) if label not in ids]
    if missing:
        raise KeyError(f"no snapshot(s) named {missing} for tenant {tenant_id!r}")

    rows = (
        await session.execute(text(_DIFF_SQL), {"from_id": ids[from_label], "to_id": ids[to_label]})
    ).all()

    added: list[EdgeChange] = []
    removed: list[EdgeChange] = []
    changed: list[EdgeChange] = []
    for row in rows:
        if row.change == "same":
            continue
        detail = ""
        if row.change == "changed":
            detail = f"confidence {row.old_confidence} -> {row.new_confidence}"
        change = EdgeChange(
            principal=row.principal,
            resource=row.resource,
            capability=row.capability,
            sensitivity=row.sensitivity,
            resource_app=row.app,
            detail=detail,
        )
        {"added": added, "removed": removed, "changed": changed}[row.change].append(change)

    return SnapshotDiff(
        tenant_id=tenant_id,
        from_label=from_label,
        to_label=to_label,
        added=tuple(added),
        removed=tuple(removed),
        changed=tuple(changed),
    )


async def delete_snapshot(session: AsyncSession, tenant_id: str, label: str) -> bool:
    deleted = (
        await session.execute(
            text(
                "DELETE FROM reach_snapshots WHERE tenant_id = :tenant AND label = :label "
                "RETURNING id"
            ),
            {"tenant": tenant_id, "label": label},
        )
    ).scalar_one_or_none()
    return deleted is not None
