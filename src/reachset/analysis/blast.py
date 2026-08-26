"""Owns blast-radius analysis and what-if revocation.

Two questions, one engine:

- "Credential X is compromised — what is reachable through it, worst first?"
  That is the IR responder's first question, and answering it well means
  ranking by sensitivity and capability rather than dumping an edge list.
- "If I revoke these grants, what actually goes away?" Answered by recomputing
  reach with those grants suppressed and diffing against the live result. The
  simulation is a read-only query: nothing is written, so nobody has to
  remember to roll a transaction back.

Both return summaries with bounded evidence, so the output fits in a terminal
or an agent's context window instead of overflowing it.
"""

import uuid
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from reachset.reach.engine import ReachRow, compute_reach

# Ranking weights. Capability severity dominates sensitivity — being able to
# delete a sensitivity-2 resource is worse than reading a sensitivity-3 one.
_CAPABILITY_WEIGHT = {
    "read": 1,
    "write": 3,
    "delete": 4,
    "admin": 5,
    "impersonate": 5,
}
TOP_RESOURCES = 20


def _score(capability: str, sensitivity: int) -> int:
    return _CAPABILITY_WEIGHT.get(capability, 1) * (sensitivity + 1)


@dataclass(frozen=True)
class ExposedResource:
    resource_id: uuid.UUID
    path: str
    app_id: str
    sensitivity: int
    capabilities: tuple[str, ...]
    confidence: float
    score: int
    derivation: list[dict[str, Any]]

    def as_dict(self) -> dict[str, Any]:
        return {
            "resource": self.path,
            "app": self.app_id,
            "sensitivity": self.sensitivity,
            "capabilities": list(self.capabilities),
            "confidence": self.confidence,
            "score": self.score,
            "derivation": self.derivation,
        }


@dataclass(frozen=True)
class BlastRadius:
    tenant_id: str
    subject: dict[str, Any]
    total_resources: int
    total_edges: int
    apps: tuple[str, ...]
    by_sensitivity: dict[int, int]
    by_capability: dict[str, int]
    writable_sensitive: int
    top_resources: tuple[ExposedResource, ...]
    truncated: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "subject": self.subject,
            "summary": {
                "resources": self.total_resources,
                "edges": self.total_edges,
                "apps": list(self.apps),
                "by_sensitivity": {str(k): v for k, v in sorted(self.by_sensitivity.items())},
                "by_capability": dict(sorted(self.by_capability.items())),
                "writable_sensitive_resources": self.writable_sensitive,
            },
            "top_resources": [r.as_dict() for r in self.top_resources],
            "truncated_resources": self.truncated,
        }

    def headline(self) -> str:
        """One sentence an on-call responder can paste into an incident channel."""
        name = self.subject.get("display_name") or self.subject.get("external_id")
        if self.total_resources == 0:
            return f"{name} reaches nothing that Reachset has ingested."
        apps = ", ".join(self.apps)
        return (
            f"{name} reaches {self.total_resources} resource(s) across {len(self.apps)} "
            f"app(s) ({apps}); {self.writable_sensitive} of them are sensitive and "
            f"writable."
        )


async def _resource_index(
    session: AsyncSession, tenant_id: str, resource_ids: set[uuid.UUID]
) -> dict[uuid.UUID, tuple[str, str, int]]:
    if not resource_ids:
        return {}
    rows = (
        await session.execute(
            text(
                "SELECT id, path, app_id, sensitivity FROM resources "
                "WHERE tenant_id = :tenant AND id = ANY(:ids)"
            ),
            {"tenant": tenant_id, "ids": list(resource_ids)},
        )
    ).all()
    return {row.id: (row.path, row.app_id, row.sensitivity) for row in rows}


def _summarize(
    tenant_id: str,
    subject: dict[str, Any],
    rows: list[ReachRow],
    resources: dict[uuid.UUID, tuple[str, str, int]],
    *,
    limit: int = TOP_RESOURCES,
) -> BlastRadius:
    """Collapse per-capability edges into per-resource exposure, ranked."""
    grouped: dict[uuid.UUID, dict[str, Any]] = {}
    by_sensitivity: Counter[int] = Counter()
    by_capability: Counter[str] = Counter()

    for row in rows:
        meta = resources.get(row.resource_id)
        if meta is None:
            continue  # resource deleted between recompute and query
        path, app_id, sensitivity = meta
        by_capability[row.capability] += 1
        entry = grouped.setdefault(
            row.resource_id,
            {
                "path": path,
                "app_id": app_id,
                "sensitivity": sensitivity,
                "capabilities": set(),
                "confidence": 0.0,
                "derivation": row.path,
            },
        )
        entry["capabilities"].add(row.capability)
        if row.confidence > entry["confidence"]:
            entry["confidence"] = row.confidence
            entry["derivation"] = row.path

    exposed: list[ExposedResource] = []
    for resource_id, entry in grouped.items():
        by_sensitivity[entry["sensitivity"]] += 1
        capabilities = tuple(sorted(entry["capabilities"]))
        exposed.append(
            ExposedResource(
                resource_id=resource_id,
                path=entry["path"],
                app_id=entry["app_id"],
                sensitivity=entry["sensitivity"],
                capabilities=capabilities,
                confidence=entry["confidence"],
                score=max(_score(c, entry["sensitivity"]) for c in capabilities),
                derivation=entry["derivation"],
            )
        )

    # Deterministic order: worst score first, then path, so repeated runs and
    # snapshot tests agree.
    exposed.sort(key=lambda r: (-r.score, r.path))
    writable = {"write", "delete", "admin", "impersonate"}
    writable_sensitive = sum(
        1 for r in exposed if r.sensitivity >= 2 and writable.intersection(r.capabilities)
    )

    return BlastRadius(
        tenant_id=tenant_id,
        subject=subject,
        total_resources=len(exposed),
        total_edges=len(rows),
        apps=tuple(sorted({r.app_id for r in exposed})),
        by_sensitivity=dict(by_sensitivity),
        by_capability=dict(by_capability),
        writable_sensitive=writable_sensitive,
        top_resources=tuple(exposed[:limit]),
        truncated=max(0, len(exposed) - limit),
    )


async def blast_radius_for_principal(
    session: AsyncSession,
    tenant_id: str,
    principal_id: uuid.UUID,
    *,
    limit: int = TOP_RESOURCES,
    depth_cap: int = 8,
) -> BlastRadius | None:
    principal = (
        await session.execute(
            text(
                "SELECT id, external_id, display_name, kind, app_id FROM principals "
                "WHERE tenant_id = :tenant AND id = :id"
            ),
            {"tenant": tenant_id, "id": principal_id},
        )
    ).one_or_none()
    if principal is None:
        return None

    rows = await compute_reach(session, tenant_id, origin=principal_id, depth_cap=depth_cap)
    resources = await _resource_index(session, tenant_id, {r.resource_id for r in rows})
    subject = {
        "type": "principal",
        "id": str(principal.id),
        "external_id": principal.external_id,
        "display_name": principal.display_name,
        "kind": principal.kind,
        "app": principal.app_id,
    }
    return _summarize(tenant_id, subject, rows, resources, limit=limit)


async def blast_radius_for_credential(
    session: AsyncSession,
    tenant_id: str,
    credential_external_id: str,
    *,
    limit: int = TOP_RESOURCES,
    depth_cap: int = 8,
) -> BlastRadius | None:
    """Reach through one credential.

    Only edges whose derivation actually traverses this credential's grants
    count: holding a Vault token does not hand you the reach of every other
    token its owner holds. That distinction is the whole point of the query.
    """
    credential = (
        await session.execute(
            text(
                "SELECT c.id, c.external_id, c.kind, c.principal_id, c.revoked_at, "
                "p.external_id AS principal_external_id, p.display_name "
                "FROM credentials c LEFT JOIN principals p ON p.id = c.principal_id "
                "WHERE c.tenant_id = :tenant AND c.external_id = :ext"
            ),
            {"tenant": tenant_id, "ext": credential_external_id},
        )
    ).one_or_none()
    if credential is None or credential.principal_id is None:
        return None

    grant_ids = {
        row.id
        for row in (
            await session.execute(
                text("SELECT id FROM grants WHERE tenant_id = :tenant AND credential_id = :cid"),
                {"tenant": tenant_id, "cid": credential.id},
            )
        ).all()
    }

    rows = await compute_reach(
        session, tenant_id, origin=credential.principal_id, depth_cap=depth_cap
    )
    scoped = [row for row in rows if _path_uses_grant(row.path, grant_ids)]
    resources = await _resource_index(session, tenant_id, {r.resource_id for r in scoped})
    subject = {
        "type": "credential",
        "external_id": credential.external_id,
        "kind": credential.kind,
        "revoked": credential.revoked_at is not None,
        "principal_external_id": credential.principal_external_id,
        "display_name": credential.display_name,
        "grants": len(grant_ids),
    }
    return _summarize(tenant_id, subject, scoped, resources, limit=limit)


def _path_uses_grant(path: list[dict[str, Any]], grant_ids: set[uuid.UUID]) -> bool:
    wanted = {str(g) for g in grant_ids}
    return any(step.get("grant_id") in wanted for step in path)


@dataclass(frozen=True)
class RevocationImpact:
    tenant_id: str
    revoked_grant_ids: tuple[uuid.UUID, ...]
    removed_edges: int
    retained_edges: int
    removed_resources: tuple[str, ...]
    still_reachable_resources: tuple[str, ...]
    affected_principals: tuple[str, ...]
    collateral: tuple[str, ...] = field(default=())

    def as_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "revoked_grants": [str(g) for g in self.revoked_grant_ids],
            "removed_edges": self.removed_edges,
            "retained_edges": self.retained_edges,
            "removed_resources": list(self.removed_resources),
            "still_reachable_after_revocation": list(self.still_reachable_resources),
            "affected_principals": list(self.affected_principals),
            "collateral_principals": list(self.collateral),
        }

    def headline(self) -> str:
        if self.removed_edges == 0:
            return (
                "Revoking these grants removes no reach — the same access is "
                "available by another path."
            )
        collateral = (
            f"; {len(self.collateral)} other principal(s) lose access too"
            if self.collateral
            else ""
        )
        return (
            f"Revoking {len(self.revoked_grant_ids)} grant(s) removes "
            f"{self.removed_edges} reach edge(s) covering "
            f"{len(self.removed_resources)} resource(s){collateral}."
        )


async def simulate_revocation(
    session: AsyncSession,
    tenant_id: str,
    grant_ids: list[uuid.UUID],
    *,
    focus_principal: uuid.UUID | None = None,
    depth_cap: int = 8,
) -> RevocationImpact:
    """Diff full-tenant reach against reach with `grant_ids` suppressed.

    Read-only. The interesting output is usually the *collateral*: which other
    principals silently depended on the grant you were about to revoke, and
    which resources stay reachable anyway through a second path.
    """
    before = await compute_reach(session, tenant_id, origin=focus_principal, depth_cap=depth_cap)
    after = await compute_reach(
        session,
        tenant_id,
        origin=focus_principal,
        depth_cap=depth_cap,
        exclude_grant_ids=grant_ids,
    )

    def key(row: ReachRow) -> tuple[uuid.UUID, uuid.UUID, str]:
        return (row.origin_id, row.resource_id, row.capability)

    before_keys = {key(row) for row in before}
    after_keys = {key(row) for row in after}
    removed = before_keys - after_keys

    removed_resource_ids = {r for _, r, _ in removed}
    surviving_resource_ids = {r for _, r, _ in after_keys}
    resources = await _resource_index(
        session, tenant_id, removed_resource_ids | surviving_resource_ids
    )

    affected_principal_ids = {p for p, _, _ in removed}
    principal_names: dict[uuid.UUID, str] = {}
    if affected_principal_ids:
        principal_names = {
            row.id: row.display_name or row.external_id
            for row in (
                await session.execute(
                    text(
                        "SELECT id, external_id, display_name FROM principals "
                        "WHERE tenant_id = :tenant AND id = ANY(:ids)"
                    ),
                    {"tenant": tenant_id, "ids": list(affected_principal_ids)},
                )
            ).all()
        }

    # Principals who owned none of the revoked grants but lose reach anyway:
    # the delegation chains nobody remembers when they revoke something.
    owners = {
        row.principal_id
        for row in (
            await session.execute(
                text(
                    "SELECT principal_id FROM grants WHERE tenant_id = :tenant AND id = ANY(:ids)"
                ),
                {"tenant": tenant_id, "ids": grant_ids},
            )
        ).all()
    }
    collateral = tuple(
        sorted(principal_names[p] for p in affected_principal_ids - owners if p in principal_names)
    )

    return RevocationImpact(
        tenant_id=tenant_id,
        revoked_grant_ids=tuple(grant_ids),
        removed_edges=len(removed),
        retained_edges=len(after_keys),
        removed_resources=tuple(
            sorted({resources[r][0] for r in removed_resource_ids if r in resources})
        ),
        still_reachable_resources=tuple(
            sorted(
                {
                    resources[r][0]
                    for r in removed_resource_ids & surviving_resource_ids
                    if r in resources
                }
            )
        ),
        affected_principals=tuple(sorted(principal_names.values())),
        collateral=collateral,
    )
