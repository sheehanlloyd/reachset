"""Owns least-privilege analysis: granted reach versus reach actually exercised.

The premise is that a grant nobody uses is a grant nobody will miss. For each
non-human identity this joins its materialized reach against its own event
history over a window and reports:

- how much of its reach it actually touched,
- which capabilities it holds but has never exercised,
- a concrete narrowed selector derived from the paths it did touch.

The narrowed selector is computed from the longest common path prefix of the
resources actually used, which is exactly the shape most policy languages
(Vault paths, GitHub repo globs, S3 prefixes) want back.

Nothing here revokes anything — Reachset reports, it does not remediate. Every
recommendation carries the evidence needed to justify or reject it.
"""

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

DEFAULT_WINDOW_DAYS = 90
# Reads are the only capability an event stream reliably attributes; a "write"
# action implies read too. Mapping is declarative for the same reason the scope
# tables are.
ACTION_CAPABILITIES: dict[str, frozenset[str]] = {
    "read": frozenset({"read"}),
    "list": frozenset({"read"}),
    "access": frozenset({"read"}),
    "clone": frozenset({"read"}),
    "login": frozenset(),
    "write": frozenset({"read", "write"}),
    "update": frozenset({"read", "write"}),
    "create": frozenset({"write"}),
    "push": frozenset({"read", "write"}),
    "delete": frozenset({"delete"}),
}


def capabilities_for_action(action: str) -> frozenset[str]:
    """`vault.read` -> {read}. Unknown verbs contribute nothing rather than
    guessing, which keeps "unused" honest: we never claim a capability was
    exercised on the strength of a verb we don't understand."""
    verb = action.rsplit(".", 1)[-1].lower()
    return ACTION_CAPABILITIES.get(verb, frozenset())


def common_path_prefix(paths: list[str], separator: str = "/") -> str:
    """Longest common prefix on separator boundaries, as a glob.

    ["a/b/c", "a/b/d"] -> "a/b/*"; ["a/b", "x/y"] -> "*" (nothing in common).
    A single path narrows to itself, with no wildcard at all.
    """
    if not paths:
        return "*"
    if len(paths) == 1:
        return paths[0]
    split = [p.split(separator) for p in paths]
    prefix: list[str] = []
    for parts in zip(*split, strict=False):
        if len(set(parts)) != 1:
            break
        prefix.append(parts[0])
    if not prefix:
        return "*"
    return separator.join(prefix) + separator + "*"


@dataclass(frozen=True)
class Recommendation:
    principal_id: uuid.UUID
    external_id: str
    display_name: str | None
    kind: str
    granted_resources: int
    used_resources: int
    granted_capabilities: tuple[str, ...]
    used_capabilities: tuple[str, ...]
    unused_capabilities: tuple[str, ...]
    suggested_selector: str
    max_sensitivity_granted: int
    max_sensitivity_used: int
    window_days: int
    events_observed: int
    evidence_resources: tuple[str, ...]

    @property
    def unused_ratio(self) -> float:
        if self.granted_resources == 0:
            return 0.0
        return 1.0 - (self.used_resources / self.granted_resources)

    @property
    def severity(self) -> str:
        """How much this over-grant matters, not just how big it is."""
        privileged_unused = {"write", "delete", "admin", "impersonate"} & set(
            self.unused_capabilities
        )
        if privileged_unused and self.max_sensitivity_granted >= 2:
            return "high"
        if privileged_unused or self.unused_ratio >= 0.9:
            return "medium"
        return "low"

    def summary(self) -> str:
        if self.events_observed == 0:
            return (
                f"{self.display_name or self.external_id} can reach "
                f"{self.granted_resources} resource(s) and has not touched any of "
                f"them in {self.window_days} days."
            )
        return (
            f"{self.display_name or self.external_id} can reach "
            f"{self.granted_resources} resource(s) but used {self.used_resources} "
            f"in {self.window_days} days ({self.unused_ratio:.0%} unused)."
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "principal_id": str(self.principal_id),
            "external_id": self.external_id,
            "display_name": self.display_name,
            "kind": self.kind,
            "severity": self.severity,
            "summary": self.summary(),
            "granted_resources": self.granted_resources,
            "used_resources": self.used_resources,
            "unused_ratio": round(self.unused_ratio, 4),
            "granted_capabilities": list(self.granted_capabilities),
            "used_capabilities": list(self.used_capabilities),
            "unused_capabilities": list(self.unused_capabilities),
            "suggested_selector": self.suggested_selector,
            "max_sensitivity_granted": self.max_sensitivity_granted,
            "max_sensitivity_used": self.max_sensitivity_used,
            "window_days": self.window_days,
            "events_observed": self.events_observed,
            "evidence_resources": list(self.evidence_resources),
        }


_GRANTED_SQL = """
SELECT p.id AS principal_id,
       p.external_id,
       p.display_name,
       p.kind,
       COUNT(DISTINCT re.resource_id) AS granted_resources,
       array_agg(DISTINCT re.capability) AS capabilities,
       MAX(res.sensitivity) AS max_sensitivity
FROM reach_edges re
JOIN principals p ON p.id = re.principal_id
JOIN resources res ON res.id = re.resource_id
WHERE re.tenant_id = :tenant
  AND p.kind IN ('service', 'agent', 'app')
  AND p.status = 'active'
GROUP BY p.id, p.external_id, p.display_name, p.kind
"""

_USED_SQL = """
SELECT e.actor_principal_id AS principal_id,
       e.action,
       res.path,
       res.sensitivity,
       COUNT(*) AS hits
FROM events e
JOIN resources res ON res.id = e.target_resource_id
WHERE e.tenant_id = :tenant
  AND e.ts >= :since
  AND e.actor_principal_id IS NOT NULL
GROUP BY e.actor_principal_id, e.action, res.path, res.sensitivity
"""

_EVENT_COUNT_SQL = """
SELECT actor_principal_id AS principal_id, COUNT(*) AS events
FROM events
WHERE tenant_id = :tenant AND ts >= :since AND actor_principal_id IS NOT NULL
GROUP BY actor_principal_id
"""


async def recommend(
    session: AsyncSession,
    tenant_id: str,
    *,
    now: datetime,
    window_days: int = DEFAULT_WINDOW_DAYS,
    min_unused_ratio: float = 0.5,
    evidence_limit: int = 10,
) -> list[Recommendation]:
    """Over-granted non-human identities, worst first.

    `min_unused_ratio` is the reporting threshold — a principal using most of
    what it holds is not interesting. A principal with zero events in the
    window is always reported, because "never used at all" is the strongest
    signal there is.
    """
    since = now - timedelta(days=window_days)

    granted_rows = (await session.execute(text(_GRANTED_SQL), {"tenant": tenant_id})).all()
    if not granted_rows:
        return []

    used_rows = (
        await session.execute(text(_USED_SQL), {"tenant": tenant_id, "since": since})
    ).all()
    event_counts = {
        row.principal_id: row.events
        for row in (
            await session.execute(text(_EVENT_COUNT_SQL), {"tenant": tenant_id, "since": since})
        ).all()
    }

    used_paths: dict[uuid.UUID, set[str]] = {}
    used_caps: dict[uuid.UUID, set[str]] = {}
    used_sensitivity: dict[uuid.UUID, int] = {}
    for row in used_rows:
        used_paths.setdefault(row.principal_id, set()).add(row.path)
        used_caps.setdefault(row.principal_id, set()).update(capabilities_for_action(row.action))
        used_sensitivity[row.principal_id] = max(
            used_sensitivity.get(row.principal_id, 0), row.sensitivity
        )

    recommendations: list[Recommendation] = []
    for row in granted_rows:
        pid = row.principal_id
        paths = sorted(used_paths.get(pid, set()))
        granted_caps = tuple(sorted(row.capabilities))
        exercised = used_caps.get(pid, set())
        unused = tuple(sorted(set(granted_caps) - exercised))
        used_count = len(paths)
        ratio = 1.0 - (used_count / row.granted_resources) if row.granted_resources else 0.0
        observed = event_counts.get(pid, 0)

        if observed and ratio < min_unused_ratio and not unused:
            continue

        recommendations.append(
            Recommendation(
                principal_id=pid,
                external_id=row.external_id,
                display_name=row.display_name,
                kind=row.kind,
                granted_resources=row.granted_resources,
                used_resources=used_count,
                granted_capabilities=granted_caps,
                used_capabilities=tuple(sorted(exercised)),
                unused_capabilities=unused,
                # Nothing used means nothing to justify keeping; the honest
                # suggestion is to revoke rather than to narrow.
                suggested_selector=common_path_prefix(paths) if paths else "(revoke)",
                max_sensitivity_granted=row.max_sensitivity or 0,
                max_sensitivity_used=used_sensitivity.get(pid, 0),
                window_days=window_days,
                events_observed=observed,
                evidence_resources=tuple(paths[:evidence_limit]),
            )
        )

    severity_order = {"high": 0, "medium": 1, "low": 2}
    recommendations.sort(
        key=lambda r: (severity_order[r.severity], -r.unused_ratio, -r.granted_resources)
    )
    return recommendations
