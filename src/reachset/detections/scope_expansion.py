"""Owns the scope-expansion detection.

The pipeline records an inferred `reachset.grant_widened` event whenever a
grant's capability set grows between syncs. A widening is fine when the app's
own audit stream shows a corresponding administrative change close in time; a
widening with no audit trail is the finding.
"""

from datetime import datetime, timedelta

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from reachset.detections.base import Finding

RULE_ID = "scope_expansion"
CORROBORATION_WINDOW_HOURS = 24

# Audit actions that legitimately explain a capability change, per app.
# Declarative on purpose, like the scope tables.
CHANGE_ACTIONS: dict[str, tuple[str, ...]] = {
    "github": (
        "github.repo.add_member",
        "github.repo.update_member",
        "github.org.update_member",
        "github.personal_access_token.access_granted",
        "github.integration_installation.repositories_added",
    ),
    "vault": ("vault.update", "vault.create"),
}

_SQL = """
SELECT w.id AS event_id,
       w.ts,
       w.app_id,
       p.id AS principal_id,
       p.external_id,
       p.display_name,
       corroboration.id AS corroborating_event_id
FROM events w
JOIN principals p ON p.id = w.actor_principal_id
LEFT JOIN LATERAL (
    SELECT e.id
    FROM events e
    WHERE e.tenant_id = w.tenant_id
      AND e.provenance = 'audit_log'
      AND e.action = ANY(:change_actions)
      AND e.ts BETWEEN w.ts - CAST(:window AS interval)
                   AND w.ts + CAST(:window AS interval)
    LIMIT 1
) corroboration ON true
WHERE w.tenant_id = :tenant
  AND w.action = 'reachset.grant_widened'
  AND corroboration.id IS NULL
"""


class ScopeExpansion:
    rule_id = RULE_ID

    async def run(self, session: AsyncSession, tenant_id: str, *, now: datetime) -> list[Finding]:
        change_actions = [a for actions in CHANGE_ACTIONS.values() for a in actions]
        result = await session.execute(
            text(_SQL),
            {
                "tenant": tenant_id,
                "change_actions": change_actions,
                "window": timedelta(hours=CORROBORATION_WINDOW_HOURS),
            },
        )
        findings = []
        for row in result:
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    tenant_id=tenant_id,
                    principal_id=row.principal_id,
                    severity="high",
                    summary=(
                        f"capabilities of a grant to {row.display_name or row.external_id} "
                        f"widened at {row.ts.isoformat()} with no matching change event in "
                        f"the {row.app_id} audit stream (±{CORROBORATION_WINDOW_HOURS}h)"
                    ),
                    evidence={
                        "widened_event_id": row.event_id,
                        "widened_at": row.ts.isoformat(),
                        "app_id": row.app_id,
                        "searched_actions": change_actions,
                        "window_hours": CORROBORATION_WINDOW_HOURS,
                    },
                )
            )
        return findings
