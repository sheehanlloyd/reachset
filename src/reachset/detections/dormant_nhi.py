"""Owns the dormant-privileged-NHI detection.

A service/agent principal that can write, admin, or delete something and has
shown no activity for over 90 days. "No activity" means: no principal
last_active_at, no credential last_used_at, and no event, each within the
window. A brand-new principal with no history yet is not dormant — dormancy
requires having existed for the whole window.
"""

from datetime import datetime, timedelta

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from reachset.detections.base import Finding

RULE_ID = "dormant_privileged_nhi"
WINDOW_DAYS = 90
_PRIVILEGED = ("write", "admin", "delete")

_SQL = """
WITH activity AS (
    SELECT p.id,
           GREATEST(
               p.last_active_at,
               (SELECT MAX(c.last_used_at) FROM credentials c WHERE c.principal_id = p.id),
               (SELECT MAX(e.ts) FROM events e WHERE e.actor_principal_id = p.id)
           ) AS last_activity,
           LEAST(p.first_seen_at, p.created_at) AS known_since
    FROM principals p
    WHERE p.tenant_id = :tenant
      AND p.kind IN ('service', 'agent')
      AND p.status = 'active'
)
SELECT p.id AS principal_id,
       p.external_id,
       p.display_name,
       a.last_activity,
       a.known_since,
       COUNT(re.id) AS privileged_edges,
       MAX(res.sensitivity) AS max_sensitivity,
       jsonb_agg(
           jsonb_build_object(
               'resource', res.path,
               'capability', re.capability,
               'sensitivity', res.sensitivity,
               'path', re.path_json
           ) ORDER BY res.sensitivity DESC, res.path
       ) FILTER (WHERE re.id IS NOT NULL) AS edges
FROM principals p
JOIN activity a ON a.id = p.id
JOIN reach_edges re
  ON re.principal_id = p.id
 AND re.tenant_id = :tenant
 AND re.capability = ANY(:privileged)
JOIN resources res ON res.id = re.resource_id
WHERE (a.last_activity IS NULL OR a.last_activity < :cutoff)
  AND a.known_since < :cutoff
GROUP BY p.id, p.external_id, p.display_name, a.last_activity, a.known_since
"""


class DormantPrivilegedNHI:
    rule_id = RULE_ID

    async def run(self, session: AsyncSession, tenant_id: str, *, now: datetime) -> list[Finding]:
        cutoff = now - timedelta(days=WINDOW_DAYS)
        result = await session.execute(
            text(_SQL),
            {"tenant": tenant_id, "cutoff": cutoff, "privileged": list(_PRIVILEGED)},
        )
        findings = []
        for row in result:
            idle_days = (now - row.last_activity).days if row.last_activity is not None else None
            idle_text = "its whole recorded life" if idle_days is None else f"{idle_days} days"
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    tenant_id=tenant_id,
                    principal_id=row.principal_id,
                    severity="high" if (row.max_sensitivity or 0) >= 2 else "medium",
                    summary=(
                        f"{row.display_name or row.external_id} holds "
                        f"{row.privileged_edges} privileged reach edge(s) but has been "
                        f"idle for {idle_text}"
                    ),
                    evidence={
                        "external_id": row.external_id,
                        "last_activity": row.last_activity.isoformat()
                        if row.last_activity
                        else None,
                        "window_days": WINDOW_DAYS,
                        "edges": row.edges or [],
                    },
                )
            )
        return findings
