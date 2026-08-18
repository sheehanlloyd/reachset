"""Owns the cross-app concentration detection: one non-human identity that can
reach sensitive resources in three or more different apps. Any single app's
admins can miss it; only the cross-app graph sees it."""

from datetime import datetime

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from reachset.detections.base import Finding

RULE_ID = "cross_app_concentration"
MIN_SENSITIVITY = 2
MIN_APPS = 3

_SQL = """
SELECT p.id AS principal_id,
       p.external_id,
       p.display_name,
       p.kind,
       COUNT(DISTINCT res.app_id) AS app_count,
       jsonb_agg(DISTINCT jsonb_build_object(
           'app', res.app_id,
           'resource', res.path,
           'sensitivity', res.sensitivity,
           'capability', re.capability
       )) AS edges
FROM reach_edges re
JOIN principals p ON p.id = re.principal_id
JOIN resources res ON res.id = re.resource_id
WHERE re.tenant_id = :tenant
  AND p.kind IN ('service', 'agent', 'app')
  AND res.sensitivity >= :min_sensitivity
GROUP BY p.id, p.external_id, p.display_name, p.kind
HAVING COUNT(DISTINCT res.app_id) >= :min_apps
"""


class CrossAppConcentration:
    rule_id = RULE_ID

    async def run(self, session: AsyncSession, tenant_id: str, *, now: datetime) -> list[Finding]:
        result = await session.execute(
            text(_SQL),
            {"tenant": tenant_id, "min_sensitivity": MIN_SENSITIVITY, "min_apps": MIN_APPS},
        )
        findings = []
        for row in result:
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    tenant_id=tenant_id,
                    principal_id=row.principal_id,
                    severity="critical",
                    summary=(
                        f"{row.kind} identity {row.display_name or row.external_id} reaches "
                        f"sensitivity>={MIN_SENSITIVITY} resources in {row.app_count} apps; "
                        f"one compromised credential spans all of them"
                    ),
                    evidence={
                        "external_id": row.external_id,
                        "app_count": row.app_count,
                        "min_sensitivity": MIN_SENSITIVITY,
                        "edges": row.edges,
                    },
                )
            )
        return findings
