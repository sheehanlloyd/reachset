"""Owns the orphaned-grant detection: the person who granted access is gone,
but the access is still there."""

from datetime import datetime

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from reachset.detections.base import Finding

RULE_ID = "orphaned_grant"

_SQL = """
SELECT g.id AS grant_id,
       g.resource_selector,
       g.scope_raw,
       g.capabilities,
       g.granted_at,
       p.id AS principal_id,
       p.external_id AS principal_external_id,
       p.display_name AS principal_name,
       granter.external_id AS granter_external_id,
       granter.display_name AS granter_name,
       granter.status AS granter_status
FROM grants g
JOIN principals p ON p.id = g.principal_id
JOIN principals granter ON granter.id = g.granted_by_principal_id
WHERE g.tenant_id = :tenant
  AND granter.status IN ('deactivated', 'deleted')
ORDER BY g.granted_at NULLS LAST
"""


class OrphanedGrant:
    rule_id = RULE_ID

    async def run(self, session: AsyncSession, tenant_id: str, *, now: datetime) -> list[Finding]:
        result = await session.execute(text(_SQL), {"tenant": tenant_id})
        findings = []
        for row in result:
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    tenant_id=tenant_id,
                    principal_id=row.principal_id,
                    severity="high" if "admin" in row.capabilities else "medium",
                    summary=(
                        f"grant on {row.resource_selector!r} to "
                        f"{row.principal_name or row.principal_external_id} was granted by "
                        f"{row.granter_name or row.granter_external_id}, who is now "
                        f"{row.granter_status}"
                    ),
                    evidence={
                        "grant_id": str(row.grant_id),
                        "resource_selector": row.resource_selector,
                        "scope_raw": row.scope_raw,
                        "capabilities": list(row.capabilities),
                        "granted_at": row.granted_at.isoformat() if row.granted_at else None,
                        "granter": {
                            "external_id": row.granter_external_id,
                            "status": row.granter_status,
                        },
                    },
                )
            )
        return findings
