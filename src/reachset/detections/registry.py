"""Owns the detection roster. Order is severity-tiebreak order in reports."""

from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession

from reachset.detections.base import Detection, Finding
from reachset.detections.concentration import CrossAppConcentration
from reachset.detections.dormant_nhi import DormantPrivilegedNHI
from reachset.detections.off_hours import OffHoursBulkRead
from reachset.detections.orphaned_grant import OrphanedGrant
from reachset.detections.scope_expansion import ScopeExpansion
from reachset.detections.shadow_ai import ShadowAIIntegration
from reachset.observability import FINDINGS

ALL_DETECTIONS: tuple[Detection, ...] = (
    CrossAppConcentration(),
    ShadowAIIntegration(),
    ScopeExpansion(),
    DormantPrivilegedNHI(),
    OrphanedGrant(),
    OffHoursBulkRead(),
)


async def run_all(session: AsyncSession, tenant_id: str, *, now: datetime) -> list[Finding]:
    findings: list[Finding] = []
    for detection in ALL_DETECTIONS:
        produced = await detection.run(session, tenant_id, now=now)
        for finding in produced:
            FINDINGS.inc(rule=finding.rule_id, severity=finding.severity)
        findings.extend(produced)
    return findings
