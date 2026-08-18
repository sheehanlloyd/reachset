"""Owns the off-hours bulk-read detection.

Each NHI is compared to its own 28-day history, not to a fleet average:
- baseline hours: UTC hours-of-day in which the principal showed any activity
  during the baseline window;
- baseline volume: its own mean daily read count over that window.
A finding needs both anomalies at once — reads in hours the principal has never
been active in, and a day volume well above its own mean."""

from datetime import datetime, timedelta

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from reachset.detections.base import Finding

RULE_ID = "off_hours_bulk_read"
BASELINE_DAYS = 28
VOLUME_MULTIPLIER = 3.0
MIN_READS = 20

_READ_ACTIONS = ("vault.read", "vault.list", "github.git.clone", "github.repo.access")

_SQL = """
WITH baseline AS (
    SELECT e.actor_principal_id,
           COUNT(*)::float / :baseline_days AS mean_daily_reads,
           array_agg(DISTINCT EXTRACT(HOUR FROM e.ts)::int) AS active_hours
    FROM events e
    WHERE e.tenant_id = :tenant
      AND e.ts >= :baseline_start AND e.ts < :window_start
      AND e.action = ANY(:read_actions)
    GROUP BY e.actor_principal_id
),
current_window AS (
    SELECT e.actor_principal_id,
           COUNT(*) AS reads,
           COUNT(*) FILTER (
               WHERE NOT (EXTRACT(HOUR FROM e.ts)::int = ANY(
                   COALESCE(b.active_hours, ARRAY[]::int[])))
           ) AS off_hours_reads,
           array_agg(DISTINCT EXTRACT(HOUR FROM e.ts)::int) AS hours_seen
    FROM events e
    LEFT JOIN baseline b ON b.actor_principal_id = e.actor_principal_id
    WHERE e.tenant_id = :tenant
      AND e.ts >= :window_start
      AND e.action = ANY(:read_actions)
    GROUP BY e.actor_principal_id, b.active_hours
)
SELECT p.id AS principal_id,
       p.external_id,
       p.display_name,
       c.reads,
       c.off_hours_reads,
       c.hours_seen,
       COALESCE(b.mean_daily_reads, 0) AS mean_daily_reads,
       COALESCE(b.active_hours, ARRAY[]::int[]) AS active_hours
FROM current_window c
JOIN principals p ON p.id = c.actor_principal_id
LEFT JOIN baseline b ON b.actor_principal_id = c.actor_principal_id
WHERE p.kind IN ('service', 'agent', 'app')
  AND c.off_hours_reads > 0
  AND c.reads >= :min_reads
  AND b.mean_daily_reads IS NOT NULL
  AND c.reads > b.mean_daily_reads * :multiplier
"""


class OffHoursBulkRead:
    rule_id = RULE_ID

    async def run(self, session: AsyncSession, tenant_id: str, *, now: datetime) -> list[Finding]:
        window_start = now - timedelta(days=1)
        baseline_start = window_start - timedelta(days=BASELINE_DAYS)
        result = await session.execute(
            text(_SQL),
            {
                "tenant": tenant_id,
                "baseline_days": BASELINE_DAYS,
                "baseline_start": baseline_start,
                "window_start": window_start,
                "read_actions": list(_READ_ACTIONS),
                "min_reads": MIN_READS,
                "multiplier": VOLUME_MULTIPLIER,
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
                        f"{row.display_name or row.external_id} read {row.reads} objects in "
                        f"24h ({row.off_hours_reads} outside its historical active hours) vs "
                        f"a personal baseline of {row.mean_daily_reads:.1f}/day"
                    ),
                    evidence={
                        "external_id": row.external_id,
                        "reads_24h": row.reads,
                        "off_hours_reads": row.off_hours_reads,
                        "mean_daily_reads": float(row.mean_daily_reads),
                        "baseline_active_hours_utc": sorted(row.active_hours),
                        "hours_seen_utc": sorted(row.hours_seen),
                        "baseline_days": BASELINE_DAYS,
                        "volume_multiplier": VOLUME_MULTIPLIER,
                    },
                )
            )
        return findings
