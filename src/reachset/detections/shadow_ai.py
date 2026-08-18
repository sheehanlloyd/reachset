"""Owns the shadow-AI detection: an app principal matching the declarative
known-AI-vendor list with read reach on sensitive resources.

The vendor list is data, not code — extend it in a PR, not with if-statements.
"""

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from reachset.detections.base import Finding
from reachset.reach.selectors import glob_match

RULE_ID = "shadow_ai_integration"
MIN_SENSITIVITY = 2


@dataclass(frozen=True)
class AIVendorSignature:
    vendor: str
    # Globs matched (case-insensitively) against display_name and external_id.
    patterns: tuple[str, ...]


AI_VENDORS: tuple[AIVendorSignature, ...] = (
    AIVendorSignature("openai", ("*openai*", "*gpt-*", "*chatgpt*")),
    AIVendorSignature("anthropic", ("*anthropic*", "*claude*")),
    AIVendorSignature("google-gemini", ("*gemini*", "*bard*")),
    AIVendorSignature("cohere", ("*cohere*",)),
    AIVendorSignature("mistral", ("*mistral*",)),
    AIVendorSignature("perplexity", ("*perplexity*",)),
    AIVendorSignature("generic-summarizer", ("*summarize-ai*", "*summarizer*", "*ai-notetaker*")),
    AIVendorSignature("copilot", ("*copilot*",)),
)


def match_vendor(display_name: str | None, external_id: str) -> str | None:
    for candidate in (display_name or "", external_id):
        lowered = candidate.lower()
        for signature in AI_VENDORS:
            for pattern in signature.patterns:
                if glob_match(pattern, lowered):
                    return signature.vendor
    return None


_SQL = """
SELECT p.id AS principal_id,
       p.external_id,
       p.display_name,
       jsonb_agg(jsonb_build_object(
           'resource', res.path,
           'app', res.app_id,
           'sensitivity', res.sensitivity,
           'capability', re.capability,
           'path', re.path_json
       ) ORDER BY res.sensitivity DESC, res.path) AS edges
FROM reach_edges re
JOIN principals p ON p.id = re.principal_id
JOIN resources res ON res.id = re.resource_id
WHERE re.tenant_id = :tenant
  AND p.kind = 'app'
  AND re.capability = 'read'
  AND res.sensitivity >= :min_sensitivity
GROUP BY p.id, p.external_id, p.display_name
"""


class ShadowAIIntegration:
    rule_id = RULE_ID

    async def run(self, session: AsyncSession, tenant_id: str, *, now: datetime) -> list[Finding]:
        result = await session.execute(
            text(_SQL), {"tenant": tenant_id, "min_sensitivity": MIN_SENSITIVITY}
        )
        findings = []
        for row in result:
            vendor = match_vendor(row.display_name, row.external_id)
            if vendor is None:
                continue
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    tenant_id=tenant_id,
                    principal_id=row.principal_id,
                    severity="high",
                    summary=(
                        f"AI integration {row.display_name or row.external_id!r} "
                        f"(vendor match: {vendor}) holds read reach on "
                        f"sensitivity>={MIN_SENSITIVITY} resources"
                    ),
                    evidence={
                        "external_id": row.external_id,
                        "vendor": vendor,
                        "edges": row.edges,
                    },
                )
            )
        return findings
