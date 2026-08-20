"""Owns the detection contract. A finding always carries the exact rows that
triggered it — a detection that cannot show its evidence does not fire."""

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from sqlalchemy.ext.asyncio import AsyncSession


@dataclass(frozen=True)
class Finding:
    rule_id: str
    tenant_id: str
    principal_id: uuid.UUID
    severity: str  # low | medium | high | critical
    summary: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "tenant_id": self.tenant_id,
            "principal_id": str(self.principal_id),
            "severity": self.severity,
            "summary": self.summary,
            "evidence": self.evidence,
        }


class Detection(Protocol):  # pragma: no cover - structural declaration, never executed
    rule_id: str

    async def run(
        self, session: AsyncSession, tenant_id: str, *, now: datetime
    ) -> list[Finding]: ...
