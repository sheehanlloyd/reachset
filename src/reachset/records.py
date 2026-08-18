"""Owns the canonical records extractors emit. Pure data, no DB identity.

Extractors return these; the ingest pipeline resolves external ids to row ids at
upsert time. Records are frozen so an extractor bug can't mutate shared state.
"""

from collections.abc import Sequence
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, field_validator

from reachset.models import (
    Capability,
    CredentialKind,
    PrincipalKind,
    PrincipalStatus,
    Provenance,
    ResourceKind,
)


class _Record(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class PrincipalRecord(_Record):
    external_id: str
    kind: PrincipalKind
    display_name: str | None = None
    email: str | None = None
    status: PrincipalStatus = PrincipalStatus.ACTIVE
    created_at: datetime | None = None
    last_active_at: datetime | None = None


class CredentialRecord(_Record):
    external_id: str
    kind: CredentialKind
    principal_external_id: str | None = None
    issued_at: datetime | None = None
    last_used_at: datetime | None = None
    expires_at: datetime | None = None
    revoked_at: datetime | None = None


class ResourceRecord(_Record):
    external_id: str
    kind: ResourceKind
    path: str
    sensitivity: int = 0

    @field_validator("sensitivity")
    @classmethod
    def _sensitivity_range(cls, v: int) -> int:
        if not 0 <= v <= 3:
            raise ValueError(f"sensitivity must be 0..3, got {v}")
        return v


class GrantRecord(_Record):
    principal_external_id: str
    resource_selector: str
    scope_raw: str
    capabilities: frozenset[Capability]
    credential_external_id: str | None = None
    granted_by_external_id: str | None = None
    granted_at: datetime | None = None


class EventRecord(_Record):
    raw_ref: str
    action: str
    ts: datetime
    provenance: Provenance
    actor_external_id: str | None = None
    target_resource_external_id: str | None = None
    ip: str | None = None
    user_agent: str | None = None


class ExtractBatch(_Record):
    """One page of extracted records, in dependency order for upsert."""

    principals: Sequence[PrincipalRecord] = ()
    credentials: Sequence[CredentialRecord] = ()
    resources: Sequence[ResourceRecord] = ()
    grants: Sequence[GrantRecord] = ()
    events: Sequence[EventRecord] = ()

    def counts(self) -> dict[str, Any]:
        return {
            "principals": len(self.principals),
            "credentials": len(self.credentials),
            "resources": len(self.resources),
            "grants": len(self.grants),
            "events": len(self.events),
        }
