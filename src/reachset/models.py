"""Owns the canonical Postgres schema. Every table carries tenant_id.

Idempotency keys:
- principals/resources: (tenant_id, app_id, external_id)
- credentials: (tenant_id, kind, external_id) — credentials have no app_id in the
  canonical model; the external id (e.g. a Vault accessor) is unique per kind.
- grants: a deterministic dedupe_key hashed from the grant's identity fields,
  because upstream APIs mostly do not give grants a stable id of their own.
- events: (tenant_id, app_id, raw_ref) where raw_ref is a stable content hash.
"""

import enum
import hashlib
import uuid
from datetime import datetime
from typing import Any, ClassVar

from sqlalchemy import (
    JSON,
    BigInteger,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, TIMESTAMP, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class PrincipalKind(enum.StrEnum):
    HUMAN = "human"
    SERVICE = "service"
    AGENT = "agent"
    APP = "app"


class PrincipalStatus(enum.StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DEACTIVATED = "deactivated"
    DELETED = "deleted"


class CredentialKind(enum.StrEnum):
    OAUTH_TOKEN = "oauth_token"
    PAT = "pat"
    API_KEY = "api_key"
    VAULT_TOKEN = "vault_token"
    SESSION = "session"
    SSH_KEY = "ssh_key"


class ResourceKind(enum.StrEnum):
    REPO = "repo"
    SOBJECT = "sobject"
    SECRET_PATH = "secret_path"
    DRIVE_FILE = "drive_file"
    CHANNEL = "channel"
    MAILBOX = "mailbox"


class Capability(enum.StrEnum):
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"
    DELETE = "delete"
    IMPERSONATE = "impersonate"


class Provenance(enum.StrEnum):
    API = "api"
    AUDIT_LOG = "audit_log"
    INFERRED = "inferred"


class LinkMethod(enum.StrEnum):
    EXTERNAL_ID_EXACT = "external_id_exact"
    EMAIL_EXACT = "email_exact"
    SSO_SUBJECT = "sso_subject"
    FUZZY_NAME = "fuzzy_name"


def _enum(e: type[enum.StrEnum], name: str) -> Enum:
    # VARCHAR + CHECK rather than a native PG enum: adding values is a plain
    # migration instead of ALTER TYPE gymnastics.
    return Enum(e, name=name, native_enum=False, values_callable=lambda x: [i.value for i in x])


class Base(DeclarativeBase):
    type_annotation_map: ClassVar[dict[type, object]] = {
        datetime: TIMESTAMP(timezone=True),
        dict[str, Any]: JSONB().with_variant(JSON(), "sqlite"),
        list[dict[str, Any]]: JSONB().with_variant(JSON(), "sqlite"),
    }


def _uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )


class Principal(Base):
    __tablename__ = "principals"
    __table_args__ = (
        UniqueConstraint("tenant_id", "app_id", "external_id", name="uq_principal_identity"),
        Index("ix_principals_tenant_kind", "tenant_id", "kind"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[str] = mapped_column(Text)
    app_id: Mapped[str] = mapped_column(Text)
    external_id: Mapped[str] = mapped_column(Text)
    kind: Mapped[PrincipalKind] = mapped_column(_enum(PrincipalKind, "principal_kind"))
    display_name: Mapped[str | None] = mapped_column(Text)
    email: Mapped[str | None] = mapped_column(Text)
    status: Mapped[PrincipalStatus] = mapped_column(
        _enum(PrincipalStatus, "principal_status"), default=PrincipalStatus.ACTIVE
    )
    created_at: Mapped[datetime | None]
    last_active_at: Mapped[datetime | None]
    first_seen_at: Mapped[datetime] = mapped_column(server_default=text("now()"))
    last_seen_at: Mapped[datetime] = mapped_column(server_default=text("now()"))


class Credential(Base):
    __tablename__ = "credentials"
    __table_args__ = (
        UniqueConstraint("tenant_id", "kind", "external_id", name="uq_credential_identity"),
        Index("ix_credentials_principal", "principal_id"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[str] = mapped_column(Text)
    principal_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("principals.id", ondelete="SET NULL")
    )
    kind: Mapped[CredentialKind] = mapped_column(_enum(CredentialKind, "credential_kind"))
    external_id: Mapped[str] = mapped_column(Text)
    issued_at: Mapped[datetime | None]
    last_used_at: Mapped[datetime | None]
    expires_at: Mapped[datetime | None]
    revoked_at: Mapped[datetime | None]


class Resource(Base):
    __tablename__ = "resources"
    __table_args__ = (
        UniqueConstraint("tenant_id", "app_id", "external_id", name="uq_resource_identity"),
        Index("ix_resources_tenant_path", "tenant_id", "path"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[str] = mapped_column(Text)
    app_id: Mapped[str] = mapped_column(Text)
    external_id: Mapped[str] = mapped_column(Text)
    kind: Mapped[ResourceKind] = mapped_column(_enum(ResourceKind, "resource_kind"))
    path: Mapped[str] = mapped_column(Text)
    sensitivity: Mapped[int] = mapped_column(Integer, default=0)


class Grant(Base):
    __tablename__ = "grants"
    __table_args__ = (
        UniqueConstraint("tenant_id", "dedupe_key", name="uq_grant_dedupe"),
        Index("ix_grants_principal", "principal_id"),
        Index("ix_grants_granted_by", "granted_by_principal_id"),
        Index("ix_grants_credential", "credential_id"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[str] = mapped_column(Text)
    principal_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("principals.id", ondelete="CASCADE"))
    credential_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("credentials.id", ondelete="SET NULL")
    )
    resource_selector: Mapped[str] = mapped_column(Text)
    scope_raw: Mapped[str] = mapped_column(Text)
    capabilities: Mapped[list[str]] = mapped_column(ARRAY(Text))
    granted_by_principal_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("principals.id", ondelete="SET NULL")
    )
    granted_at: Mapped[datetime | None]
    source_app_id: Mapped[str] = mapped_column(Text)
    dedupe_key: Mapped[str] = mapped_column(Text)
    first_seen_at: Mapped[datetime] = mapped_column(server_default=text("now()"))
    last_seen_at: Mapped[datetime] = mapped_column(server_default=text("now()"))

    @staticmethod
    def compute_dedupe_key(
        principal_external_id: str,
        credential_external_id: str | None,
        resource_selector: str,
        scope_raw: str,
        source_app_id: str,
    ) -> str:
        """Stable identity for a grant across syncs. Capabilities are deliberately
        excluded so a widened scope updates the same row (scope-expansion detection
        compares snapshots, not row counts)."""
        material = "\x1f".join(
            [
                principal_external_id,
                credential_external_id or "",
                resource_selector,
                scope_raw,
                source_app_id,
            ]
        )
        return hashlib.sha256(material.encode()).hexdigest()


class Event(Base):
    __tablename__ = "events"
    __table_args__ = (
        UniqueConstraint("tenant_id", "app_id", "raw_ref", name="uq_event_identity"),
        Index("ix_events_actor_ts", "actor_principal_id", "ts"),
        Index("ix_events_tenant_ts", "tenant_id", "ts"),
        Index("ix_events_target_resource", "target_resource_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(Text)
    app_id: Mapped[str] = mapped_column(Text)
    actor_principal_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("principals.id", ondelete="SET NULL")
    )
    action: Mapped[str] = mapped_column(Text)
    target_resource_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("resources.id", ondelete="SET NULL")
    )
    ts: Mapped[datetime]
    ip: Mapped[str | None] = mapped_column(Text)
    user_agent: Mapped[str | None] = mapped_column(Text)
    raw_ref: Mapped[str] = mapped_column(Text)
    provenance: Mapped[Provenance] = mapped_column(_enum(Provenance, "event_provenance"))


class IdentityLink(Base):
    __tablename__ = "identity_links"
    __table_args__ = (
        UniqueConstraint("principal_a", "principal_b", "method", name="uq_link_identity"),
        # principal_a is covered by the unique constraint's leading column;
        # principal_b needs its own index for the FK cascade.
        Index("ix_identity_links_principal_b", "principal_b"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    tenant_id: Mapped[str] = mapped_column(Text)
    principal_a: Mapped[uuid.UUID] = mapped_column(ForeignKey("principals.id", ondelete="CASCADE"))
    principal_b: Mapped[uuid.UUID] = mapped_column(ForeignKey("principals.id", ondelete="CASCADE"))
    method: Mapped[LinkMethod] = mapped_column(_enum(LinkMethod, "link_method"))
    confidence: Mapped[float] = mapped_column(Float)
    evidence_json: Mapped[dict[str, Any]] = mapped_column(default=dict)


class ReachEdge(Base):
    __tablename__ = "reach_edges"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "principal_id", "resource_id", "capability", name="uq_reach_edge"
        ),
        Index("ix_reach_edges_resource", "resource_id"),
        # uq_reach_edge leads with tenant_id, so it cannot serve a lookup by
        # principal alone — which is exactly what the FK cascade does when a
        # principal is deleted. Without this, deleting one principal sequentially
        # scans the whole edge table.
        Index("ix_reach_edges_principal", "principal_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(Text)
    principal_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("principals.id", ondelete="CASCADE"))
    resource_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("resources.id", ondelete="CASCADE"))
    capability: Mapped[Capability] = mapped_column(_enum(Capability, "capability"))
    path_json: Mapped[list[dict[str, Any]]] = mapped_column(default=list)
    confidence: Mapped[float] = mapped_column(Float)
    computed_at: Mapped[datetime] = mapped_column(server_default=text("now()"))


class SyncWatermark(Base):
    __tablename__ = "sync_watermarks"

    tenant_id: Mapped[str] = mapped_column(Text, primary_key=True)
    app_id: Mapped[str] = mapped_column(Text, primary_key=True)
    stream: Mapped[str] = mapped_column(Text, primary_key=True)
    cursor: Mapped[str | None] = mapped_column(Text)
    last_success_at: Mapped[datetime | None]
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)


class DeadLetter(Base):
    __tablename__ = "dead_letters"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(Text)
    app_id: Mapped[str] = mapped_column(Text)
    stream: Mapped[str] = mapped_column(Text)
    payload: Mapped[dict[str, Any]] = mapped_column(default=dict)
    error: Mapped[str] = mapped_column(Text)
    attempts: Mapped[int] = mapped_column(Integer)
    first_failed_at: Mapped[datetime] = mapped_column(server_default=text("now()"))
