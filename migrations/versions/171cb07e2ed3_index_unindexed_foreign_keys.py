"""index unindexed foreign keys

Revision ID: 171cb07e2ed3
Revises: d83b1ba52717
Create Date: 2026-08-20 15:23:08.000000
"""

from collections.abc import Sequence

from alembic import op

revision: str = "171cb07e2ed3"
down_revision: str | None = "d83b1ba52717"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index("ix_events_target_resource", "events", ["target_resource_id"], unique=False)
    op.create_index("ix_grants_credential", "grants", ["credential_id"], unique=False)
    op.create_index("ix_grants_granted_by", "grants", ["granted_by_principal_id"], unique=False)
    op.create_index(
        "ix_identity_links_principal_b", "identity_links", ["principal_b"], unique=False
    )
    op.create_index("ix_reach_edges_principal", "reach_edges", ["principal_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_reach_edges_principal", table_name="reach_edges")
    op.drop_index("ix_identity_links_principal_b", table_name="identity_links")
    op.drop_index("ix_grants_granted_by", table_name="grants")
    op.drop_index("ix_grants_credential", table_name="grants")
    op.drop_index("ix_events_target_resource", table_name="events")
