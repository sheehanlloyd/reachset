"""index principal external_id for impersonation matching

Revision ID: 4552a499c0af
Revises: 171cb07e2ed3
Create Date: 2026-08-21 14:02:16.000000
"""

from collections.abc import Sequence

from alembic import op

revision: str = "4552a499c0af"
down_revision: str | None = "171cb07e2ed3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        "ix_principals_tenant_external_id",
        "principals",
        ["tenant_id", "external_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_principals_tenant_external_id", table_name="principals")
