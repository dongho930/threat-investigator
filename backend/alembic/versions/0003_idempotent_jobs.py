"""idempotent investigation jobs

Revision ID: 0003
Revises: 0002
Create Date: 2026-09-23 23:40:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("cases") as batch:
        batch.add_column(sa.Column("current_job_id", sa.Uuid(), nullable=True))
        batch.add_column(sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"))
    with op.batch_alter_table("evidence") as batch:
        batch.add_column(sa.Column("job_id", sa.Uuid(), nullable=True))
        batch.create_unique_constraint("uq_evidence_case_kind_job", ["case_id", "kind", "job_id"])


def downgrade() -> None:
    with op.batch_alter_table("evidence") as batch:
        batch.drop_constraint("uq_evidence_case_kind_job", type_="unique")
        batch.drop_column("job_id")
    with op.batch_alter_table("cases") as batch:
        batch.drop_column("attempts")
        batch.drop_column("lease_expires_at")
        batch.drop_column("current_job_id")
