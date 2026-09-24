"""review drafts (AI review assist, reference only)

Revision ID: 0007
Revises: 0006
Create Date: 2026-09-24 14:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "review_drafts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("case_id", sa.Uuid(), nullable=False),
        sa.Column("job_id", sa.Uuid(), nullable=True),
        sa.Column("model", sa.String(length=64), nullable=False),
        sa.Column("suggestion", sa.JSON(), nullable=True),
        sa.Column("error", sa.String(length=64), nullable=True),
        sa.Column("api_called", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("case_id", "job_id", name="uq_review_drafts_case_job"),
    )
    op.create_index(op.f("ix_review_drafts_case_id"), "review_drafts", ["case_id"], unique=False)
    op.create_index(op.f("ix_review_drafts_created_at"), "review_drafts", ["created_at"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_review_drafts_created_at"), table_name="review_drafts")
    op.drop_index(op.f("ix_review_drafts_case_id"), table_name="review_drafts")
    op.drop_table("review_drafts")
