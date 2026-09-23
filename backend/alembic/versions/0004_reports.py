"""reports table and report case source

Revision ID: 0004
Revises: 0003
Create Date: 2026-09-24 00:10:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

OLD_SOURCES = ("manual", "feed")
NEW_SOURCES = ("manual", "feed", "report")


def _source_enum(values: tuple[str, ...]) -> sa.Enum:
    return sa.Enum(*values, name="case_source", native_enum=False, create_constraint=True, length=32)


def upgrade() -> None:
    # native_enum=False라 허용값은 CHECK 제약(case_source)이다. 제약을 새 값 목록으로 바꾼다.
    with op.batch_alter_table("cases", recreate="auto") as batch:
        batch.alter_column("source", existing_type=_source_enum(OLD_SOURCES), type_=_source_enum(NEW_SOURCES))
    op.create_table(
        "reports",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("case_id", sa.Uuid(), nullable=False),
        sa.Column("report_no", sa.String(length=64), nullable=False),
        sa.Column("reported_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("url_reported", sa.Text(), nullable=False),
        sa.Column("note", sa.String(length=500), nullable=True),
        sa.Column("batch_id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("report_no"),
    )
    op.create_index(op.f("ix_reports_batch_id"), "reports", ["batch_id"], unique=False)
    op.create_index(op.f("ix_reports_case_id"), "reports", ["case_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_reports_case_id"), table_name="reports")
    op.drop_index(op.f("ix_reports_batch_id"), table_name="reports")
    op.drop_table("reports")
    with op.batch_alter_table("cases", recreate="auto") as batch:
        batch.alter_column("source", existing_type=_source_enum(NEW_SOURCES), type_=_source_enum(OLD_SOURCES))
