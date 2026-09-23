"""evidence size and case status reason

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-23 20:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("cases", sa.Column("status_reason", sa.String(length=64), nullable=True))
    # 기존 행이 있어도 추가할 수 있도록 기본값 0으로 만든 뒤 기본값을 제거한다.
    with op.batch_alter_table("evidence") as batch:
        batch.add_column(sa.Column("size_bytes", sa.Integer(), nullable=False, server_default="0"))
        batch.alter_column("size_bytes", server_default=None)


def downgrade() -> None:
    with op.batch_alter_table("evidence") as batch:
        batch.drop_column("size_bytes")
    op.drop_column("cases", "status_reason")
