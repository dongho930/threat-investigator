"""video evidence kind (investigation recording)

Revision ID: 0006
Revises: 0005
Create Date: 2026-09-24 12:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

OLD_KINDS = ("screenshot", "dom_summary", "redirect_chain", "network_summary")
NEW_KINDS = (*OLD_KINDS, "video")


def _kind_enum(values: tuple[str, ...]) -> sa.Enum:
    return sa.Enum(*values, name="evidence_kind", native_enum=False, create_constraint=True, length=32)


def upgrade() -> None:
    with op.batch_alter_table("evidence", recreate="auto") as batch:
        batch.alter_column("kind", existing_type=_kind_enum(OLD_KINDS), type_=_kind_enum(NEW_KINDS))


def downgrade() -> None:
    # 녹화 증거 행이 있으면 이전 CHECK 제약에 걸린다. 녹화 파일·행은 수동으로 정리한 뒤 되돌린다(증거를 자동 삭제하지 않음).
    with op.batch_alter_table("evidence", recreate="auto") as batch:
        batch.alter_column("kind", existing_type=_kind_enum(NEW_KINDS), type_=_kind_enum(OLD_KINDS))
