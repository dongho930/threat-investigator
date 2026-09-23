"""login sessions, login attempts, case assignee and confirmed status

Revision ID: 0005
Revises: 0004
Create Date: 2026-09-24 10:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

OLD_STATUSES = ("queued", "investigating", "judging", "review", "reported", "held", "rejected", "failed")
NEW_STATUSES = ("queued", "investigating", "judging", "review", "confirmed", "reported", "held", "rejected", "failed")


def _status_enum(values: tuple[str, ...]) -> sa.Enum:
    return sa.Enum(*values, name="case_status", native_enum=False, create_constraint=True, length=32)


def upgrade() -> None:
    # native_enum=False라 허용값은 CHECK 제약(case_status)이다. 제약을 새 값 목록으로 바꾼다.
    with op.batch_alter_table("cases", recreate="auto") as batch:
        batch.alter_column("status", existing_type=_status_enum(OLD_STATUSES), type_=_status_enum(NEW_STATUSES))
        batch.add_column(sa.Column("assignee_id", sa.Uuid(), nullable=True))
        batch.create_foreign_key("fk_cases_assignee_id_users", "users", ["assignee_id"], ["id"])
        batch.create_index("ix_cases_assignee_id", ["assignee_id"], unique=False)

    op.create_table(
        "sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("token_sha256", sa.String(length=64), nullable=False),
        sa.Column("csrf_token", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_sha256"),
    )
    op.create_index(op.f("ix_sessions_user_id"), "sessions", ["user_id"], unique=False)

    op.create_table(
        "login_attempts",
        sa.Column("id", sa.BigInteger().with_variant(sa.Integer(), "sqlite"), autoincrement=True, nullable=False),
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("success", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_login_attempts_username"), "login_attempts", ["username"], unique=False)
    op.create_index(op.f("ix_login_attempts_created_at"), "login_attempts", ["created_at"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_login_attempts_created_at"), table_name="login_attempts")
    op.drop_index(op.f("ix_login_attempts_username"), table_name="login_attempts")
    op.drop_table("login_attempts")
    op.drop_index(op.f("ix_sessions_user_id"), table_name="sessions")
    op.drop_table("sessions")
    # 이전 CHECK 제약에는 confirmed가 없다. 확정된 사건은 검토 필요로 되돌린다(검토자 판정은 verdicts에 남아 있다).
    op.execute("UPDATE cases SET status = 'review' WHERE status = 'confirmed'")
    with op.batch_alter_table("cases", recreate="auto") as batch:
        batch.drop_index("ix_cases_assignee_id")
        batch.drop_constraint("fk_cases_assignee_id_users", type_="foreignkey")
        batch.drop_column("assignee_id")
        batch.alter_column("status", existing_type=_status_enum(NEW_STATUSES), type_=_status_enum(OLD_STATUSES))
