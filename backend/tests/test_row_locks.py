"""행 잠금 쿼리 회귀 시험.

시험은 SQLite로 돌지만 운영은 PostgreSQL이다. PostgreSQL은 SELECT ... FOR UPDATE에 LEFT OUTER JOIN이 섞이면
거부한다(FeatureNotSupported). 잠그는 테이블의 관계를 joined로 읽으면 Worker의 claim·완료 보고가 500이 된다.
"""

import pytest
from sqlalchemy import inspect, select
from sqlalchemy.dialects import postgresql

from app.db.models import Case, OutboxEvent


@pytest.mark.parametrize("model", [Case, OutboxEvent])
def test_locked_tables_have_no_joined_eager_loads(model: type) -> None:
    joined = [r.key for r in inspect(model).relationships if r.lazy == "joined"]
    assert joined == []


def test_case_lock_query_has_no_outer_join_on_postgres() -> None:
    sql = str(select(Case).where(Case.id.is_not(None)).with_for_update().compile(dialect=postgresql.dialect()))
    assert "FOR UPDATE" in sql
    assert "JOIN" not in sql
