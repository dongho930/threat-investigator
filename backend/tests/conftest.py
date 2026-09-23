import os
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

os.environ["ENV"] = "test"
os.environ["DATABASE_URL"] = "sqlite+pysqlite:///:memory:"


@pytest.fixture
def client() -> Iterator[TestClient]:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from app.db import session as db_session
    from app.db.models import Base
    from app.main import create_app

    engine = create_engine(
        "sqlite+pysqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)

    def override_db() -> Iterator:
        s = factory()
        try:
            yield s
        finally:
            s.close()

    app = create_app()
    app.dependency_overrides[db_session.get_db] = override_db
    app.state.session_factory = factory
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
