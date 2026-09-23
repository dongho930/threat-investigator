import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

os.environ["ENV"] = "test"
os.environ["DATABASE_URL"] = "sqlite+pysqlite:///:memory:"
os.environ["WORKER_API_TOKEN"] = "test-worker-token-0123456789abcdef"

WORKER_TOKEN = os.environ["WORKER_API_TOKEN"]


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from app.api import deps
    from app.db import session as db_session
    from app.db.models import Base
    from app.main import create_app
    from app.services.evidence_store import LocalEvidenceStore

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
    store = LocalEvidenceStore(tmp_path / "evidence")
    app.dependency_overrides[db_session.get_db] = override_db
    app.dependency_overrides[deps.get_evidence_store] = lambda: store
    app.state.session_factory = factory
    app.state.evidence_store = store
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
