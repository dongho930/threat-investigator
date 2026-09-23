import os
from collections.abc import Callable, Iterator
from functools import lru_cache
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

os.environ["ENV"] = "test"
os.environ["DATABASE_URL"] = "sqlite+pysqlite:///:memory:"
os.environ["WORKER_API_TOKEN"] = "test-worker-token-0123456789abcdef"

WORKER_TOKEN = os.environ["WORKER_API_TOKEN"]
PASSWORD = "correct-horse-battery-7"
# 세션 쿠키는 Secure(__Host-)라 https 주소로 요청해야 쿠키가 실린다.
BASE_URL = "https://testserver"


@lru_cache
def _password_hash() -> str:
    # Argon2id 해시는 느리므로 시험 전체에서 한 번만 만든다.
    from app.security.passwords import hash_password

    return hash_password(PASSWORD)


def create_user(app: FastAPI, username: str, role: str, *, active: bool = True):  # noqa: ANN201
    from app.db.models import User, UserRole

    with app.state.session_factory() as db:
        user = User(username=username, password_hash=_password_hash(), role=UserRole(role), is_active=active)
        db.add(user)
        db.commit()
        return user


def login(app: FastAPI, username: str, password: str = PASSWORD) -> TestClient:
    """로그인한 새 클라이언트. 상태 변경 요청에 CSRF 헤더가 자동으로 붙는다."""
    c = TestClient(app, base_url=BASE_URL, raise_server_exceptions=False)
    r = c.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    c.headers["X-CSRF-Token"] = r.json()["csrf_token"]
    return c


@pytest.fixture
def app(tmp_path: Path) -> FastAPI:
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

    application = create_app()
    store = LocalEvidenceStore(tmp_path / "evidence")
    application.dependency_overrides[db_session.get_db] = override_db
    application.dependency_overrides[deps.get_evidence_store] = lambda: store
    application.state.session_factory = factory
    application.state.evidence_store = store
    return application


@pytest.fixture
def anon(app: FastAPI) -> TestClient:
    """로그인하지 않은 클라이언트."""
    return TestClient(app, base_url=BASE_URL, raise_server_exceptions=False)


@pytest.fixture
def as_user(app: FastAPI) -> Callable[..., TestClient]:
    """as_user("kim", "investigator") → 그 역할로 로그인한 클라이언트."""

    def make(username: str, role: str) -> TestClient:
        create_user(app, username, role)
        return login(app, username)

    return make


@pytest.fixture
def client(as_user: Callable[..., TestClient]) -> TestClient:
    """기존 기능 시험용: 모든 권한이 있는 관리자로 로그인한 클라이언트."""
    return as_user("admin", "admin")
