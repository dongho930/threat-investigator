"""콘솔 로그인·세션·CSRF 시험 (SC-SF-01, SC-SF-05)."""

import hashlib
import io
from collections.abc import Callable
from datetime import timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import cli
from app.db.models import LoginAttempt, User, UserSession, utcnow
from app.services.auth import SESSION_COOKIE
from tests.conftest import BASE_URL, PASSWORD, create_user, login


def _set_cookie_header(client: TestClient, username: str, password: str = PASSWORD) -> str:
    r = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.headers["set-cookie"]


def test_login_sets_hardened_cookie_and_returns_role(app: FastAPI, anon: TestClient) -> None:
    create_user(app, "kim", "investigator")
    r = anon.post("/api/v1/auth/login", json={"username": "Kim ", "password": PASSWORD})
    assert r.status_code == 200
    body = r.json()
    assert body["username"] == "kim" and body["role"] == "investigator"
    assert "case:create" in body["permissions"] and "case:review" not in body["permissions"]
    assert len(body["csrf_token"]) >= 32

    cookie = r.headers["set-cookie"]
    assert cookie.startswith(f"{SESSION_COOKIE}=")
    lowered = cookie.lower()
    for flag in ("httponly", "secure", "samesite=strict", "path=/"):
        assert flag in lowered
    assert "domain=" not in lowered  # __Host- 접두사 조건


def test_password_is_argon2id_and_token_is_stored_hashed(app: FastAPI, anon: TestClient) -> None:
    create_user(app, "kim", "investigator")
    cookie = _set_cookie_header(anon, "kim")
    token = cookie.split(";", 1)[0].split("=", 1)[1]
    with app.state.session_factory() as db:
        user = db.scalar(select(User).where(User.username == "kim"))
        assert user.password_hash.startswith("$argon2id$")
        session = db.scalar(select(UserSession))
        assert session.token_sha256 == hashlib.sha256(token.encode()).hexdigest()
        assert token not in (session.token_sha256, session.csrf_token)


@pytest.mark.parametrize(
    ("username", "password", "active"),
    [("kim", "wrong-password-123", True), ("nobody", PASSWORD, True), ("kim", PASSWORD, False)],
    ids=["wrong_password", "unknown_user", "inactive_user"],
)
def test_login_failures_look_identical(
    app: FastAPI, anon: TestClient, username: str, password: str, active: bool
) -> None:
    create_user(app, "kim", "investigator", active=active)
    r = anon.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert r.status_code == 401
    assert r.json() == {"code": "invalid_credentials", "detail": "아이디 또는 비밀번호가 올바르지 않습니다."}
    assert "set-cookie" not in r.headers


def test_login_is_locked_after_repeated_failures(app: FastAPI, anon: TestClient) -> None:
    create_user(app, "kim", "investigator")
    for _ in range(5):
        assert (
            anon.post("/api/v1/auth/login", json={"username": "kim", "password": "wrong-password"}).status_code == 401
        )
    # 제한에 걸리면 맞는 비밀번호도 확인하지 않는다.
    r = anon.post("/api/v1/auth/login", json={"username": "kim", "password": PASSWORD})
    assert r.status_code == 429 and r.json()["code"] == "login_locked"

    # 제한 시간이 지나면 다시 로그인할 수 있다.
    with app.state.session_factory() as db:
        for attempt in db.scalars(select(LoginAttempt)):
            attempt.created_at = utcnow() - timedelta(minutes=16)
        db.commit()
    assert anon.post("/api/v1/auth/login", json={"username": "kim", "password": PASSWORD}).status_code == 200


def test_successful_login_resets_failure_count(app: FastAPI, anon: TestClient) -> None:
    create_user(app, "kim", "investigator")
    for _ in range(4):
        anon.post("/api/v1/auth/login", json={"username": "kim", "password": "wrong-password"})
    assert anon.post("/api/v1/auth/login", json={"username": "kim", "password": PASSWORD}).status_code == 200
    for _ in range(4):
        anon.post("/api/v1/auth/login", json={"username": "kim", "password": "wrong-password"})
    assert anon.post("/api/v1/auth/login", json={"username": "kim", "password": PASSWORD}).status_code == 200


def test_console_api_requires_session(anon: TestClient) -> None:
    r = anon.get("/api/v1/cases")
    assert r.status_code == 401 and r.json()["code"] == "unauthenticated"
    anon.cookies.set(SESSION_COOKIE, "forged-token")
    assert anon.get("/api/v1/cases").status_code == 401


def test_worker_token_does_not_open_console_api(anon: TestClient) -> None:
    from tests.conftest import WORKER_TOKEN

    r = anon.get("/api/v1/cases", headers={"Authorization": f"Bearer {WORKER_TOKEN}"})
    assert r.status_code == 401


@pytest.mark.parametrize("field", ["last_seen_at", "expires_at"], ids=["idle_timeout", "absolute_timeout"])
def test_expired_session_is_rejected_and_deleted(app: FastAPI, as_user: Callable[..., TestClient], field: str) -> None:
    c = as_user("kim", "investigator")
    assert c.get("/api/v1/auth/me").status_code == 200
    with app.state.session_factory() as db:
        session = db.scalar(select(UserSession))
        past = utcnow() - timedelta(hours=9)
        setattr(session, field, past)
        if field == "expires_at":
            session.last_seen_at = utcnow()
        db.commit()
    assert c.get("/api/v1/auth/me").status_code == 401
    with app.state.session_factory() as db:
        assert db.scalar(select(UserSession)) is None


def test_logout_invalidates_session(app: FastAPI, as_user: Callable[..., TestClient]) -> None:
    c = as_user("kim", "investigator")
    token = c.cookies.get(SESSION_COOKIE)
    assert c.post("/api/v1/auth/logout").status_code == 204
    replay = TestClient(app, base_url=BASE_URL)
    replay.cookies.set(SESSION_COOKIE, token)
    assert replay.get("/api/v1/auth/me").status_code == 401


def test_relogin_issues_new_session_and_drops_old(app: FastAPI, as_user: Callable[..., TestClient]) -> None:
    c = as_user("kim", "investigator")
    old = c.cookies.get(SESSION_COOKIE)
    r = c.post("/api/v1/auth/login", json={"username": "kim", "password": PASSWORD})
    assert r.status_code == 200
    assert c.cookies.get(SESSION_COOKIE) != old
    with app.state.session_factory() as db:
        assert len(db.scalars(select(UserSession)).all()) == 1


def test_deactivating_user_ends_active_session(app: FastAPI, as_user: Callable[..., TestClient]) -> None:
    c = as_user("kim", "investigator")
    with app.state.session_factory() as db:
        cli.set_active(db, "kim", False)
    assert c.get("/api/v1/cases").status_code == 401


# --- CSRF ---


def test_state_change_without_csrf_token_is_rejected(as_user: Callable[..., TestClient]) -> None:
    c = as_user("kim", "investigator")
    del c.headers["X-CSRF-Token"]
    r = c.post("/api/v1/cases", json={"url": "https://phish.example.com/"})
    assert r.status_code == 403 and r.json()["code"] == "csrf_failed"
    c.headers["X-CSRF-Token"] = "x" * 43
    assert c.post("/api/v1/cases", json={"url": "https://phish.example.com/"}).status_code == 403
    # 읽기 요청은 토큰 없이 된다.
    assert c.get("/api/v1/cases").status_code == 200


def test_csrf_token_of_other_session_is_rejected(app: FastAPI, as_user: Callable[..., TestClient]) -> None:
    kim = as_user("kim", "investigator")
    lee = as_user("lee", "investigator")
    kim.headers["X-CSRF-Token"] = lee.headers["X-CSRF-Token"]
    assert kim.post("/api/v1/cases", json={"url": "https://phish.example.com/"}).status_code == 403


def test_cross_site_requests_are_rejected_before_auth(app: FastAPI, as_user: Callable[..., TestClient]) -> None:
    create_user(app, "lee", "investigator")
    anon = TestClient(app, base_url=BASE_URL)
    r = anon.post(
        "/api/v1/auth/login",
        json={"username": "lee", "password": PASSWORD},
        headers={"Sec-Fetch-Site": "cross-site"},
    )
    assert r.status_code == 403 and r.json()["code"] == "cross_site_request"
    c = as_user("kim", "investigator")
    r = c.post("/api/v1/cases", json={"url": "https://phish.example.com/"}, headers={"Sec-Fetch-Site": "same-site"})
    assert r.status_code == 403
    ok = c.post("/api/v1/cases", json={"url": "https://phish.example.com/"}, headers={"Sec-Fetch-Site": "same-origin"})
    assert ok.status_code == 201


# --- 계정 관리 CLI ---


def test_cli_rejects_weak_password_and_bad_username(app: FastAPI, monkeypatch: pytest.MonkeyPatch) -> None:
    with app.state.session_factory() as db:
        monkeypatch.setattr("sys.stdin", io.StringIO("short\n"))
        with pytest.raises(cli.CliError):
            cli._read_password("kim", from_stdin=True)
        monkeypatch.setattr("sys.stdin", io.StringIO("kim-password-long\n"))
        with pytest.raises(cli.CliError):
            cli._read_password("kim", from_stdin=True)
        with pytest.raises(cli.CliError):
            cli.create_user(db, "a b", "investigator", PASSWORD)
        cli.create_user(db, "Kim", "reviewer", PASSWORD)
        with pytest.raises(cli.CliError):
            cli.create_user(db, "kim", "reviewer", PASSWORD)
    assert login(app, "kim").get("/api/v1/auth/me").json()["role"] == "reviewer"


def test_cli_reset_password_ends_sessions(app: FastAPI, as_user: Callable[..., TestClient]) -> None:
    c = as_user("kim", "investigator")
    with app.state.session_factory() as db:
        cli.reset_password(db, "kim", "a-brand-new-passphrase")
    assert c.get("/api/v1/auth/me").status_code == 401
    assert login(app, "kim", "a-brand-new-passphrase").get("/api/v1/auth/me").status_code == 200
