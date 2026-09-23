"""역할별 권한(RBAC)·사건 단위 접근(IDOR)·배정·검토자 판정 확정 시험 (SC-SF-02, SC-SF-03)."""

import uuid
from collections.abc import Callable

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.db.models import Case, CaseStatus, User
from tests.conftest import create_user

CSV = "text/csv"


def _create(c: TestClient, url: str = "https://phish.example.com/login") -> str:
    r = c.post("/api/v1/cases", json={"url": url, "note": "담당자 메모"})
    assert r.status_code == 201, r.text
    return r.json()["case"]["id"]


def _set_status(app: FastAPI, case_id: str, status: CaseStatus) -> None:
    with app.state.session_factory() as db:
        db.get(Case, uuid.UUID(case_id)).status = status
        db.commit()


def _user_id(app: FastAPI, username: str) -> str:
    with app.state.session_factory() as db:
        from sqlalchemy import select

        return str(db.scalar(select(User.id).where(User.username == username)))


CASE_ID = "00000000-0000-0000-0000-000000000001"
# (메서드, 경로, 본문) — 로그인하지 않으면 모두 401이어야 하는 콘솔 API 전체
CONSOLE_ENDPOINTS = [
    ("GET", "/api/v1/cases", None),
    ("POST", "/api/v1/cases", {"url": "https://a.example.com/"}),
    ("GET", f"/api/v1/cases/{CASE_ID}", None),
    ("POST", f"/api/v1/cases/{CASE_ID}/assign", {"assignee_id": CASE_ID}),
    ("POST", f"/api/v1/cases/{CASE_ID}/review", {"decision": "BENIGN", "reason": "x"}),
    ("GET", f"/api/v1/cases/{CASE_ID}/evidence", None),
    ("GET", f"/api/v1/cases/{CASE_ID}/evidence/{CASE_ID}/content", None),
    ("GET", f"/api/v1/cases/{CASE_ID}/verdicts", None),
    ("GET", f"/api/v1/cases/{CASE_ID}/reports", None),
    ("POST", "/api/v1/reports/import", None),
    ("GET", "/api/v1/users", None),
    ("GET", "/api/v1/auth/me", None),
    ("POST", "/api/v1/auth/logout", None),
]


@pytest.mark.parametrize(
    ("method", "path", "body"), CONSOLE_ENDPOINTS, ids=[f"{m} {p}" for m, p, _ in CONSOLE_ENDPOINTS]
)
def test_every_console_endpoint_requires_login(anon: TestClient, method: str, path: str, body: dict | None) -> None:
    r = anon.request(method, path, json=body)
    assert r.status_code == 401, (method, path, r.status_code)


def test_every_console_route_is_covered_by_the_list(app: FastAPI) -> None:
    """새 라우트를 추가하고 인증 시험 목록에 넣지 않으면 실패한다(인증 누락 방지)."""
    listed = {
        (m, p.replace(CASE_ID, "{case_id}", 1).replace(CASE_ID, "{evidence_id}")) for m, p, _ in CONSOLE_ENDPOINTS
    }
    public = {("POST", "/api/v1/auth/login"), ("GET", "/api/health")}
    for route in app.routes:
        path = getattr(route, "path", "")
        if not path.startswith("/api/") or path.startswith("/api/docs") or path == "/api/openapi.json":
            continue
        for method in route.methods - {"HEAD", "OPTIONS"}:
            assert (method, path) in listed | public, f"인증 시험 목록에 없는 라우트: {method} {path}"


# --- 역할별 권한 ---


def test_investigator_cannot_review_assign_or_list_users(app: FastAPI, as_user: Callable[..., TestClient]) -> None:
    kim = as_user("kim", "investigator")
    case_id = _create(kim)
    _set_status(app, case_id, CaseStatus.REVIEW)
    r = kim.post(f"/api/v1/cases/{case_id}/review", json={"decision": "BENIGN", "reason": "정상"})
    assert r.status_code == 403 and r.json()["code"] == "forbidden"
    assert kim.post(f"/api/v1/cases/{case_id}/assign", json={"assignee_id": _user_id(app, "kim")}).status_code == 403
    assert kim.get("/api/v1/users").status_code == 403


def test_reviewer_cannot_create_cases_or_import(as_user: Callable[..., TestClient]) -> None:
    park = as_user("park", "reviewer")
    assert park.post("/api/v1/cases", json={"url": "https://a.example.com/"}).status_code == 403
    r = park.post("/api/v1/reports/import", content=b"report_no,reported_at,url\n", headers={"Content-Type": CSV})
    assert r.status_code == 403


# --- 사건 단위 접근 (IDOR) ---


def test_investigator_cannot_see_other_investigators_case(app: FastAPI, as_user: Callable[..., TestClient]) -> None:
    kim = as_user("kim", "investigator")
    lee = as_user("lee", "investigator")
    case_id = _create(kim)
    # 증거가 하나 있는 상황을 만든다(증거 ID를 알아도 볼 수 없어야 한다).
    from tests.test_investigation_api import PNG, _claim, _put

    assert _claim(kim, case_id).status_code == 200
    ev = _put(kim, case_id, "screenshot", PNG, "image/png").json()

    for path in (
        f"/api/v1/cases/{case_id}",
        f"/api/v1/cases/{case_id}/evidence",
        f"/api/v1/cases/{case_id}/evidence/{ev['id']}/content",
        f"/api/v1/cases/{case_id}/verdicts",
        f"/api/v1/cases/{case_id}/reports",
    ):
        r = lee.get(path)
        # 없는 사건과 똑같이 404 (존재 여부도 알려 주지 않는다)
        assert r.status_code == 404, path
        assert r.json() == {"code": "http_error", "detail": "사건을 찾을 수 없습니다."}
    assert lee.get("/api/v1/cases").json() == {"items": [], "total": 0}
    assert kim.get(f"/api/v1/cases/{case_id}/evidence/{ev['id']}/content").status_code == 200


def test_duplicate_url_from_other_investigator_hides_case(as_user: Callable[..., TestClient]) -> None:
    kim = as_user("kim", "investigator")
    lee = as_user("lee", "investigator")
    _create(kim)
    r = lee.post("/api/v1/cases", json={"url": "https://phish.example.com/login"})
    assert r.status_code == 200
    assert r.json() == {"case": None, "duplicate": True}


def test_reviewer_sees_all_and_assignment_grants_access(app: FastAPI, as_user: Callable[..., TestClient]) -> None:
    kim = as_user("kim", "investigator")
    lee = as_user("lee", "investigator")
    park = as_user("park", "reviewer")
    case_id = _create(kim)
    assert park.get("/api/v1/cases").json()["total"] == 1

    r = park.post(f"/api/v1/cases/{case_id}/assign", json={"assignee_id": _user_id(app, "lee")})
    assert r.status_code == 200 and r.json()["assignee"] == "lee"
    assert lee.get(f"/api/v1/cases/{case_id}").status_code == 200
    assert lee.get("/api/v1/cases").json()["total"] == 1


@pytest.mark.parametrize("target", ["park", "gone", "missing"])
def test_only_active_investigators_can_be_assigned(
    app: FastAPI, as_user: Callable[..., TestClient], target: str
) -> None:
    kim = as_user("kim", "investigator")
    park = as_user("park", "reviewer")
    create_user(app, "gone", "investigator", active=False)
    case_id = _create(kim)
    assignee = str(uuid.uuid4()) if target == "missing" else _user_id(app, target)
    r = park.post(f"/api/v1/cases/{case_id}/assign", json={"assignee_id": assignee})
    assert r.status_code == 422 and r.json()["code"] == "invalid_assignee"


def test_users_endpoint_exposes_only_brief_fields(as_user: Callable[..., TestClient]) -> None:
    as_user("kim", "investigator")
    park = as_user("park", "reviewer")
    items = park.get("/api/v1/users", params={"role": "investigator"}).json()["items"]
    assert [u["username"] for u in items] == ["kim"]
    assert set(items[0]) == {"id", "username", "role"}


# --- 검토자 판정 확정 ---


def test_reviewer_confirms_case_as_new_human_verdict(app: FastAPI, as_user: Callable[..., TestClient]) -> None:
    kim = as_user("kim", "investigator")
    park = as_user("park", "reviewer")
    case_id = _create(kim)
    _set_status(app, case_id, CaseStatus.REVIEW)

    r = park.post(
        f"/api/v1/cases/{case_id}/review",
        json={"decision": "SUSPICIOUS", "suspected_types": ["PHISHING"], "reason": "은행 사칭 OTP 입력 폼"},
    )
    assert r.status_code == 201, r.text
    v = r.json()
    assert v["decided_by"] == "human" and v["reviewer"] == "park" and v["version"] == 1
    assert kim.get(f"/api/v1/cases/{case_id}").json()["status"] == "confirmed"

    # 확정된 사건은 다시 확정할 수 없다(보류·검토 필요 상태만 가능).
    again = park.post(f"/api/v1/cases/{case_id}/review", json={"decision": "BENIGN", "reason": "번복"})
    assert again.status_code == 409 and again.json()["code"] == "not_reviewable"


@pytest.mark.parametrize(("decision", "status"), [("BENIGN", "rejected"), ("UNKNOWN", "held")])
def test_review_decision_moves_case_status(
    app: FastAPI, as_user: Callable[..., TestClient], decision: str, status: str
) -> None:
    kim = as_user("kim", "investigator")
    park = as_user("park", "reviewer")
    case_id = _create(kim)
    _set_status(app, case_id, CaseStatus.REVIEW)
    assert (
        park.post(f"/api/v1/cases/{case_id}/review", json={"decision": decision, "reason": "사유"}).status_code == 201
    )
    assert park.get(f"/api/v1/cases/{case_id}").json()["status"] == status


def test_admin_cannot_confirm_own_case(app: FastAPI, client: TestClient) -> None:
    case_id = _create(client)
    _set_status(app, case_id, CaseStatus.REVIEW)
    r = client.post(f"/api/v1/cases/{case_id}/review", json={"decision": "BENIGN", "reason": "정상"})
    assert r.status_code == 403 and r.json()["code"] == "self_review"


def test_review_requires_reviewable_status(as_user: Callable[..., TestClient]) -> None:
    kim = as_user("kim", "investigator")
    park = as_user("park", "reviewer")
    case_id = _create(kim)  # queued
    r = park.post(f"/api/v1/cases/{case_id}/review", json={"decision": "BENIGN", "reason": "정상"})
    assert r.status_code == 409


@pytest.mark.parametrize(
    "body",
    [
        {"decision": "SUSPICIOUS", "reason": "유형 없음"},
        {"decision": "BENIGN", "suspected_types": ["PHISHING"], "reason": "유형 있음"},
        {"decision": "SUSPICIOUS", "suspected_types": ["PHISHING", "PHISHING"], "reason": "중복"},
        {"decision": "SUSPICIOUS", "suspected_types": ["NOT_A_TYPE"], "reason": "허용값 밖"},
        {"decision": "BENIGN", "reason": "   "},
        {"decision": "APPROVE", "reason": "허용값 밖"},
        {"decision": "BENIGN", "reason": "x", "reviewer_id": CASE_ID},
    ],
)
def test_review_body_is_validated(app: FastAPI, as_user: Callable[..., TestClient], body: dict) -> None:
    kim = as_user("kim", "investigator")
    park = as_user("park", "reviewer")
    case_id = _create(kim)
    _set_status(app, case_id, CaseStatus.REVIEW)
    assert park.post(f"/api/v1/cases/{case_id}/review", json=body).status_code == 422
