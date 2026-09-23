from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db.models import AuditLog, OutboxEvent


def test_create_case_records_audit_and_outbox(client: TestClient) -> None:
    res = client.post("/api/v1/cases", json={"url": "https://phish.example.com/login?token=abc"})
    assert res.status_code == 201
    body = res.json()
    assert body["duplicate"] is False
    assert body["case"]["url"] == "https://phish.example.com/login?token=abc"
    assert body["case"]["status"] == "queued"
    assert "created_by" not in body["case"]

    with client.app.state.session_factory() as db:
        audits = db.scalars(select(AuditLog).where(AuditLog.action == "case.create")).all()
        assert len(audits) == 1
        assert audits[0].actor == "admin"  # 로그인 사용자가 감사 로그에 남는다
        events = db.scalars(select(OutboxEvent)).all()
        assert len(events) == 1
        assert events[0].payload["case_id"] == body["case"]["id"]


def test_duplicate_url_returns_existing(client: TestClient) -> None:
    first = client.post("/api/v1/cases", json={"url": "https://dup.example.com/"}).json()
    res = client.post("/api/v1/cases", json={"url": "https://DUP.example.com/#frag"})
    assert res.status_code == 200
    assert res.json()["duplicate"] is True
    assert res.json()["case"]["id"] == first["case"]["id"]


def test_policy_violation_returns_code(client: TestClient) -> None:
    res = client.post("/api/v1/cases", json={"url": "http://169.254.169.254/"})
    assert res.status_code == 400
    assert res.json()["code"] == "ip_not_allowed"


def test_unknown_field_rejected_without_echo(client: TestClient) -> None:
    res = client.post("/api/v1/cases", json={"url": "https://a.example.com/", "role": "admin"})
    assert res.status_code == 422
    assert "admin" not in res.text


def test_list_and_get(client: TestClient) -> None:
    created = client.post("/api/v1/cases", json={"url": "https://list.example.com/"}).json()
    listing = client.get("/api/v1/cases?limit=10").json()
    assert listing["total"] == 1
    got = client.get(f"/api/v1/cases/{created['case']['id']}")
    assert got.status_code == 200


def test_invalid_id_and_missing_case(client: TestClient) -> None:
    assert client.get("/api/v1/cases/not-a-uuid").status_code == 422
    missing = client.get("/api/v1/cases/00000000-0000-0000-0000-000000000000")
    assert missing.status_code == 404
    assert missing.json()["code"] == "http_error"


def test_limit_is_bounded(client: TestClient) -> None:
    assert client.get("/api/v1/cases?limit=100000").status_code == 422


def test_security_headers(client: TestClient) -> None:
    res = client.get("/api/health")
    assert res.headers["X-Content-Type-Options"] == "nosniff"
    assert res.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'none'" in res.headers["Content-Security-Policy"]
    assert res.headers["Cache-Control"] == "no-store"
    assert len(res.headers["X-Request-ID"]) == 32


def test_unhandled_error_hides_details(client: TestClient) -> None:
    @client.app.get("/api/_boom")
    def boom() -> None:
        raise RuntimeError("secret db password in message")

    res = client.get("/api/_boom")
    assert res.status_code == 500
    assert "secret" not in res.text
    assert res.json()["code"] == "internal_error"
