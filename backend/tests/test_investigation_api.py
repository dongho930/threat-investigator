import json
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db.models import AuditLog, Case, Evidence
from tests.conftest import WORKER_TOKEN

AUTH = {"Authorization": f"Bearer {WORKER_TOKEN}"}
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64


def _new_case(client: TestClient, url: str = "https://evidence.example.com/") -> str:
    return client.post("/api/v1/cases", json={"url": url}).json()["case"]["id"]


def _job(client: TestClient, case_id: str) -> str:
    """사건의 현재 작업 ID(outbox로 발행된 job_id)."""
    with client.app.state.session_factory() as db:
        return str(db.get(Case, uuid.UUID(case_id)).current_job_id)


def _claim(client: TestClient, case_id: str, headers: dict[str, str] | None = None, job: str | None = None):
    return client.post(
        f"/internal/v1/cases/{case_id}/claim",
        headers=AUTH if headers is None else headers,
        json={"job_id": job or _job(client, case_id)},
    )


def _complete(client: TestClient, case_id: str, **body: object):
    return client.post(
        f"/internal/v1/cases/{case_id}/complete", headers=AUTH, json={"job_id": _job(client, case_id), **body}
    )


def _claimed_case(client: TestClient) -> str:
    case_id = _new_case(client)
    assert _claim(client, case_id).status_code == 200
    return case_id


def _put(client: TestClient, case_id: str, kind: str, body: bytes, ctype: str, **headers: str):
    return client.put(
        f"/internal/v1/cases/{case_id}/evidence/{kind}",
        content=body,
        headers={**AUTH, "Content-Type": ctype, "X-Job-Id": _job(client, case_id), **headers},
    )


@pytest.mark.parametrize(
    "headers",
    [{}, {"Authorization": "Bearer wrong-token"}, {"Authorization": WORKER_TOKEN}, {"Authorization": "Basic x"}],
)
def test_internal_api_requires_worker_token(client: TestClient, headers: dict[str, str]) -> None:
    case_id = _new_case(client)
    res = _claim(client, case_id, headers=headers)
    assert res.status_code == 401
    assert WORKER_TOKEN not in res.text


def test_claim_returns_url_from_db_and_moves_to_investigating(client: TestClient) -> None:
    case_id = _new_case(client, "https://claim.example.com/login?x=1")
    res = _claim(client, case_id)
    assert res.status_code == 200
    assert res.json() == {"case_id": case_id, "url": "https://claim.example.com/login?x=1", "status": "investigating"}
    # 재전달된 메시지로 다시 claim해도 된다
    assert _claim(client, case_id).status_code == 200
    assert client.get(f"/api/v1/cases/{case_id}").json()["status"] == "investigating"


def test_claim_missing_case(client: TestClient) -> None:
    res = _claim(client, str(uuid.uuid4()), job=str(uuid.uuid4()))
    assert res.status_code == 404 and res.json()["code"] == "case_not_found"


def test_full_flow_stores_hashed_evidence_and_serves_it(client: TestClient) -> None:
    case_id = _claimed_case(client)
    shot = _put(client, case_id, "screenshot", PNG, "image/png", **{"X-Collector-Version": "worker/0.2.0"})
    assert shot.status_code == 201
    body = shot.json()
    assert body["version"] == 1 and body["size_bytes"] == len(PNG)
    assert body["collector_version"] == "worker/0.2.0"
    assert "storage_key" not in body

    dom = json.dumps({"title": "<script>alert(1)</script>"}).encode()
    assert _put(client, case_id, "dom_summary", dom, "application/json").status_code == 201

    done = _complete(client, case_id, outcome="collected")
    assert done.json()["status"] == "review"

    listing = client.get(f"/api/v1/cases/{case_id}/evidence").json()["items"]
    assert {e["kind"] for e in listing} == {"screenshot", "dom_summary"}

    content = client.get(f"/api/v1/cases/{case_id}/evidence/{body['id']}/content")
    assert content.status_code == 200
    assert content.content == PNG
    assert content.headers["content-type"] == "image/png"
    assert content.headers["x-evidence-sha256"] == body["sha256"]
    assert content.headers["x-content-type-options"] == "nosniff"

    with client.app.state.session_factory() as db:
        actions = [a.action for a in db.scalars(select(AuditLog).order_by(AuditLog.id)) if a.target_type == "case"]
    assert actions == [
        "case.create",
        "case.investigate.start",
        "evidence.add",
        "evidence.add",
        "case.investigate.finish",
        "case.judge",
    ]


def test_storage_key_is_server_generated(client: TestClient) -> None:
    case_id = _claimed_case(client)
    _put(client, case_id, "screenshot", PNG, "image/png")
    with client.app.state.session_factory() as db:
        key = db.scalars(select(Evidence)).one().storage_key
    assert key.startswith(f"{case_id}/") and key.endswith(".png")
    assert ".." not in key


def test_same_job_reupload_is_idempotent(client: TestClient) -> None:
    case_id = _claimed_case(client)
    first = _put(client, case_id, "screenshot", PNG, "image/png")
    again = _put(client, case_id, "screenshot", PNG + b"different bytes", "image/png")
    assert (first.status_code, again.status_code) == (201, 200)
    assert again.json()["id"] == first.json()["id"] and again.json()["version"] == 1
    with client.app.state.session_factory() as db:
        assert len(db.scalars(select(Evidence)).all()) == 1
    assert len(list(client.app.state.evidence_store.root.rglob("*.png"))) == 1


@pytest.mark.parametrize(
    ("kind", "body", "ctype", "status", "code"),
    [
        ("screenshot", b"GIF89a....", "image/png", 422, "invalid_content"),
        ("screenshot", PNG, "text/html", 415, "unsupported_media_type"),
        ("dom_summary", b"<html>", "application/json", 422, "invalid_content"),
        ("dom_summary", b"[1, 2]", "application/json", 422, "invalid_content"),
        ("dom_summary", b"{}", "text/plain", 415, "unsupported_media_type"),
        ("redirect_chain", b"\xff\xfe", "application/json", 422, "invalid_content"),
    ],
)
def test_invalid_evidence_rejected(
    client: TestClient, kind: str, body: bytes, ctype: str, status: int, code: str
) -> None:
    case_id = _claimed_case(client)
    res = _put(client, case_id, kind, body, ctype)
    assert res.status_code == status
    assert res.json()["code"] == code


def test_unknown_kind_and_bad_collector_version(client: TestClient) -> None:
    case_id = _claimed_case(client)
    assert _put(client, case_id, "..%2F..%2Fetc", b"{}", "application/json").status_code in (404, 422)
    bad = _put(client, case_id, "dom_summary", b"{}", "application/json", **{"X-Collector-Version": "a;rm -rf"})
    assert bad.status_code == 422


def test_oversized_evidence_rejected(client: TestClient) -> None:
    case_id = _claimed_case(client)
    big = b"{" + b" " * (1024 * 1024 + 10) + b"}"
    res = _put(client, case_id, "dom_summary", big, "application/json")
    assert res.status_code == 413


def test_evidence_only_while_investigating(client: TestClient) -> None:
    case_id = _new_case(client)
    res = _put(client, case_id, "screenshot", PNG, "image/png")
    assert res.status_code == 409 and res.json()["code"] == "not_investigating"


def test_failed_outcome_records_reason_code(client: TestClient) -> None:
    case_id = _claimed_case(client)
    res = _complete(client, case_id, outcome="failed", reason="blocked_by_policy")
    assert res.json() == {"case_id": case_id, "status": "failed", "status_reason": "blocked_by_policy"}
    assert client.get(f"/api/v1/cases/{case_id}").json()["status_reason"] == "blocked_by_policy"
    # 끝난 사건은 다시 가져갈 수 없다
    assert _claim(client, case_id).status_code == 409


def test_free_text_reason_rejected(client: TestClient) -> None:
    case_id = _claimed_case(client)
    res = _complete(client, case_id, outcome="failed", reason="Traceback: secret")
    assert res.status_code == 422


def test_tampered_evidence_is_not_served(client: TestClient) -> None:
    case_id = _claimed_case(client)
    evidence_id = _put(client, case_id, "screenshot", PNG, "image/png").json()["id"]
    with client.app.state.session_factory() as db:
        key = db.scalars(select(Evidence)).one().storage_key
    (client.app.state.evidence_store.root / key).write_bytes(PNG + b"tampered")

    res = client.get(f"/api/v1/cases/{case_id}/evidence/{evidence_id}/content")
    assert res.status_code == 409
    assert res.json()["code"] == "integrity_mismatch"


def test_evidence_of_other_case_not_served(client: TestClient) -> None:
    case_id = _claimed_case(client)
    evidence_id = _put(client, case_id, "screenshot", PNG, "image/png").json()["id"]
    other = _new_case(client, "https://other.example.com/")
    assert client.get(f"/api/v1/cases/{other}/evidence/{evidence_id}/content").status_code == 404


def test_internal_routes_not_under_public_api_prefix(client: TestClient) -> None:
    # nginx는 /api/만 프록시한다. 내부 API가 /api 아래로 새지 않았는지 확인한다.
    spec = client.get("/api/openapi.json").json()["paths"]
    internal = [p for p, ops in spec.items() if any("internal" in op.get("tags", []) for op in ops.values())]
    assert internal and all(p.startswith("/internal/") for p in internal)
