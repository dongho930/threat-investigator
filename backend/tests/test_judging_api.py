"""완료 보고 → 규칙 판정 기록 → 판정 이력 조회 흐름 시험."""

import json
import uuid
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db.models import AuditLog, Case, Evidence, Verdict
from app.judging.rules import RULES_VERSION
from tests.conftest import WORKER_TOKEN

AUTH = {"Authorization": f"Bearer {WORKER_TOKEN}"}
FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "dom" / "phishing.json").read_text(encoding="utf-8"))


def _start(client: TestClient, url: str = "https://judge.example.com/") -> tuple[str, str]:
    case_id = client.post("/api/v1/cases", json={"url": url}).json()["case"]["id"]
    with client.app.state.session_factory() as db:
        job = str(db.get(Case, uuid.UUID(case_id)).current_job_id)
    client.post(f"/internal/v1/cases/{case_id}/claim", headers=AUTH, json={"job_id": job})
    return case_id, job


def _upload(client: TestClient, case_id: str, job: str, kind: str, data: dict) -> None:
    res = client.put(
        f"/internal/v1/cases/{case_id}/evidence/{kind}",
        content=json.dumps(data, ensure_ascii=False).encode(),
        headers={**AUTH, "Content-Type": "application/json", "X-Job-Id": job},
    )
    assert res.status_code == 201


def _complete(client: TestClient, case_id: str, job: str, **body):
    return client.post(
        f"/internal/v1/cases/{case_id}/complete", headers=AUTH, json={"job_id": job, "outcome": "collected", **body}
    )


def test_collected_case_gets_rule_verdict(client: TestClient) -> None:
    case_id, job = _start(client)
    _upload(client, case_id, job, "dom_summary", FIXTURE["dom_summary"])
    _upload(client, case_id, job, "redirect_chain", FIXTURE["redirect_chain"])
    assert _complete(client, case_id, job).json()["status"] == "review"

    items = client.get(f"/api/v1/cases/{case_id}/verdicts").json()["items"]
    assert len(items) == 1
    v = items[0]
    assert (v["version"], v["status"], v["suspected_types"], v["decided_by"]) == (
        1,
        "SUSPICIOUS",
        ["PHISHING"],
        "system",
    )
    assert v["rule_result"]["version"] == RULES_VERSION and v["rule_result"]["job_id"] == job
    assert {s["code"] for s in v["rule_result"]["signals"]} >= {"P1_password_field", "P2_sensitive_field"}
    # 판정에 쓴 증거의 해시를 함께 남긴다(재현·검증용)
    assert set(v["rule_result"]["evidence"]) == {"dom_summary", "redirect_chain"}


def test_failed_collection_records_unknown_not_benign(client: TestClient) -> None:
    case_id, job = _start(client, "https://judge-fail.example.com/")
    _complete(client, case_id, job, outcome="failed", reason="navigation_error")
    v = client.get(f"/api/v1/cases/{case_id}/verdicts").json()["items"][0]
    assert v["status"] == "UNKNOWN" and v["policy_reason"] == "insufficient_evidence"


def test_repeated_complete_does_not_judge_twice(client: TestClient) -> None:
    case_id, job = _start(client, "https://judge-once.example.com/")
    _upload(client, case_id, job, "dom_summary", FIXTURE["dom_summary"])
    _complete(client, case_id, job)
    _complete(client, case_id, job)
    with client.app.state.session_factory() as db:
        assert len(db.scalars(select(Verdict)).all()) == 1
        assert len(db.scalars(select(AuditLog).where(AuditLog.action == "case.judge")).all()) == 1


def test_tampered_evidence_is_not_used_for_judging(client: TestClient) -> None:
    case_id, job = _start(client, "https://judge-tamper.example.com/")
    _upload(client, case_id, job, "dom_summary", FIXTURE["dom_summary"])
    with client.app.state.session_factory() as db:
        key = db.scalars(select(Evidence)).one().storage_key
    # 저장 후 파일을 '정상 페이지'처럼 바꿔치기해도 해시가 맞지 않으므로 판정에 쓰지 않는다.
    (client.app.state.evidence_store.root / key).write_text(json.dumps({"title": "정상"}), encoding="utf-8")
    _complete(client, case_id, job)
    v = client.get(f"/api/v1/cases/{case_id}/verdicts").json()["items"][0]
    assert v["status"] == "UNKNOWN" and v["policy_reason"] == "insufficient_evidence"


def test_only_current_job_evidence_is_judged(client: TestClient) -> None:
    """이전 작업이 올린 증거는 판정에 섞이지 않는다(작업 단위 증거)."""
    case_id, job = _start(client, "https://judge-job.example.com/")
    _complete(client, case_id, job)  # 증거 없이 완료 → 판단 불가
    v = client.get(f"/api/v1/cases/{case_id}/verdicts").json()["items"][0]
    assert v["status"] == "UNKNOWN" and v["rule_result"]["evidence"] == {}
