"""조사 작업 멱등 처리와 멈춘 사건 정리(스위퍼) 시험 (SC-TS-02, SC-EH-03)."""

import uuid
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.config import get_settings
from app.db.models import AuditLog, Case, CaseStatus, Evidence, OutboxEvent
from app.services.sweeper import sweep
from tests.conftest import WORKER_TOKEN

AUTH = {"Authorization": f"Bearer {WORKER_TOKEN}"}
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64


def _new_case(client: TestClient, url: str = "https://idem.example.com/") -> str:
    return client.post("/api/v1/cases", json={"url": url}).json()["case"]["id"]


def _case(client: TestClient, case_id: str) -> Case:
    with client.app.state.session_factory() as db:
        return db.get(Case, uuid.UUID(case_id))


def _job(client: TestClient, case_id: str) -> str:
    return str(_case(client, case_id).current_job_id)


def _claim(client: TestClient, case_id: str, job: str):
    return client.post(f"/internal/v1/cases/{case_id}/claim", headers=AUTH, json={"job_id": job})


def _put(client: TestClient, case_id: str, job: str, kind: str = "screenshot"):
    return client.put(
        f"/internal/v1/cases/{case_id}/evidence/{kind}",
        content=PNG,
        headers={**AUTH, "Content-Type": "image/png", "X-Job-Id": job},
    )


def _complete(client: TestClient, case_id: str, job: str, **body: object):
    return client.post(
        f"/internal/v1/cases/{case_id}/complete", headers=AUTH, json={"job_id": job, "outcome": "collected", **body}
    )


def _publish_all(client: TestClient) -> None:
    """relay가 발행을 마친 상태로 만든다(스위퍼는 발행 대기 중인 사건을 건드리지 않는다)."""
    with client.app.state.session_factory() as db:
        for e in db.scalars(select(OutboxEvent).where(OutboxEvent.published_at.is_(None))):
            e.published_at = datetime.now(UTC)
        db.commit()


def _sweep(client: TestClient, *, after_s: int) -> dict[str, int]:
    with client.app.state.session_factory() as db:
        return sweep(db, get_settings(), now=datetime.now(UTC) + timedelta(seconds=after_s))


def test_create_issues_first_job_matching_outbox(client: TestClient) -> None:
    case_id = _new_case(client)
    case = _case(client, case_id)
    with client.app.state.session_factory() as db:
        event = db.scalars(select(OutboxEvent)).one()
    assert event.payload["job_id"] == str(case.current_job_id) and case.attempts == 1


def test_stale_job_is_rejected_everywhere(client: TestClient) -> None:
    case_id = _new_case(client)
    job = _job(client, case_id)
    other = str(uuid.uuid4())
    assert _claim(client, case_id, other).json()["code"] == "stale_job"
    assert _claim(client, case_id, job).status_code == 200
    assert _put(client, case_id, other).json()["code"] == "stale_job"
    assert _complete(client, case_id, other).json()["code"] == "stale_job"


def test_redelivered_job_resumes_and_extends_lease(client: TestClient) -> None:
    case_id = _new_case(client)
    job = _job(client, case_id)
    assert _claim(client, case_id, job).status_code == 200
    first_lease = _case(client, case_id).lease_expires_at
    assert _claim(client, case_id, job).status_code == 200
    assert _case(client, case_id).lease_expires_at >= first_lease
    with client.app.state.session_factory() as db:
        starts = db.scalars(select(AuditLog).where(AuditLog.action == "case.investigate.start")).all()
    assert len(starts) == 1


def test_complete_is_idempotent_for_same_job(client: TestClient) -> None:
    case_id = _new_case(client)
    job = _job(client, case_id)
    _claim(client, case_id, job)
    assert _complete(client, case_id, job).json()["status"] == "review"
    again = _complete(client, case_id, job)
    assert again.status_code == 200 and again.json()["status"] == "review"
    assert _case(client, case_id).lease_expires_at is None
    with client.app.state.session_factory() as db:
        finishes = db.scalars(select(AuditLog).where(AuditLog.action == "case.investigate.finish")).all()
    assert len(finishes) == 1


def test_sweeper_leaves_fresh_and_pending_cases_alone(client: TestClient) -> None:
    case_id = _new_case(client)
    # 발행 대기 중인 이벤트가 있으면(relay가 늦는 경우) 오래됐어도 건드리지 않는다.
    assert _sweep(client, after_s=10_000) == {"requeued": 0, "exhausted": 0, "ai_fallback": 0}
    _publish_all(client)
    # 발행은 됐지만 아직 오래되지 않은 대기 사건도 그대로 둔다.
    assert _sweep(client, after_s=10) == {"requeued": 0, "exhausted": 0, "ai_fallback": 0}
    assert _case(client, case_id).status is CaseStatus.QUEUED


def test_sweeper_requeues_stale_queued_case_with_new_job(client: TestClient) -> None:
    case_id = _new_case(client)
    old_job = _job(client, case_id)
    _publish_all(client)
    assert _sweep(client, after_s=get_settings().queued_stale_seconds + 1) == {
        "requeued": 1,
        "exhausted": 0,
        "ai_fallback": 0,
    }
    case = _case(client, case_id)
    assert case.status is CaseStatus.QUEUED and case.attempts == 2 and str(case.current_job_id) != old_job
    with client.app.state.session_factory() as db:
        payloads = [e.payload for e in db.scalars(select(OutboxEvent).order_by(OutboxEvent.id))]
        audit = db.scalars(select(AuditLog).where(AuditLog.action == "case.requeue")).one()
    assert payloads[-1] == {
        "job_id": str(case.current_job_id),
        "case_id": case_id,
        "stage": "investigate",
        "attempt": 2,
    }
    assert audit.actor == "system" and audit.after["why"] == "stale_queued"
    # 늦게 도착한 이전 작업 메시지는 거절된다.
    assert _claim(client, case_id, old_job).json()["code"] == "stale_job"


def test_sweeper_requeues_expired_lease_and_new_job_gets_next_version(client: TestClient) -> None:
    case_id = _new_case(client)
    job1 = _job(client, case_id)
    _claim(client, case_id, job1)
    assert _put(client, case_id, job1).json()["version"] == 1
    _publish_all(client)
    lease_s = get_settings().investigation_lease_seconds
    assert _sweep(client, after_s=lease_s - 60) == {"requeued": 0, "exhausted": 0, "ai_fallback": 0}
    assert _sweep(client, after_s=lease_s + 1) == {"requeued": 1, "exhausted": 0, "ai_fallback": 0}
    job2 = _job(client, case_id)
    assert _claim(client, case_id, job2).status_code == 200
    assert _put(client, case_id, job2).json()["version"] == 2
    with client.app.state.session_factory() as db:
        assert len(db.scalars(select(Evidence)).all()) == 2


def test_sweeper_fails_case_after_max_attempts(client: TestClient) -> None:
    case_id = _new_case(client)
    stale = get_settings().queued_stale_seconds + 1
    for _ in range(get_settings().max_investigation_attempts - 1):
        _publish_all(client)
        assert _sweep(client, after_s=stale)["requeued"] == 1
        stale += get_settings().queued_stale_seconds + 1
    _publish_all(client)
    assert _sweep(client, after_s=stale) == {"requeued": 0, "exhausted": 1, "ai_fallback": 0}
    case = _case(client, case_id)
    # 실패를 안전으로 두지 않는다: BENIGN이 아니라 failed + 사유
    assert case.status is CaseStatus.FAILED and case.status_reason == "retry_exhausted"
    assert client.get(f"/api/v1/cases/{case_id}").json()["status_reason"] == "retry_exhausted"


def test_legacy_case_without_job_accepts_first_job(client: TestClient) -> None:
    case_id = _new_case(client)
    with client.app.state.session_factory() as db:
        case = db.get(Case, uuid.UUID(case_id))
        case.current_job_id = None
        db.commit()
    job = str(uuid.uuid4())
    assert _claim(client, case_id, job).status_code == 200
    assert _job(client, case_id) == job


def test_claim_requires_job_id(client: TestClient) -> None:
    case_id = _new_case(client)
    res = client.post(f"/internal/v1/cases/{case_id}/claim", headers=AUTH)
    assert res.status_code == 422
    upload = client.put(
        f"/internal/v1/cases/{case_id}/evidence/screenshot",
        content=PNG,
        headers={**AUTH, "Content-Type": "image/png"},
    )
    assert upload.status_code == 422
