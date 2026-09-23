"""멈춘 사건 정리(스위퍼). outbox relay 프로세스가 주기적으로 실행한다.

- 대기(queued) 상태로 오래 머문 사건: 메시지가 유실됐거나 처리 없이 ACK된 경우
- 조사 중(investigating)인데 임대가 끝난 사건: Worker가 죽었거나 작업이 dead-letter로 간 경우

둘 다 새 작업 ID로 다시 발행한다. 이전 작업은 stale_job으로 거절되므로 두 작업이 함께 진행되지 않는다.
발행 횟수가 상한에 이르면 retry_exhausted로 실패 처리해 무한 재시도를 막는다(실패를 안전으로 두지 않는다).
"""

import logging
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.db.models import AuditLog, Case, CaseStatus, OutboxEvent
from app.services.cases import INVESTIGATE_TOPIC
from app.services.investigation import SystemReason, aware

logger = logging.getLogger(__name__)


def _unpublished_case_ids(db: Session) -> set[str]:
    """아직 Redis로 나가지 않은 작업이 있는 사건은 건드리지 않는다(relay가 늦는 것뿐일 수 있다)."""
    events = db.scalars(select(OutboxEvent).where(OutboxEvent.published_at.is_(None))).all()
    return {str(e.payload.get("case_id")) for e in events if isinstance(e.payload, dict)}


def sweep(db: Session, settings: Settings, *, now: datetime | None = None) -> dict[str, int]:
    now = now or datetime.now(UTC)
    stale_before = now - timedelta(seconds=settings.queued_stale_seconds)
    candidates = db.scalars(
        select(Case)
        .where(
            or_(
                Case.status == CaseStatus.QUEUED,
                Case.status == CaseStatus.INVESTIGATING,
            )
        )
        .with_for_update(skip_locked=True)
    ).all()
    pending = _unpublished_case_ids(db)
    counts = {"requeued": 0, "exhausted": 0}
    for case in candidates:
        if str(case.id) in pending:
            continue
        if case.status is CaseStatus.QUEUED:
            if aware(case.updated_at) >= stale_before:
                continue
            why = "stale_queued"
        else:
            lease = aware(case.lease_expires_at)
            if lease is not None and lease >= now:
                continue
            why = "lease_expired"

        before = {"status": case.status.value, "job_id": str(case.current_job_id), "attempts": case.attempts}
        if case.attempts >= settings.max_investigation_attempts:
            case.status = CaseStatus.FAILED
            case.status_reason = SystemReason.RETRY_EXHAUSTED.value
            case.lease_expires_at = None
            action, after = "case.retry_exhausted", {"status": "failed", "reason": case.status_reason, "why": why}
            counts["exhausted"] += 1
        else:
            job_id = uuid.uuid4()
            case.attempts += 1
            case.current_job_id = job_id
            case.status = CaseStatus.QUEUED
            case.lease_expires_at = None
            case.updated_at = now
            db.add(
                OutboxEvent(
                    topic=INVESTIGATE_TOPIC,
                    payload={
                        "job_id": str(job_id),
                        "case_id": str(case.id),
                        "stage": "investigate",
                        "attempt": case.attempts,
                    },
                )
            )
            action = "case.requeue"
            after = {"status": "queued", "job_id": str(job_id), "attempts": case.attempts, "why": why}
            counts["requeued"] += 1
        db.add(
            AuditLog(
                actor="system", action=action, target_type="case", target_id=str(case.id), before=before, after=after
            )
        )
    db.commit()
    if counts["requeued"] or counts["exhausted"]:
        logger.info("sweep requeued=%d exhausted=%d", counts["requeued"], counts["exhausted"])
    return counts
