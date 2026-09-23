import logging
import uuid

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.logging import redact_url
from app.db.models import AuditLog, Case, CaseSource, OutboxEvent
from app.security.url_policy import normalize_candidate_url

logger = logging.getLogger(__name__)

INVESTIGATE_TOPIC = "investigate"


def create_case(db: Session, settings: Settings, *, url: str, note: str | None, actor: str) -> tuple[Case, bool]:
    """URL을 정책 검사 후 사건으로 등록한다. 같은 URL이 있으면 기존 사건을 돌려준다.

    사건·감사 로그·outbox 이벤트를 한 트랜잭션에 기록해, 작업 발행이 누락되거나 중복되지 않게 한다.
    """
    normalized = normalize_candidate_url(
        url,
        max_length=settings.url_max_length,
        allowed_ports=set(settings.url_allowed_ports),
        host_allowlist=set(settings.url_host_allowlist),
    )

    existing = db.scalar(select(Case).where(Case.url_sha256 == normalized.sha256))
    if existing is not None:
        return existing, True

    job_id = uuid.uuid4()
    case = Case(
        id=uuid.uuid4(),
        url_original=normalized.original,
        url_normalized=normalized.normalized,
        url_sha256=normalized.sha256,
        host=normalized.host,
        source=CaseSource.MANUAL,
        note=note,
        current_job_id=job_id,
        attempts=1,
    )
    db.add(case)
    db.add(
        AuditLog(
            actor=actor,
            action="case.create",
            target_type="case",
            target_id=str(case.id),
            after={"url": normalized.normalized, "source": CaseSource.MANUAL.value},
        )
    )
    db.add(
        OutboxEvent(
            topic=INVESTIGATE_TOPIC,
            payload={"job_id": str(job_id), "case_id": str(case.id), "stage": "investigate", "attempt": 1},
        )
    )
    try:
        db.commit()
    except IntegrityError:
        # 동시에 같은 URL이 등록된 경우: 먼저 커밋된 사건을 돌려준다.
        db.rollback()
        existing = db.scalar(select(Case).where(Case.url_sha256 == normalized.sha256))
        if existing is None:
            raise
        return existing, True

    logger.info("case created id=%s url=%s", case.id, redact_url(normalized.normalized))
    return case, False


def list_cases(db: Session, *, limit: int, offset: int) -> tuple[list[Case], int]:
    total = db.scalar(select(func.count()).select_from(Case)) or 0
    items = db.scalars(select(Case).order_by(Case.created_at.desc()).limit(limit).offset(offset)).all()
    return list(items), total


def get_case(db: Session, case_id: uuid.UUID) -> Case | None:
    return db.get(Case, case_id)
