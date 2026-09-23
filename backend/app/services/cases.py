import logging
import uuid

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.logging import redact_url
from app.db.models import AuditLog, Case, CaseSource, OutboxEvent, User, UserRole
from app.security.rbac import case_visibility_filter
from app.security.url_policy import normalize_candidate_url

logger = logging.getLogger(__name__)

INVESTIGATE_TOPIC = "investigate"
FEED_TOPIC = "investigate_feed"  # 낮은 우선순위 스트림으로 발행된다


class CaseError(Exception):
    def __init__(self, code: str, message: str, status_code: int) -> None:
        super().__init__(code)
        self.code = code
        self.message = message
        self.status_code = status_code


def topic_for(source: CaseSource) -> str:
    return FEED_TOPIC if source is CaseSource.FEED else INVESTIGATE_TOPIC


def create_case(
    db: Session,
    settings: Settings,
    *,
    url: str,
    note: str | None,
    actor: str,
    source: CaseSource = CaseSource.MANUAL,
    source_ref: str | None = None,
    created_by: uuid.UUID | None = None,
) -> tuple[Case, bool]:
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
        source=source,
        source_ref=source_ref,
        note=note,
        created_by=created_by,
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
            after={"url": normalized.normalized, "source": source.value},
        )
    )
    db.add(
        OutboxEvent(
            topic=topic_for(source),
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


def list_cases(db: Session, user: User, *, limit: int, offset: int) -> tuple[list[Case], int]:
    """사용자가 볼 수 있는 사건만 센다·돌려준다(조사자는 자기가 등록했거나 배정받은 사건)."""
    visible = case_visibility_filter(user)
    total = db.scalar(select(func.count()).select_from(Case).where(visible)) or 0
    items = db.scalars(select(Case).where(visible).order_by(Case.created_at.desc()).limit(limit).offset(offset)).all()
    return list(items), total


def assign_case(db: Session, case: Case, actor: User, assignee_id: uuid.UUID) -> Case:
    """사건을 조사자에게 배정한다. 비활성 계정·조사자가 아닌 계정에는 배정할 수 없다."""
    assignee = db.get(User, assignee_id)
    if assignee is None or not assignee.is_active or assignee.role is not UserRole.INVESTIGATOR:
        raise CaseError("invalid_assignee", "배정할 수 없는 사용자입니다(활성 조사자만 배정 가능).", 422)
    before = str(case.assignee_id) if case.assignee_id else None
    case.assignee_id = assignee.id
    db.add(
        AuditLog(
            actor=actor.username,
            action="case.assign",
            target_type="case",
            target_id=str(case.id),
            before={"assignee_id": before},
            after={"assignee_id": str(assignee.id)},
        )
    )
    db.commit()
    db.refresh(case)
    logger.info("case assigned id=%s assignee=%s by=%s", case.id, assignee.username, actor.username)
    return case


def get_case(db: Session, case_id: uuid.UUID) -> Case | None:
    return db.get(Case, case_id)
