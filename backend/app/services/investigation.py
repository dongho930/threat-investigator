"""조사 진행 상태와 증거 기록.

Worker는 DB에 직접 접근하지 않고 내부 API를 거쳐 이 함수들을 호출한다.
상태 전이는 여기서만 일어나며, 전이마다 감사 로그를 남긴다.

멱등 처리: 작업 메시지는 최소 1회 전달되므로 같은 작업이 여러 번 올 수 있다.
- 사건에는 가장 최근 발행한 작업 ID(current_job_id)만 기록하고, 그 작업만 claim·업로드·완료를 할 수 있다.
- 같은 작업의 재전달은 이어서 진행하고, 증거는 (사건, 종류, 작업) 단위로 한 건만 남긴다.
- 끝난 사건에 같은 작업이 완료를 다시 보고하면 현재 상태를 그대로 돌려준다.
"""

import hashlib
import hmac
import json
import logging
import uuid
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.db.models import AuditLog, Case, CaseStatus, Evidence, EvidenceKind
from app.services.evidence_store import LocalEvidenceStore

logger = logging.getLogger(__name__)

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
WEBM_SIGNATURE = b"\x1a\x45\xdf\xa3"  # EBML 헤더(WebM·Matroska)


class Outcome(StrEnum):
    COLLECTED = "collected"
    FAILED = "failed"


class FailureReason(StrEnum):
    """Worker가 보고할 수 있는 실패 사유. 외부 오류 메시지 원문은 받지 않는다."""

    BLOCKED_BY_POLICY = "blocked_by_policy"
    TOO_MANY_REDIRECTS = "too_many_redirects"
    NAVIGATION_TIMEOUT = "navigation_timeout"
    NAVIGATION_ERROR = "navigation_error"
    COLLECTOR_ERROR = "collector_error"
    COLLECTION_TIMEOUT = "collection_timeout"  # 수집 전체 시간 제한 초과(브라우저 강제 종료)


class SystemReason(StrEnum):
    """시스템(스위퍼)이 기록하는 사유."""

    RETRY_EXHAUSTED = "retry_exhausted"


def aware(dt: datetime | None) -> datetime | None:
    """SQLite는 시간대 정보를 버리므로 비교 전에 UTC로 맞춘다."""
    return dt.replace(tzinfo=UTC) if dt is not None and dt.tzinfo is None else dt


class InvestigationError(Exception):
    def __init__(self, code: str, message: str, status_code: int) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


def _not_found() -> InvestigationError:
    return InvestigationError("case_not_found", "사건을 찾을 수 없습니다.", 404)


def _audit(db: Session, action: str, case: Case, before: dict | None, after: dict | None) -> None:
    db.add(
        AuditLog(actor="worker", action=action, target_type="case", target_id=str(case.id), before=before, after=after)
    )


def _stale_job() -> InvestigationError:
    return InvestigationError("stale_job", "더 최신 작업이 발행된 사건입니다.", 409)


def claim_case(db: Session, case_id: uuid.UUID, job_id: uuid.UUID, settings: Settings) -> Case:
    """조사 시작. 사건의 현재 작업만 가져갈 수 있고, 가져가면 임대 시간을 준다.

    - 대기 중 → 조사 중(최초 전달)
    - 조사 중이고 같은 작업 → 재전달: 임대를 연장하고 이어서 진행
    - 다른(이전) 작업 → 409 stale_job, 끝난 사건 → 409 not_claimable
    """
    case = db.get(Case, case_id, with_for_update=True)
    if case is None:
        raise _not_found()
    if case.status not in (CaseStatus.QUEUED, CaseStatus.INVESTIGATING):
        raise InvestigationError("not_claimable", "조사할 수 없는 상태입니다.", 409)
    if case.current_job_id is None:
        # 멱등 처리 도입 전에 만든 사건: 처음 온 작업을 현재 작업으로 삼는다.
        case.current_job_id = job_id
        case.attempts = max(case.attempts, 1)
    elif case.current_job_id != job_id:
        raise _stale_job()
    if case.status is CaseStatus.QUEUED:
        _audit(
            db,
            "case.investigate.start",
            case,
            {"status": case.status.value},
            {"status": "investigating", "job_id": str(job_id), "attempt": case.attempts},
        )
        case.status = CaseStatus.INVESTIGATING
        case.status_reason = None
    case.lease_expires_at = datetime.now(UTC) + timedelta(seconds=settings.investigation_lease_seconds)
    db.commit()
    return case


def _validate_content(kind: EvidenceKind, data: bytes, content_type: str, settings: Settings) -> str:
    """종류별 형식·크기 검사. 통과하면 저장할 확장자를 돌려준다."""
    media_type = content_type.split(";", 1)[0].strip().lower()
    if kind is EvidenceKind.SCREENSHOT:
        if media_type != "image/png":
            raise InvestigationError("unsupported_media_type", "스크린샷은 PNG만 받습니다.", 415)
        if len(data) > settings.evidence_max_screenshot_bytes:
            raise InvestigationError("too_large", "증거 파일이 너무 큽니다.", 413)
        if not data.startswith(PNG_SIGNATURE):
            raise InvestigationError("invalid_content", "PNG 형식이 아닙니다.", 422)
        return "png"

    if kind is EvidenceKind.VIDEO:
        if media_type != "video/webm":
            raise InvestigationError("unsupported_media_type", "녹화는 WebM만 받습니다.", 415)
        if len(data) > settings.evidence_max_video_bytes:
            raise InvestigationError("too_large", "증거 파일이 너무 큽니다.", 413)
        if not data.startswith(WEBM_SIGNATURE):
            raise InvestigationError("invalid_content", "WebM 형식이 아닙니다.", 422)
        return "webm"

    if media_type != "application/json":
        raise InvestigationError("unsupported_media_type", "JSON만 받습니다.", 415)
    if len(data) > settings.evidence_max_json_bytes:
        raise InvestigationError("too_large", "증거 파일이 너무 큽니다.", 413)
    try:
        parsed = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvestigationError("invalid_content", "JSON 형식이 아닙니다.", 422) from exc
    if not isinstance(parsed, dict):
        raise InvestigationError("invalid_content", "JSON 객체여야 합니다.", 422)
    return "json"


def add_evidence(
    db: Session,
    store: LocalEvidenceStore,
    settings: Settings,
    *,
    case_id: uuid.UUID,
    job_id: uuid.UUID,
    kind: EvidenceKind,
    data: bytes,
    content_type: str,
    collector_version: str,
) -> tuple[Evidence, bool]:
    """증거를 저장한다. 같은 작업이 같은 종류를 다시 올리면 기존 증거를 돌려준다((증거, 새로 만들었는지))."""
    case = db.get(Case, case_id)
    if case is None:
        raise _not_found()
    if case.status is not CaseStatus.INVESTIGATING:
        raise InvestigationError("not_investigating", "조사 중인 사건에만 증거를 추가할 수 있습니다.", 409)
    if case.current_job_id != job_id:
        raise _stale_job()
    ext = _validate_content(kind, data, content_type, settings)
    existing = db.scalar(
        select(Evidence).where(Evidence.case_id == case_id, Evidence.kind == kind, Evidence.job_id == job_id)
    )
    if existing is not None:
        return existing, False

    version = (
        db.scalar(select(func.max(Evidence.version)).where(Evidence.case_id == case_id, Evidence.kind == kind)) or 0
    ) + 1
    stored = store.put(case_id, data, ext)
    now = datetime.now(UTC)
    evidence = Evidence(
        id=uuid.uuid4(),
        case_id=case_id,
        job_id=job_id,
        kind=kind,
        version=version,
        storage_key=stored.key,
        sha256=stored.sha256,
        size_bytes=stored.size_bytes,
        collector_version=collector_version,
        collected_at=now,
        retention_until=now + timedelta(days=settings.evidence_retention_days),
    )
    db.add(evidence)
    _audit(
        db,
        "evidence.add",
        case,
        None,
        {"kind": kind.value, "version": version, "sha256": stored.sha256, "job_id": str(job_id)},
    )
    try:
        db.commit()
    except IntegrityError as exc:
        # 같은 증거가 동시에 올라온 경우. 방금 쓴 파일은 고아가 되지 않도록 지운다.
        db.rollback()
        store.delete(stored.key)
        winner = db.scalar(
            select(Evidence).where(Evidence.case_id == case_id, Evidence.kind == kind, Evidence.job_id == job_id)
        )
        if winner is not None:
            return winner, False
        raise InvestigationError("version_conflict", "같은 증거가 동시에 등록되었습니다.", 409) from exc
    except Exception:
        db.rollback()
        store.delete(stored.key)
        raise
    return evidence, True


def complete_case(
    db: Session,
    case_id: uuid.UUID,
    job_id: uuid.UUID,
    outcome: Outcome,
    reason: FailureReason | None,
    *,
    ai_enabled: bool = False,
) -> tuple[Case, bool]:
    """조사 완료 보고. (사건, 이번 호출에서 상태가 바뀌었는지)를 돌려준다."""
    case = db.get(Case, case_id, with_for_update=True)
    if case is None:
        raise _not_found()
    if case.current_job_id != job_id:
        raise _stale_job()
    # judging은 ai-judge가 임대(lease)를 잡고 있을 수 있으므로 임대와 관계없이 완료된 것으로 본다.
    if case.status is CaseStatus.JUDGING or (
        case.status in (CaseStatus.REVIEW, CaseStatus.FAILED) and case.lease_expires_at is None
    ):
        # 같은 작업이 완료를 다시 보고한 경우(응답 유실 후 재시도): 현재 상태를 그대로 돌려준다.
        return case, False
    if case.status is not CaseStatus.INVESTIGATING:
        raise InvestigationError("not_investigating", "조사 중인 사건이 아닙니다.", 409)
    if outcome is Outcome.COLLECTED:
        # 규칙 판정을 기록한 뒤 담당자 검토로 넘긴다(판정은 라우트에서 증거 저장소와 함께 실행).
        # AI 판정을 켜면 judging에 두고 ai-judge가 모델 판단을 더한 뒤 검토로 넘긴다.
        new_status, new_reason = (CaseStatus.JUDGING if ai_enabled else CaseStatus.REVIEW), None
    else:
        new_status, new_reason = CaseStatus.FAILED, (reason or FailureReason.COLLECTOR_ERROR).value
    _audit(
        db,
        "case.investigate.finish",
        case,
        {"status": case.status.value},
        {"status": new_status.value, "reason": new_reason},
    )
    case.status = new_status
    case.status_reason = new_reason
    case.lease_expires_at = None
    db.commit()
    return case, True


def list_evidence(db: Session, case_id: uuid.UUID) -> list[Evidence]:
    return list(
        db.scalars(select(Evidence).where(Evidence.case_id == case_id).order_by(Evidence.kind, Evidence.version)).all()
    )


def read_evidence(
    db: Session, store: LocalEvidenceStore, *, case_id: uuid.UUID, evidence_id: uuid.UUID
) -> tuple[Evidence, bytes]:
    """증거를 읽으면서 기록된 SHA-256과 다시 대조한다. 다르면 내용을 돌려주지 않는다."""
    evidence = db.get(Evidence, evidence_id)
    if evidence is None or evidence.case_id != case_id:
        raise InvestigationError("evidence_not_found", "증거를 찾을 수 없습니다.", 404)
    try:
        data = store.get(evidence.storage_key)
    except FileNotFoundError as exc:
        logger.error("evidence file missing id=%s", evidence.id)
        raise InvestigationError("evidence_missing", "증거 파일이 없습니다.", 410) from exc
    if not hmac.compare_digest(hashlib.sha256(data).hexdigest(), evidence.sha256):
        logger.error("evidence integrity mismatch id=%s", evidence.id)
        raise InvestigationError("integrity_mismatch", "증거 무결성 검증에 실패했습니다.", 409)
    return evidence, data
