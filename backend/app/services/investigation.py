"""조사 진행 상태와 증거 기록.

Worker는 DB에 직접 접근하지 않고 내부 API를 거쳐 이 함수들을 호출한다.
상태 전이는 여기서만 일어나며, 전이마다 감사 로그를 남긴다.
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


def claim_case(db: Session, case_id: uuid.UUID) -> Case:
    """조사 시작. 대기 중이거나(최초) 조사 중인(재전달) 사건만 가져갈 수 있다."""
    case = db.get(Case, case_id, with_for_update=True)
    if case is None:
        raise _not_found()
    if case.status not in (CaseStatus.QUEUED, CaseStatus.INVESTIGATING):
        raise InvestigationError("not_claimable", "조사할 수 없는 상태입니다.", 409)
    if case.status is CaseStatus.QUEUED:
        _audit(db, "case.investigate.start", case, {"status": case.status.value}, {"status": "investigating"})
        case.status = CaseStatus.INVESTIGATING
        case.status_reason = None
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
    kind: EvidenceKind,
    data: bytes,
    content_type: str,
    collector_version: str,
) -> Evidence:
    case = db.get(Case, case_id)
    if case is None:
        raise _not_found()
    if case.status is not CaseStatus.INVESTIGATING:
        raise InvestigationError("not_investigating", "조사 중인 사건에만 증거를 추가할 수 있습니다.", 409)
    ext = _validate_content(kind, data, content_type, settings)

    version = (
        db.scalar(select(func.max(Evidence.version)).where(Evidence.case_id == case_id, Evidence.kind == kind)) or 0
    ) + 1
    stored = store.put(case_id, data, ext)
    now = datetime.now(UTC)
    evidence = Evidence(
        id=uuid.uuid4(),
        case_id=case_id,
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
    _audit(db, "evidence.add", case, None, {"kind": kind.value, "version": version, "sha256": stored.sha256})
    try:
        db.commit()
    except IntegrityError as exc:
        # 같은 종류·버전이 동시에 올라온 경우. 방금 쓴 파일은 고아가 되지 않도록 지운다.
        db.rollback()
        store.delete(stored.key)
        raise InvestigationError("version_conflict", "같은 증거가 동시에 등록되었습니다.", 409) from exc
    except Exception:
        db.rollback()
        store.delete(stored.key)
        raise
    return evidence


def complete_case(db: Session, case_id: uuid.UUID, outcome: Outcome, reason: FailureReason | None) -> Case:
    case = db.get(Case, case_id, with_for_update=True)
    if case is None:
        raise _not_found()
    if case.status is not CaseStatus.INVESTIGATING:
        raise InvestigationError("not_investigating", "조사 중인 사건이 아닙니다.", 409)
    if outcome is Outcome.COLLECTED:
        # 판정 엔진(4·5주차)이 붙기 전까지는 수집이 끝나면 담당자 검토로 넘긴다.
        new_status, new_reason = CaseStatus.REVIEW, None
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
    db.commit()
    return case


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
