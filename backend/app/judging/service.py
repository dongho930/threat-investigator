"""판정 단계: 조사 작업의 증거를 읽어 규칙 판정을 기록한다.

- 증거는 해당 작업(job_id)이 올린 것만 쓰고, 읽을 때 SHA-256을 다시 대조한다(변조된 증거로 판정하지 않음).
- 판정은 버전으로 쌓인다(재조사·재판정 이력 보존). 시스템 판정은 decided_by=system이며 최종 결론이 아니다.
- 사건은 판정 뒤 담당자 검토(review)로 넘어간다. 자동 신고·차단은 하지 않는다.
- 최종 결론은 검토자가 review_case로 확정한다(decided_by=human, 새 판정 버전). 자기가 등록한 사건은 확정할 수 없다.
"""

import hashlib
import hmac
import json
import logging
import uuid
from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models import (
    AuditLog,
    Case,
    CaseStatus,
    DecidedBy,
    Evidence,
    EvidenceKind,
    User,
    Verdict,
    VerdictStatus,
)
from app.judging import rules
from app.services.cases import CaseError
from app.services.evidence_store import LocalEvidenceStore

logger = logging.getLogger(__name__)


def _load_json(store: LocalEvidenceStore, evidence: Evidence | None) -> dict | None:
    if evidence is None:
        return None
    try:
        data = store.get(evidence.storage_key)
    except FileNotFoundError:
        logger.error("evidence file missing id=%s", evidence.id)
        return None
    if not hmac.compare_digest(hashlib.sha256(data).hexdigest(), evidence.sha256):
        logger.error("evidence integrity mismatch during judging id=%s", evidence.id)
        return None
    try:
        parsed = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


@dataclass
class JobEvidence:
    dom: dict | None
    chain: dict | None
    hashes: dict[str, str]


def load_job_evidence(db: Session, store: LocalEvidenceStore, case_id: uuid.UUID, job_id: uuid.UUID) -> JobEvidence:
    """해당 작업이 올린 증거만 읽는다. 읽을 때 SHA-256을 다시 대조하고, 어긋나면 없는 것으로 본다."""
    evidence = {
        e.kind: e
        for e in db.scalars(select(Evidence).where(Evidence.case_id == case_id, Evidence.job_id == job_id)).all()
    }
    return JobEvidence(
        dom=_load_json(store, evidence.get(EvidenceKind.DOM_SUMMARY)),
        chain=_load_json(store, evidence.get(EvidenceKind.REDIRECT_CHAIN)),
        hashes={k.value: e.sha256 for k, e in evidence.items()},
    )


def rule_result_dict(ev: JobEvidence, job_id: uuid.UUID, *, collected: bool) -> tuple[rules.RuleResult, dict]:
    result = rules.evaluate(ev.dom, ev.chain, collected)
    rule_result = result.as_dict()
    rule_result["job_id"] = str(job_id)
    rule_result["evidence"] = ev.hashes
    return result, rule_result


def next_version(db: Session, case_id: uuid.UUID) -> int:
    return (db.scalar(select(func.max(Verdict.version)).where(Verdict.case_id == case_id)) or 0) + 1


def judge_case(db: Session, store: LocalEvidenceStore, case: Case, job_id: uuid.UUID, *, collected: bool) -> Verdict:
    """규칙 판정(기준선). AI 판정을 켜면 사건은 judging 상태로 남고 ai-judge가 모델 판단을 더한 새 버전을 쌓는다."""
    ev = load_job_evidence(db, store, case.id, job_id)
    result, rule_result = rule_result_dict(ev, job_id, collected=collected)
    version = next_version(db, case.id)
    verdict = Verdict(
        id=uuid.uuid4(),
        case_id=case.id,
        version=version,
        suspected_types=result.suspected_types,
        status=VerdictStatus(result.status),
        rule_result=rule_result,
        policy_reason=result.reason,
        decided_by=DecidedBy.SYSTEM,
    )
    db.add(verdict)
    db.add(
        AuditLog(
            actor="system",
            action="case.judge",
            target_type="case",
            target_id=str(case.id),
            after={
                "version": version,
                "status": result.status,
                "suspected_types": result.suspected_types,
                "rules": rules.RULES_VERSION,
            },
        )
    )
    db.commit()
    logger.info("judged case=%s version=%d status=%s types=%s", case.id, version, result.status, result.suspected_types)
    return verdict


def list_verdicts(db: Session, case_id: uuid.UUID) -> list[Verdict]:
    return list(db.scalars(select(Verdict).where(Verdict.case_id == case_id).order_by(Verdict.version.desc())).all())


REVIEWABLE = frozenset({CaseStatus.REVIEW, CaseStatus.HELD})
DECISION_STATUS = {
    VerdictStatus.SUSPICIOUS: CaseStatus.CONFIRMED,
    VerdictStatus.BENIGN: CaseStatus.REJECTED,
    VerdictStatus.UNKNOWN: CaseStatus.HELD,
}


def review_case(
    db: Session,
    case: Case,
    reviewer: User,
    *,
    decision: VerdictStatus,
    suspected_types: list[str],
    reason: str,
) -> Verdict:
    """검토자의 판정 확정. 새 판정 버전(decided_by=human)을 쌓고 사건 상태를 바꾼다."""
    # 같은 사건을 두 검토자가 동시에 확정해도 판정 버전이 겹치지 않도록 사건 행을 잠근다(PostgreSQL).
    locked = db.scalar(
        select(Case).where(Case.id == case.id).with_for_update().execution_options(populate_existing=True)
    )
    if locked is None:
        raise CaseError("not_found", "사건을 찾을 수 없습니다.", 404)
    if locked.status not in REVIEWABLE:
        raise CaseError("not_reviewable", "검토 필요·보류 상태의 사건만 판정을 확정할 수 있습니다.", 409)
    if locked.created_by == reviewer.id:
        raise CaseError("self_review", "자기가 등록한 사건은 다른 검토자가 확정해야 합니다.", 403)

    version = (db.scalar(select(func.max(Verdict.version)).where(Verdict.case_id == locked.id)) or 0) + 1
    verdict = Verdict(
        id=uuid.uuid4(),
        case_id=locked.id,
        version=version,
        suspected_types=suspected_types,
        status=decision,
        rule_result={},
        policy_reason=reason.strip(),
        decided_by=DecidedBy.HUMAN,
        reviewer_id=reviewer.id,
    )
    before = locked.status
    locked.status = DECISION_STATUS[decision]
    db.add(verdict)
    db.add(
        AuditLog(
            actor=reviewer.username,
            action="case.review",
            target_type="case",
            target_id=str(locked.id),
            before={"status": before.value},
            after={
                "status": locked.status.value,
                "version": version,
                "decision": decision.value,
                "suspected_types": suspected_types,
            },
        )
    )
    db.commit()
    db.refresh(verdict)
    logger.info("case reviewed id=%s version=%d decision=%s by=%s", locked.id, version, decision, reviewer.username)
    return verdict
