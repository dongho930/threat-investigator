"""판정 단계: 조사 작업의 증거를 읽어 규칙 판정을 기록한다.

- 증거는 해당 작업(job_id)이 올린 것만 쓰고, 읽을 때 SHA-256을 다시 대조한다(변조된 증거로 판정하지 않음).
- 판정은 버전으로 쌓인다(재조사·재판정 이력 보존). 시스템 판정은 decided_by=system이며 최종 결론이 아니다.
- 사건은 판정 뒤 담당자 검토(review)로 넘어간다. 자동 신고·차단은 하지 않는다.
"""

import hashlib
import hmac
import json
import logging
import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models import AuditLog, Case, DecidedBy, Evidence, EvidenceKind, Verdict, VerdictStatus
from app.judging import rules
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


def judge_case(db: Session, store: LocalEvidenceStore, case: Case, job_id: uuid.UUID, *, collected: bool) -> Verdict:
    evidence = {
        e.kind: e
        for e in db.scalars(select(Evidence).where(Evidence.case_id == case.id, Evidence.job_id == job_id)).all()
    }
    dom = _load_json(store, evidence.get(EvidenceKind.DOM_SUMMARY))
    chain = _load_json(store, evidence.get(EvidenceKind.REDIRECT_CHAIN))
    result = rules.evaluate(dom, chain, collected)

    version = (db.scalar(select(func.max(Verdict.version)).where(Verdict.case_id == case.id)) or 0) + 1
    rule_result = result.as_dict()
    rule_result["job_id"] = str(job_id)
    rule_result["evidence"] = {k.value: e.sha256 for k, e in evidence.items()}
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
