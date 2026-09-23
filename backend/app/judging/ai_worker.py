"""AI 판정 처리기(ai-judge). 규칙 판정 뒤 judging 상태인 사건에 모델 판단을 더한다.

- 상태의 원본은 DB다. judging 사건을 임대(lease)로 하나씩 잡아 처리하므로 여러 개를 띄워도 겹치지 않는다.
- 모델 호출 중에는 DB 트랜잭션을 잡고 있지 않는다(잡기 → 모델 호출 → 다시 잠그고 기록).
- 기록 전에 사건이 아직 judging이고 같은 작업(current_job_id)인지 다시 확인한다
  (재조사로 바뀐 사건에 옛 결과를 쓰지 않음).
- 모델 실패는 정해진 코드로만 기록하고 보류(UNKNOWN)로 넘긴다. ai-judge 자체가 멈추면 스위퍼가 같은 처리를 한다.
- 실행: python -m app.judging.ai_worker (compose의 ai-judge, AI_MODEL=laya|qwen)
"""

import logging
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.db.models import AuditLog, Case, CaseStatus, DecidedBy, Verdict, VerdictStatus
from app.judging import injection, policy
from app.judging.models import LayaAdapter, LlamaCppAdapter, ModelAdapter, ModelError, ModelResult, build_facts
from app.judging.service import load_job_evidence, next_version, rule_result_dict
from app.services.evidence_store import LocalEvidenceStore
from app.services.investigation import aware

logger = logging.getLogger(__name__)


def make_adapter(settings: Settings) -> ModelAdapter | None:
    if settings.ai_model == "laya":
        return LayaAdapter(settings.laya_url, settings.ai_timeout_seconds)
    if settings.ai_model == "qwen":
        return LlamaCppAdapter(settings.llm_url, settings.llm_revision, settings.ai_timeout_seconds)
    return None


def claim_next(db: Session, settings: Settings, *, now: datetime | None = None) -> tuple[uuid.UUID, uuid.UUID] | None:
    """임대가 없거나 끝난 judging 사건 하나를 잡는다. (사건 ID, 작업 ID)."""
    now = now or datetime.now(UTC)
    case = db.scalar(
        select(Case)
        .where(
            Case.status == CaseStatus.JUDGING,
            or_(Case.lease_expires_at.is_(None), Case.lease_expires_at < now),
        )
        .order_by(Case.updated_at)
        .limit(1)
        .with_for_update(skip_locked=True)
    )
    if case is None or case.current_job_id is None:
        db.rollback()
        return None
    case.lease_expires_at = now + timedelta(seconds=settings.ai_timeout_seconds * 2)
    db.commit()
    return case.id, case.current_job_id


def model_record(
    model: ModelResult | None, error: str | None, injection_codes: list[str], used: bool
) -> dict[str, Any]:
    """verdicts.model_result에 남기는 값. 모델이 만든 자유 문장은 없다(선택지·정해진 신호 코드뿐)."""
    record: dict[str, Any] = {"used": used, "error": error, "injection": injection_codes}
    if model is not None:
        record.update(
            {
                "model": model.model,
                "revision": model.revision,
                "site_type": model.answer.site_type.value,
                "signals": [s.value for s in model.answer.signals],
                "confidence": model.confidence,
                "latency_ms": model.latency_ms,
                **model.extra,
            }
        )
    return record


def finish(
    db: Session,
    case_id: uuid.UUID,
    job_id: uuid.UUID,
    rule_result: dict[str, Any],
    combined: policy.Combined,
    record: dict[str, Any],
    *,
    actor: str = "ai-judge",
) -> Verdict | None:
    """모델 판단을 더한 새 판정 버전을 쌓고 사건을 검토로 넘긴다. 사건이 이미 바뀌었으면 아무것도 하지 않는다."""
    case = db.scalar(select(Case).where(Case.id == case_id).with_for_update().execution_options(populate_existing=True))
    if case is None or case.status is not CaseStatus.JUDGING or case.current_job_id != job_id:
        db.rollback()
        logger.info("ai judge skipped case=%s (state changed)", case_id)
        return None
    version = next_version(db, case.id)
    verdict = Verdict(
        id=uuid.uuid4(),
        case_id=case.id,
        version=version,
        suspected_types=combined.suspected_types,
        status=VerdictStatus(combined.status),
        rule_result=rule_result,
        model_result=record,
        policy_reason=combined.reason,
        decided_by=DecidedBy.SYSTEM,
    )
    db.add(verdict)
    case.status = CaseStatus.REVIEW
    case.lease_expires_at = None
    db.add(
        AuditLog(
            actor=actor,
            action="case.ai_judge",
            target_type="case",
            target_id=str(case.id),
            before={"status": "judging"},
            after={
                "status": "review",
                "version": version,
                "verdict": combined.status,
                "reason": combined.reason,
                "model": record.get("model"),
                "error": record.get("error"),
            },
        )
    )
    db.commit()
    logger.info("ai judged case=%s version=%d status=%s reason=%s", case.id, version, combined.status, combined.reason)
    return verdict


def judge_one(
    db: Session,
    store: LocalEvidenceStore,
    settings: Settings,
    adapter: ModelAdapter | None,
    case_id: uuid.UUID,
    job_id: uuid.UUID,
) -> Verdict | None:
    ev = load_job_evidence(db, store, case_id, job_id)
    _, rule_result = rule_result_dict(ev, job_id, collected=True)
    codes = injection.detect(ev.dom)
    model: ModelResult | None = None
    error: str | None = None
    if codes:
        pass  # 조작 시도 문구가 있는 페이지는 모델에 보내지 않는다
    elif adapter is None:
        error = "model_disabled"
    elif ev.dom is None:
        error = "no_page_summary"
    else:
        try:
            model = adapter.classify(build_facts(ev.dom, ev.chain))
        except ModelError as exc:
            error = exc.code
            logger.warning("model call failed case=%s code=%s", case_id, exc.code)
    combined = policy.combine(
        rule_result, model, model_error=error, injection=codes, min_confidence=settings.ai_min_confidence
    )
    return finish(db, case_id, job_id, rule_result, combined, model_record(model, error, codes, combined.model_used))


def fallback_stale(db: Session, settings: Settings, *, now: datetime | None = None) -> int:
    """ai-judge가 멈춰 judging에 오래 머문 사건을 보류(model_unavailable)로 넘긴다. 스위퍼가 부른다."""
    now = now or datetime.now(UTC)
    stale_before = now - timedelta(seconds=settings.ai_judge_stale_seconds)
    cases = db.scalars(
        select(Case)
        .where(
            Case.status == CaseStatus.JUDGING,
            or_(Case.lease_expires_at.is_(None), Case.lease_expires_at < now),
        )
        .with_for_update(skip_locked=True)
    ).all()
    targets = [(c.id, c.current_job_id) for c in cases if aware(c.updated_at) < stale_before and c.current_job_id]
    db.rollback()
    count = 0
    for case_id, job_id in targets:
        latest = db.scalar(
            select(Verdict)
            .where(Verdict.case_id == case_id, Verdict.decided_by == DecidedBy.SYSTEM)
            .order_by(Verdict.version.desc())
            .limit(1)
        )
        rule_result = dict(latest.rule_result) if latest is not None else {"status": "UNKNOWN", "suspected_types": []}
        combined = policy.combine(rule_result, None, model_error="judge_timeout", injection=[], min_confidence=1.0)
        record = model_record(None, "judge_timeout", [], used=False)
        if finish(db, case_id, job_id, rule_result, combined, record, actor="system") is not None:
            count += 1
    return count


def run_forever(session_factory: sessionmaker[Session], store: LocalEvidenceStore, settings: Settings) -> None:
    adapter = make_adapter(settings)
    logger.info("ai-judge started model=%s", settings.ai_model)
    while True:
        try:
            with session_factory() as db:
                claimed = claim_next(db, settings)
                if claimed is not None:
                    judge_one(db, store, settings, adapter, *claimed)
                    continue
        except Exception:
            logger.exception("ai-judge error")
        time.sleep(settings.ai_poll_seconds)


if __name__ == "__main__":
    from app.core.config import get_settings
    from app.core.logging import configure_logging
    from app.db.session import get_sessionmaker

    configure_logging()
    cfg = get_settings()
    run_forever(get_sessionmaker(), LocalEvidenceStore(cfg.evidence_dir), cfg)
