import uuid

from fastapi import APIRouter

from app.api.deps import DbDep
from app.judging import service as judging
from app.schemas.verdicts import VerdictList, VerdictOut

# TODO(2주차 인증·RBAC): 인증·사건 단위 접근 확인 추가
router = APIRouter(prefix="/api/v1/cases/{case_id}/verdicts", tags=["verdicts"])


@router.get("", response_model=VerdictList)
def list_verdicts(case_id: uuid.UUID, db: DbDep) -> VerdictList:
    """판정 이력(최신 버전 먼저). 규칙 근거는 rule_result.signals에 있다."""
    return VerdictList(items=[VerdictOut.model_validate(v) for v in judging.list_verdicts(db, case_id)])
