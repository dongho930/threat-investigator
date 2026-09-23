from fastapi import APIRouter, Depends

from app.api.deps import AccessibleCase, DbDep, require
from app.judging import service as judging
from app.schemas.verdicts import VerdictList, VerdictOut
from app.security.rbac import Permission

router = APIRouter(
    prefix="/api/v1/cases/{case_id}/verdicts",
    tags=["verdicts"],
    dependencies=[Depends(require(Permission.CASE_READ))],
)


@router.get("", response_model=VerdictList)
def list_verdicts(case: AccessibleCase, db: DbDep) -> VerdictList:
    """판정 이력(최신 버전 먼저). 규칙 근거는 rule_result.signals에 있다."""
    return VerdictList(items=[VerdictOut.model_validate(v) for v in judging.list_verdicts(db, case.id)])
