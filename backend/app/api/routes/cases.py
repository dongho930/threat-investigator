from typing import Annotated

from fastapi import APIRouter, Depends, Query, Response, status

from app.api.deps import AccessibleCase, DbDep, SettingsDep, require
from app.db.models import User, VerdictStatus
from app.judging import service as judging
from app.schemas.cases import AssignRequest, CaseCreate, CaseCreateResult, CaseList, CaseOut, ReviewRequest
from app.schemas.verdicts import VerdictOut
from app.security.rbac import Permission, can_access_case
from app.services import cases as case_service

router = APIRouter(prefix="/api/v1/cases", tags=["cases"])


@router.post("", response_model=CaseCreateResult, status_code=status.HTTP_201_CREATED)
def create_case(
    body: CaseCreate,
    db: DbDep,
    settings: SettingsDep,
    response: Response,
    user: Annotated[User, Depends(require(Permission.CASE_CREATE))],
) -> CaseCreateResult:
    case, duplicate = case_service.create_case(
        db, settings, url=body.url, note=body.note, actor=user.username, created_by=user.id
    )
    if duplicate:
        response.status_code = status.HTTP_200_OK
        if not can_access_case(user, case):
            # 이미 다른 담당자의 사건이다. 존재만 알리고 메모·상태는 돌려주지 않는다(배정은 검토자에게 요청).
            return CaseCreateResult(case=None, duplicate=True)
    return CaseCreateResult(case=CaseOut.model_validate(case), duplicate=duplicate)


@router.get("", response_model=CaseList)
def list_cases(
    db: DbDep,
    user: Annotated[User, Depends(require(Permission.CASE_READ))],
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> CaseList:
    items, total = case_service.list_cases(db, user, limit=limit, offset=offset)
    return CaseList(items=[CaseOut.model_validate(c) for c in items], total=total)


@router.get("/{case_id}", response_model=CaseOut, dependencies=[Depends(require(Permission.CASE_READ))])
def get_case(case: AccessibleCase) -> CaseOut:
    return CaseOut.model_validate(case)


@router.post("/{case_id}/assign", response_model=CaseOut)
def assign_case(
    body: AssignRequest,
    case: AccessibleCase,
    db: DbDep,
    user: Annotated[User, Depends(require(Permission.CASE_ASSIGN))],
) -> CaseOut:
    return CaseOut.model_validate(case_service.assign_case(db, case, user, body.assignee_id))


@router.post("/{case_id}/review", response_model=VerdictOut, status_code=status.HTTP_201_CREATED)
def review_case(
    body: ReviewRequest,
    case: AccessibleCase,
    db: DbDep,
    user: Annotated[User, Depends(require(Permission.CASE_REVIEW))],
) -> VerdictOut:
    """검토자의 판정 확정: SUSPICIOUS → 확정(제보 대기), BENIGN → 제외, UNKNOWN → 보류."""
    verdict = judging.review_case(
        db,
        case,
        user,
        decision=VerdictStatus(body.decision),
        suspected_types=[t.value for t in body.suspected_types],
        reason=body.reason,
    )
    return VerdictOut.model_validate(verdict)
