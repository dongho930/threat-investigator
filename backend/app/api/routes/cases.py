import uuid
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Response, status

from app.api.deps import DbDep, SettingsDep
from app.schemas.cases import CaseCreate, CaseCreateResult, CaseList, CaseOut
from app.services import cases as case_service

# TODO(4주차): 모든 라우트에 인증·RBAC 의존성 추가 (조사자: 등록·조회, 검토자: 판정 확정)
router = APIRouter(prefix="/api/v1/cases", tags=["cases"])


@router.post("", response_model=CaseCreateResult, status_code=status.HTTP_201_CREATED)
def create_case(body: CaseCreate, db: DbDep, settings: SettingsDep, response: Response) -> CaseCreateResult:
    case, duplicate = case_service.create_case(db, settings, url=body.url, note=body.note, actor="anonymous")
    if duplicate:
        response.status_code = status.HTTP_200_OK
    return CaseCreateResult(case=CaseOut.model_validate(case), duplicate=duplicate)


@router.get("", response_model=CaseList)
def list_cases(
    db: DbDep,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> CaseList:
    items, total = case_service.list_cases(db, limit=limit, offset=offset)
    return CaseList(items=[CaseOut.model_validate(c) for c in items], total=total)


@router.get("/{case_id}", response_model=CaseOut)
def get_case(case_id: uuid.UUID, db: DbDep) -> CaseOut:
    case = case_service.get_case(db, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="사건을 찾을 수 없습니다.")
    return CaseOut.model_validate(case)
