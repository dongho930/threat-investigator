from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException

from app.api.deps import AccessibleCase, DbDep, SettingsDep, read_csv_body, require
from app.db.models import User
from app.schemas.reports import ImportResult, ReportList, ReportOut
from app.security.rbac import Permission
from app.services import reports as report_service

router = APIRouter(tags=["reports"])

CSV_MEDIA_TYPES = frozenset({"text/csv", "application/csv", "application/vnd.ms-excel"})


@router.post("/api/v1/reports/import", response_model=ImportResult)
def import_reports(
    db: DbDep,
    settings: SettingsDep,
    body: Annotated[bytes, Depends(read_csv_body)],
    user: Annotated[User, Depends(require(Permission.REPORT_IMPORT))],
    content_type: Annotated[str, Header()] = "",
) -> ImportResult:
    """신고 목록 CSV(열: 접수번호, 신고일시, URL, 메모)를 등록한다. 본문은 CSV 파일 그대로 보낸다."""
    if content_type.split(";", 1)[0].strip().lower() not in CSV_MEDIA_TYPES:
        raise HTTPException(status_code=415, detail="CSV 파일(text/csv)만 받습니다.")
    summary = report_service.import_reports(db, settings, body, actor=user.username, created_by=user.id)
    return ImportResult(**summary.__dict__)


@router.get(
    "/api/v1/cases/{case_id}/reports",
    response_model=ReportList,
    dependencies=[Depends(require(Permission.CASE_READ))],
)
def list_case_reports(case: AccessibleCase, db: DbDep) -> ReportList:
    return ReportList(items=[ReportOut.model_validate(r) for r in report_service.list_reports(db, case.id)])
