import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException

from app.api.deps import DbDep, SettingsDep, read_csv_body
from app.schemas.reports import ImportResult, ReportList, ReportOut
from app.services import reports as report_service

# TODO(2주차 판정·콘솔): 인증·RBAC 추가 (조사자 이상만 일괄 등록)
router = APIRouter(tags=["reports"])

CSV_MEDIA_TYPES = frozenset({"text/csv", "application/csv", "application/vnd.ms-excel"})


@router.post("/api/v1/reports/import", response_model=ImportResult)
def import_reports(
    db: DbDep,
    settings: SettingsDep,
    body: Annotated[bytes, Depends(read_csv_body)],
    content_type: Annotated[str, Header()] = "",
) -> ImportResult:
    """신고 목록 CSV(열: 접수번호, 신고일시, URL, 메모)를 등록한다. 본문은 CSV 파일 그대로 보낸다."""
    if content_type.split(";", 1)[0].strip().lower() not in CSV_MEDIA_TYPES:
        raise HTTPException(status_code=415, detail="CSV 파일(text/csv)만 받습니다.")
    summary = report_service.import_reports(db, settings, body, actor="anonymous")
    return ImportResult(**summary.__dict__)


@router.get("/api/v1/cases/{case_id}/reports", response_model=ReportList)
def list_case_reports(case_id: uuid.UUID, db: DbDep) -> ReportList:
    return ReportList(items=[ReportOut.model_validate(r) for r in report_service.list_reports(db, case_id)])
