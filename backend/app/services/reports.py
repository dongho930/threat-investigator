"""기관 신고 목록(CSV) 일괄 등록.

- 한 행이 신고 1건이다. 같은 URL의 신고는 한 사건에 병합하고, 신고(접수 번호·신고 시각·원본 URL)는 모두 남긴다.
- 파일은 신뢰하지 않는 입력이다. 크기·행 수를 제한하고, 행마다 URL 정책을 등록 화면과 똑같이 적용한다.
- 오류는 행 번호와 사유 코드로만 돌려준다(입력값을 응답에 그대로 반사하지 않는다).
- 같은 파일을 다시 올려도 접수 번호가 유일하므로 신고가 중복되지 않는다.
"""

import csv
import io
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.db.models import AuditLog, CaseSource, Report
from app.security.url_policy import UrlPolicyError
from app.services.cases import create_case

logger = logging.getLogger(__name__)

KST = timezone(timedelta(hours=9))  # 시간대가 없는 신고 시각은 한국 시간으로 본다(한국은 서머타임 없음)
MAX_ERRORS = 200
_REPORT_NO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-]{0,63}$")
_HEADER_ALIASES = {
    "접수번호": "report_no",
    "접수 번호": "report_no",
    "report_no": "report_no",
    "신고일시": "reported_at",
    "신고 일시": "reported_at",
    "신고시각": "reported_at",
    "reported_at": "reported_at",
    "url": "url",
    "신고url": "url",
    "메모": "note",
    "비고": "note",
    "note": "note",
}
REQUIRED = ("report_no", "reported_at", "url")
_DATE_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d", "%Y/%m/%d %H:%M:%S", "%Y/%m/%d %H:%M", "%Y/%m/%d")


class ReportImportError(Exception):
    """파일 전체를 거부하는 오류."""

    def __init__(self, code: str, message: str, status_code: int = 422) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


@dataclass
class ImportSummary:
    batch_id: uuid.UUID
    total: int = 0
    created: int = 0
    merged: int = 0
    duplicate: int = 0
    rejected: int = 0
    errors: list[dict[str, object]] = field(default_factory=list)

    def reject(self, row: int, code: str) -> None:
        self.rejected += 1
        if len(self.errors) < MAX_ERRORS:
            self.errors.append({"row": row, "code": code})


def decode_csv(data: bytes) -> str:
    """UTF-8(BOM 포함)을 먼저 시도하고, 한국어 Windows Excel이 저장하는 CP949로 한 번 더 시도한다."""
    for encoding in ("utf-8-sig", "cp949"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    raise ReportImportError("invalid_encoding", "UTF-8 또는 CP949 CSV만 받습니다.")


def parse_reported_at(value: str, now: datetime) -> datetime:
    text = value.strip()
    parsed: datetime | None = None
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        for fmt in _DATE_FORMATS:
            try:
                parsed = datetime.strptime(text, fmt)  # noqa: DTZ007 - 아래에서 KST를 붙인다
                break
            except ValueError:
                continue
    if parsed is None:
        raise ValueError("invalid_reported_at")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=KST)
    if parsed > now + timedelta(days=1):
        raise ValueError("future_reported_at")
    return parsed.astimezone(UTC)


def _read_rows(text: str, max_rows: int) -> list[dict[str, str]]:
    reader = csv.reader(io.StringIO(text, newline=""))
    try:
        header = next(reader)
    except StopIteration as exc:
        raise ReportImportError("empty_file", "비어 있는 파일입니다.") from exc
    # BOM은 decode_csv(utf-8-sig)에서 이미 제거된다.
    columns = [_HEADER_ALIASES.get(h.strip().lower()) for h in header]
    missing = [c for c in REQUIRED if c not in columns]
    if missing:
        raise ReportImportError("missing_columns", "필수 열(접수번호, 신고일시, URL)이 없습니다.")
    rows: list[dict[str, str]] = []
    try:
        for values in reader:
            if not any(v.strip() for v in values):
                continue  # 빈 줄은 건너뛴다
            if len(rows) >= max_rows:
                raise ReportImportError("too_many_rows", f"한 번에 {max_rows}행까지 등록할 수 있습니다.", 413)
            row = {col: values[i].strip() for i, col in enumerate(columns) if col and i < len(values)}
            row["_line"] = str(reader.line_num)
            rows.append(row)
    except csv.Error as exc:
        raise ReportImportError("invalid_csv", "CSV 형식이 올바르지 않습니다.") from exc
    return rows


def import_reports(
    db: Session, settings: Settings, data: bytes, *, actor: str, created_by: uuid.UUID | None = None
) -> ImportSummary:
    rows = _read_rows(decode_csv(data), settings.report_import_max_rows)
    summary = ImportSummary(batch_id=uuid.uuid4(), total=len(rows))
    now = datetime.now(UTC)
    seen: set[str] = set()

    for row in rows:
        line = int(row["_line"])
        report_no = row.get("report_no", "")
        if not _REPORT_NO.match(report_no):
            summary.reject(line, "invalid_report_no")
            continue
        if report_no in seen:
            summary.reject(line, "duplicate_in_file")
            continue
        seen.add(report_no)
        try:
            reported_at = parse_reported_at(row.get("reported_at", ""), now)
        except ValueError as exc:
            summary.reject(line, str(exc))
            continue
        note = row.get("note") or None
        if note is not None and len(note) > 500:
            summary.reject(line, "note_too_long")
            continue
        if db.scalar(select(Report.id).where(Report.report_no == report_no)) is not None:
            summary.duplicate += 1
            continue
        try:
            case, merged = create_case(
                db,
                settings,
                url=row.get("url", ""),
                note=None,
                actor=actor,
                source=CaseSource.REPORT,
                created_by=created_by,
            )
        except UrlPolicyError as exc:
            summary.reject(line, exc.code)
            continue
        db.add(
            Report(
                case_id=case.id,
                report_no=report_no,
                reported_at=reported_at,
                url_reported=row.get("url", "")[:4096],
                note=note,
                batch_id=summary.batch_id,
            )
        )
        try:
            db.commit()
        except IntegrityError:
            # 같은 접수 번호가 동시에 등록된 경우
            db.rollback()
            summary.duplicate += 1
            continue
        if merged:
            summary.merged += 1
        else:
            summary.created += 1

    db.add(
        AuditLog(
            actor=actor,
            action="report.import",
            target_type="report_batch",
            target_id=str(summary.batch_id),
            after={
                "total": summary.total,
                "created": summary.created,
                "merged": summary.merged,
                "duplicate": summary.duplicate,
                "rejected": summary.rejected,
            },
        )
    )
    db.commit()
    logger.info(
        "report import batch=%s total=%d created=%d merged=%d duplicate=%d rejected=%d",
        summary.batch_id,
        summary.total,
        summary.created,
        summary.merged,
        summary.duplicate,
        summary.rejected,
    )
    return summary


def list_reports(db: Session, case_id: uuid.UUID) -> list[Report]:
    return list(db.scalars(select(Report).where(Report.case_id == case_id).order_by(Report.reported_at)).all())
