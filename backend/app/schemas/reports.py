import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ImportError_(BaseModel):
    row: int
    code: str


class ImportResult(BaseModel):
    batch_id: uuid.UUID
    total: int
    created: int
    merged: int
    duplicate: int
    rejected: int
    errors: list[ImportError_]


class ReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    report_no: str
    reported_at: datetime
    url_reported: str
    note: str | None
    batch_id: uuid.UUID
    created_at: datetime


class ReportList(BaseModel):
    items: list[ReportOut]
