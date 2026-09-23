import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.db.models import CaseSource, CaseStatus


class CaseCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(min_length=1, max_length=4096)
    note: str | None = Field(default=None, max_length=500)


class CaseOut(BaseModel):
    """응답 전용 모델. 내부 필드(created_by 등)는 노출하지 않는다."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    url: str = Field(validation_alias="url_normalized")
    host: str
    source: CaseSource
    status: CaseStatus
    status_reason: str | None = None
    note: str | None
    created_at: datetime


class CaseCreateResult(BaseModel):
    case: CaseOut
    duplicate: bool


class CaseList(BaseModel):
    items: list[CaseOut]
    total: int
