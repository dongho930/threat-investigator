import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.db.models import DecidedBy, VerdictStatus


class VerdictOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    version: int
    status: VerdictStatus
    suspected_types: list[str]
    rule_result: dict[str, Any]
    # AI 판정 기록: 모델·리비전·선택지·신호 코드·자체 확신도(보정 전)·오류 코드·인젝션 탐지 코드. 모델이 쓴 문장은 없다.
    model_result: dict[str, Any] | None = None
    policy_reason: str | None
    decided_by: DecidedBy
    reviewer: str | None = Field(default=None, validation_alias="reviewer_username")
    created_at: datetime


class ReviewDraftOut(BaseModel):
    """AI 검토 보조 초안(참고용). 판정이 아니다."""

    model_config = ConfigDict(from_attributes=True)

    model: str
    suggestion: dict[str, Any] | None
    error: str | None
    created_at: datetime


class VerdictList(BaseModel):
    items: list[VerdictOut]
