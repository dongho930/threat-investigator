import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.db.models import CaseSource, CaseStatus, SuspectedType


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
    assignee: str | None = Field(default=None, validation_alias="assignee_username")
    # 등록한 사용자. 피드·시스템 등록은 null. agent-로 시작하면 자동화 계정(가상 조사자)이다.
    creator: str | None = Field(default=None, validation_alias="creator_username")
    created_at: datetime


class CaseCreateResult(BaseModel):
    # 이미 등록된 URL인데 요청자가 볼 수 없는 사건이면 case는 비워 둔다(다른 담당자의 메모·신고 노출 방지).
    case: CaseOut | None
    duplicate: bool


class CaseList(BaseModel):
    items: list[CaseOut]
    total: int


class AssignRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assignee_id: uuid.UUID


class ReviewRequest(BaseModel):
    """검토자의 판정 확정. SUSPICIOUS는 의심 유형이 1개 이상 필요하고, 나머지는 유형을 받지 않는다."""

    model_config = ConfigDict(extra="forbid")

    decision: Literal["SUSPICIOUS", "BENIGN", "UNKNOWN"]
    suspected_types: list[SuspectedType] = Field(default_factory=list, max_length=len(SuspectedType))
    reason: str = Field(min_length=1, max_length=500)

    @model_validator(mode="after")
    def _types_match_decision(self) -> "ReviewRequest":
        if len(set(self.suspected_types)) != len(self.suspected_types):
            raise ValueError("의심 유형이 중복되었습니다.")
        if self.decision == "SUSPICIOUS" and not self.suspected_types:
            raise ValueError("의심으로 확정하려면 의심 유형을 하나 이상 골라야 합니다.")
        if self.decision != "SUSPICIOUS" and self.suspected_types:
            raise ValueError("의심 유형은 SUSPICIOUS 확정에만 씁니다.")
        if not self.reason.strip():
            raise ValueError("판정 사유를 적어야 합니다.")
        return self
