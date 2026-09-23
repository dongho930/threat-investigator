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
    policy_reason: str | None
    decided_by: DecidedBy
    reviewer: str | None = Field(default=None, validation_alias="reviewer_username")
    created_at: datetime


class VerdictList(BaseModel):
    items: list[VerdictOut]
