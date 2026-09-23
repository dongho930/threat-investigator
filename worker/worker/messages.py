"""작업 메시지 스키마. 큐 메시지도 신뢰하지 않고 JSON + 스키마 검증만 허용한다(pickle 금지)."""

import json
import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError


class JobMessage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    job_id: uuid.UUID
    case_id: uuid.UUID
    stage: Literal["investigate"]
    attempt: int = Field(ge=1, le=10)


class InvalidMessage(ValueError):
    pass


def parse_job(fields: dict[str, str]) -> JobMessage:
    raw = fields.get("payload")
    if raw is None or len(raw) > 4096:
        raise InvalidMessage("payload missing or too large")
    try:
        return JobMessage.model_validate(json.loads(raw))
    except (json.JSONDecodeError, ValidationError) as exc:
        raise InvalidMessage("payload failed schema validation") from exc
