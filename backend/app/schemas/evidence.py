import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.db.models import CaseStatus, EvidenceKind
from app.services.investigation import FailureReason, Outcome


class EvidenceOut(BaseModel):
    """저장 경로(storage_key)는 응답에 넣지 않는다."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    kind: EvidenceKind
    version: int
    sha256: str
    size_bytes: int
    collector_version: str
    collected_at: datetime


class EvidenceList(BaseModel):
    items: list[EvidenceOut]


class ClaimResult(BaseModel):
    case_id: uuid.UUID
    url: str
    status: CaseStatus


class ClaimRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    job_id: uuid.UUID


class CompleteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    job_id: uuid.UUID
    outcome: Outcome
    reason: FailureReason | None = None


class CompleteResult(BaseModel):
    case_id: uuid.UUID
    status: CaseStatus
    status_reason: str | None = Field(default=None)
