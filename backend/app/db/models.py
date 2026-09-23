"""사건·증거·판정·제출·감사 로그 스키마.

- 상태의 원본은 PostgreSQL이다. 작업 메시지는 outbox_events를 거쳐 Redis Streams로 발행한다.
- Enum은 native_enum=False(문자열 + CHECK 제약)로 두어 DB 간 이식성과 마이그레이션 편의를 챙긴다.
"""

import enum
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, BigInteger, DateTime, Enum, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    type_annotation_map = {dict[str, Any]: JSON, list[str]: JSON}


def _enum(cls: type[enum.Enum], name: str) -> Enum:
    return Enum(
        cls,
        name=name,
        native_enum=False,
        create_constraint=True,
        length=32,
        values_callable=lambda e: [m.value for m in e],
    )


class CaseSource(enum.StrEnum):
    MANUAL = "manual"
    FEED = "feed"


class CaseStatus(enum.StrEnum):
    QUEUED = "queued"
    INVESTIGATING = "investigating"
    JUDGING = "judging"
    REVIEW = "review"
    REPORTED = "reported"
    HELD = "held"
    REJECTED = "rejected"
    FAILED = "failed"


class SuspectedType(enum.StrEnum):
    PHISHING = "PHISHING"
    SCAM = "SCAM"
    ILLEGAL_GAMBLING_SUSPECTED = "ILLEGAL_GAMBLING_SUSPECTED"
    MALWARE = "MALWARE"
    OTHER = "OTHER"


class VerdictStatus(enum.StrEnum):
    SUSPICIOUS = "SUSPICIOUS"
    BENIGN = "BENIGN"
    UNKNOWN = "UNKNOWN"


class EvidenceKind(enum.StrEnum):
    SCREENSHOT = "screenshot"
    DOM_SUMMARY = "dom_summary"
    REDIRECT_CHAIN = "redirect_chain"
    NETWORK_SUMMARY = "network_summary"


class DecidedBy(enum.StrEnum):
    SYSTEM = "system"
    HUMAN = "human"


class SubmissionKind(enum.StrEnum):
    LOOKUP = "lookup"
    ANALYSIS_SUBMIT = "analysis_submit"
    REPORT = "report"


class SubmissionState(enum.StrEnum):
    DRAFT = "draft"
    ATTEMPTED = "attempted"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    FAILED = "failed"
    CORRECTED = "corrected"


class UserRole(enum.StrEnum):
    INVESTIGATOR = "investigator"
    REVIEWER = "reviewer"
    ADMIN = "admin"


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))  # Argon2id (4주차)
    role: Mapped[UserRole] = mapped_column(_enum(UserRole, "user_role"))
    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Case(Base):
    __tablename__ = "cases"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    url_original: Mapped[str] = mapped_column(Text)
    url_normalized: Mapped[str] = mapped_column(Text)
    url_sha256: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    host: Mapped[str] = mapped_column(String(255), index=True)
    source: Mapped[CaseSource] = mapped_column(_enum(CaseSource, "case_source"))
    source_ref: Mapped[str | None] = mapped_column(String(200))
    note: Mapped[str | None] = mapped_column(String(500))
    status: Mapped[CaseStatus] = mapped_column(_enum(CaseStatus, "case_status"), default=CaseStatus.QUEUED)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    evidence: Mapped[list["Evidence"]] = relationship(back_populates="case")
    verdicts: Mapped[list["Verdict"]] = relationship(back_populates="case")


class Evidence(Base):
    __tablename__ = "evidence"
    __table_args__ = (UniqueConstraint("case_id", "kind", "version"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("cases.id"), index=True)
    kind: Mapped[EvidenceKind] = mapped_column(_enum(EvidenceKind, "evidence_kind"))
    version: Mapped[int] = mapped_column(Integer, default=1)
    # 저장소 키는 서버가 생성한 UUID 기반 경로만 사용한다(경로 조작 방지).
    storage_key: Mapped[str] = mapped_column(String(200))
    sha256: Mapped[str] = mapped_column(String(64))
    collector_version: Mapped[str] = mapped_column(String(50))
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    retention_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    case: Mapped[Case] = relationship(back_populates="evidence")


class Verdict(Base):
    __tablename__ = "verdicts"
    __table_args__ = (UniqueConstraint("case_id", "version"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("cases.id"), index=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    suspected_types: Mapped[list[str]] = mapped_column(default=list)
    status: Mapped[VerdictStatus] = mapped_column(_enum(VerdictStatus, "verdict_status"))
    rule_result: Mapped[dict[str, Any]] = mapped_column(default=dict)
    model_result: Mapped[dict[str, Any] | None] = mapped_column()
    policy_reason: Mapped[str | None] = mapped_column(Text)
    decided_by: Mapped[DecidedBy] = mapped_column(_enum(DecidedBy, "decided_by"))
    reviewer_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    case: Mapped[Case] = relationship(back_populates="verdicts")


class Submission(Base):
    __tablename__ = "submissions"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("cases.id"), index=True)
    channel: Mapped[str] = mapped_column(String(64))
    kind: Mapped[SubmissionKind] = mapped_column(_enum(SubmissionKind, "submission_kind"))
    state: Mapped[SubmissionState] = mapped_column(_enum(SubmissionState, "submission_state"))
    # 중복 제출 방지 키 (사건·채널·종류 단위)
    idempotency_key: Mapped[str] = mapped_column(String(128), unique=True)
    external_ref: Mapped[str | None] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class AuditLog(Base):
    """추가 전용 감사 로그. 운영 DB에서는 앱 계정에 UPDATE/DELETE 권한을 주지 않는다."""

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    actor: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64))
    target_type: Mapped[str] = mapped_column(String(32))
    target_id: Mapped[str] = mapped_column(String(64))
    before: Mapped[dict[str, Any] | None] = mapped_column()
    after: Mapped[dict[str, Any] | None] = mapped_column()
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class OutboxEvent(Base):
    """DB 트랜잭션과 함께 기록하고, 별도 relay가 Redis Streams로 발행한다."""

    __tablename__ = "outbox_events"

    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    topic: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict[str, Any]] = mapped_column()
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
