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
    REPORT = "report"  # 기관 신고 목록(CSV 일괄 등록)


class CaseStatus(enum.StrEnum):
    QUEUED = "queued"
    INVESTIGATING = "investigating"
    JUDGING = "judging"
    REVIEW = "review"
    CONFIRMED = "confirmed"  # 검토자가 의심으로 확정(제보 대기)
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
    VIDEO = "video"  # 조사 과정 녹화(WebM). 담당자는 영상만 보고 의심 페이지를 직접 열지 않는다.


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
    password_hash: Mapped[str] = mapped_column(String(255))  # Argon2id (app.security.passwords)
    role: Mapped[UserRole] = mapped_column(_enum(UserRole, "user_role"))
    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class UserSession(Base):
    """콘솔 로그인 세션. 쿠키에는 임의 토큰만 두고, DB에는 그 SHA-256만 저장한다(DB가 유출돼도 세션 도용 불가)."""

    __tablename__ = "sessions"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)
    token_sha256: Mapped[str] = mapped_column(String(64), unique=True)
    # 세션마다 다른 CSRF 토큰. 상태 변경 요청의 X-CSRF-Token 헤더와 대조한다.
    csrf_token: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    # 절대 만료 시각. 활동이 있어도 이 시각이 지나면 다시 로그인해야 한다.
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    user: Mapped[User] = relationship(lazy="joined")


class LoginAttempt(Base):
    """로그인 시도 기록(시도 제한용). 비밀번호는 어떤 형태로도 남기지 않는다."""

    __tablename__ = "login_attempts"

    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), index=True)
    success: Mapped[bool] = mapped_column()
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


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
    # 실패·보류 사유 코드 (정해진 코드만 저장한다. 외부 오류 메시지 원문은 저장하지 않는다)
    status_reason: Mapped[str | None] = mapped_column(String(64))
    # 멱등 처리: 가장 최근에 발행한 조사 작업 ID. 이 작업만 claim·증거 업로드·완료 보고를 할 수 있다.
    current_job_id: Mapped[uuid.UUID | None] = mapped_column()
    # claim한 작업의 임대 만료 시각. 지나면 스위퍼가 새 작업으로 다시 발행한다.
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # 발행한 조사 작업 수(최초 1). 상한을 넘으면 retry_exhausted로 실패 처리한다.
    attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    # 담당 조사자. 조사자는 자기가 등록했거나 배정받은 사건만 볼 수 있다(IDOR 방지, app.security.rbac).
    assignee_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    evidence: Mapped[list["Evidence"]] = relationship(back_populates="case")
    verdicts: Mapped[list["Verdict"]] = relationship(back_populates="case")
    reports: Mapped[list["Report"]] = relationship(back_populates="case")
    # joined(LEFT OUTER JOIN)로 읽으면 사건 행 잠금(SELECT ... FOR UPDATE)을 PostgreSQL이 거부한다. 별도 쿼리로 읽는다.
    assignee: Mapped[User | None] = relationship(foreign_keys=[assignee_id], lazy="selectin")

    @property
    def assignee_username(self) -> str | None:
        return self.assignee.username if self.assignee is not None else None


class Report(Base):
    """기관 신고 1건. 같은 URL의 신고는 한 사건에 병합되고, 신고 자체(접수 번호·신고 시각·원본 URL)는 모두 남긴다."""

    __tablename__ = "reports"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("cases.id"), index=True)
    # 접수 번호는 기관 안에서 유일하다. 같은 CSV를 다시 올려도 신고가 중복되지 않는다.
    report_no: Mapped[str] = mapped_column(String(64), unique=True)
    reported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    url_reported: Mapped[str] = mapped_column(Text)
    note: Mapped[str | None] = mapped_column(String(500))
    batch_id: Mapped[uuid.UUID] = mapped_column(index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    case: Mapped[Case] = relationship(back_populates="reports")


class Evidence(Base):
    __tablename__ = "evidence"
    __table_args__ = (
        UniqueConstraint("case_id", "kind", "version"),
        # 같은 작업이 같은 종류의 증거를 두 번 올려도 한 건만 남는다(재전달·재시도 대비).
        UniqueConstraint("case_id", "kind", "job_id", name="uq_evidence_case_kind_job"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("cases.id"), index=True)
    kind: Mapped[EvidenceKind] = mapped_column(_enum(EvidenceKind, "evidence_kind"))
    version: Mapped[int] = mapped_column(Integer, default=1)
    job_id: Mapped[uuid.UUID | None] = mapped_column()
    # 저장소 키는 서버가 생성한 UUID 기반 경로만 사용한다(경로 조작 방지).
    storage_key: Mapped[str] = mapped_column(String(200))
    sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(Integer)
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
    reviewer: Mapped[User | None] = relationship(lazy="selectin")

    @property
    def reviewer_username(self) -> str | None:
        return self.reviewer.username if self.reviewer is not None else None


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
