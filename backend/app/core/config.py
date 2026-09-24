from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """환경변수로만 설정한다. 비밀정보는 코드·저장소에 두지 않는다."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    env: Literal["development", "test", "production"] = "development"
    database_url: str = "postgresql+psycopg://app:app@localhost:5432/investigator"
    redis_url: str = "redis://localhost:6379/0"
    job_stream: str = "jobs:investigate"
    # 피드로 자동 탐색한 사건은 우선순위가 낮은 별도 스트림으로 보낸다(신고·수동 건 먼저 처리).
    feed_job_stream: str = "jobs:investigate:feed"

    cors_origins: list[str] = Field(default_factory=list)

    url_max_length: int = 2048
    url_allowed_ports: list[int] = Field(default_factory=lambda: [80, 443, 8080, 8443])
    # 개발용 시험 페이지(testsites 컨테이너) 등 내부 호스트를 예외로 허용할 때만 사용한다.
    url_host_allowlist: list[str] = Field(default_factory=list)

    # Worker 전용 내부 API 인증 토큰. 비어 있으면 내부 API를 쓸 수 없다.
    worker_api_token: SecretStr | None = None

    # 증거 파일 저장 위치와 크기 제한
    evidence_dir: str = "/data/evidence"
    evidence_max_screenshot_bytes: int = 8 * 1024 * 1024
    evidence_max_json_bytes: int = 1024 * 1024
    evidence_max_video_bytes: int = 16 * 1024 * 1024
    # 실시간 조사 화면: Worker가 보낸 최신 JPEG 한 장만 Redis에 짧게 둔다(증거가 아님, 저장하지 않음).
    live_frame_max_bytes: int = 256 * 1024
    live_frame_ttl_seconds: int = 20
    evidence_retention_days: int = 90

    # 신고 CSV 일괄 등록 제한
    report_import_max_bytes: int = 1024 * 1024
    report_import_max_rows: int = 1000

    # 위협정보 피드 자동 수집: 하루에 새로 만드는 사건 수 상한, 한 번에 받는 URL 수 상한
    feed_max_new_cases_per_day: int = 100
    feed_batch_max_items: int = 500

    # 콘솔 로그인 세션: 유휴 만료·절대 만료, 로그인 시도 제한(계정별)
    session_idle_minutes: int = Field(default=30, ge=1, le=24 * 60)
    session_absolute_hours: int = Field(default=8, ge=1, le=24 * 7)
    login_max_failures: int = Field(default=5, ge=1, le=100)
    login_lockout_minutes: int = Field(default=15, ge=1, le=24 * 60)

    # AI 판정(ai-judge). none이면 규칙 판정만 한다(기준선). 모델 서버는 인터넷이 없는 ai 네트워크에만 있다.
    ai_model: Literal["none", "laya", "qwen"] = "none"
    laya_url: str = "http://laya:8000"
    llm_url: str = "http://llm:8080"
    llm_revision: str = "Qwen/Qwen3-1.7B-GGUF@90862c4"
    ai_timeout_seconds: float = Field(default=120, gt=0, le=600)
    # 모델 자체 확신도가 이보다 낮으면 기권으로 본다(보정 전 값이라 결과보고서에서 다시 정한다).
    ai_min_confidence: float = Field(default=0.6, ge=0, le=1)
    # ai-judge가 멈춰 judging에 이만큼 머문 사건은 스위퍼가 보류(model_unavailable)로 넘긴다.
    ai_judge_stale_seconds: int = 600
    ai_poll_seconds: float = 2.0

    # 조사 작업 임대·재발행(스위퍼)
    investigation_lease_seconds: int = 600
    queued_stale_seconds: int = 600
    max_investigation_attempts: int = 3
    sweep_interval_seconds: int = 30

    @model_validator(mode="after")
    def _worker_token_strength(self) -> "Settings":
        if self.worker_api_token is not None and len(self.worker_api_token.get_secret_value()) < 32:
            raise ValueError("WORKER_API_TOKEN은 32자 이상이어야 합니다.")
        return self

    @model_validator(mode="after")
    def _no_allowlist_in_production(self) -> "Settings":
        if self.env == "production" and self.url_host_allowlist:
            raise ValueError("운영 환경에서는 URL_HOST_ALLOWLIST를 사용할 수 없습니다.")
        return self

    @property
    def is_production(self) -> bool:
        return self.env == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()
