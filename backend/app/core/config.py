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
    evidence_retention_days: int = 90

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
