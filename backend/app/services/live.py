"""실시간 조사 화면(라이브 뷰).

- Worker가 조사 중인 브라우저 화면을 JPEG로 보내면, 사건마다 **최신 한 장만** Redis에 짧게(기본 20초) 둔다.
  증거가 아니므로 디스크·DB에 저장하지 않는다. 증거로 남는 것은 조사가 끝난 뒤의 녹화(video)와 스크린샷이다.
- 받는 조건: 사건의 현재 작업(job_id)이고 조사 중(investigating)일 것, JPEG 형식, 크기 제한.
- 콘솔은 사건 단위 접근 확인을 거쳐 이미지로만 받는다. 담당자 브라우저는 의심 페이지를 직접 열지 않는다.
"""

import uuid
from functools import lru_cache
from typing import Protocol

from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.db.models import Case, CaseStatus
from app.services.investigation import InvestigationError

JPEG_SIGNATURE = b"\xff\xd8\xff"


class FrameStore(Protocol):
    def set(self, name: str, value: bytes, ex: int | None = None) -> object: ...

    def get(self, name: str) -> bytes | None: ...


def _key(case_id: uuid.UUID) -> str:
    return f"live:{case_id}"


@lru_cache
def _redis(url: str) -> FrameStore:
    import redis

    return redis.Redis.from_url(url, socket_timeout=2)


def get_frame_store() -> FrameStore:
    return _redis(get_settings().redis_url)


def put_frame(
    db: Session,
    store: FrameStore,
    settings: Settings,
    *,
    case_id: uuid.UUID,
    job_id: uuid.UUID,
    data: bytes,
    content_type: str,
) -> None:
    if content_type.split(";", 1)[0].strip().lower() != "image/jpeg":
        raise InvestigationError("unsupported_media_type", "JPEG만 받습니다.", 415)
    if len(data) > settings.live_frame_max_bytes:
        raise InvestigationError("too_large", "화면 이미지가 너무 큽니다.", 413)
    if not data.startswith(JPEG_SIGNATURE):
        raise InvestigationError("invalid_content", "JPEG 형식이 아닙니다.", 422)
    case = db.get(Case, case_id)
    if case is None:
        raise InvestigationError("not_found", "사건을 찾을 수 없습니다.", 404)
    if case.current_job_id != job_id:
        raise InvestigationError("stale_job", "현재 작업이 아닙니다.", 409)
    if case.status is not CaseStatus.INVESTIGATING:
        raise InvestigationError("not_investigating", "조사 중인 사건이 아닙니다.", 409)
    store.set(_key(case_id), data, ex=settings.live_frame_ttl_seconds)


def get_frame(store: FrameStore, case_id: uuid.UUID) -> bytes | None:
    data = store.get(_key(case_id))
    return data if isinstance(data, bytes) and data.startswith(JPEG_SIGNATURE) else None
