import hmac
import logging
from functools import lru_cache
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.db.session import get_db
from app.services.evidence_store import LocalEvidenceStore

logger = logging.getLogger(__name__)

DbDep = Annotated[Session, Depends(get_db)]
SettingsDep = Annotated[Settings, Depends(get_settings)]


@lru_cache
def _store_for(root: str) -> LocalEvidenceStore:
    return LocalEvidenceStore(root)


def get_evidence_store(settings: SettingsDep) -> LocalEvidenceStore:
    return _store_for(settings.evidence_dir)


StoreDep = Annotated[LocalEvidenceStore, Depends(get_evidence_store)]


def require_worker(settings: SettingsDep, authorization: Annotated[str | None, Header()] = None) -> None:
    """Worker 서비스 토큰 확인. 토큰이 설정되지 않았으면 내부 API를 모두 거부한다."""
    expected = settings.worker_api_token
    scheme, _, supplied = (authorization or "").partition(" ")
    if (
        expected is None
        or scheme.lower() != "bearer"
        or not hmac.compare_digest(supplied.encode(), expected.get_secret_value().encode())
    ):
        logger.warning("internal api auth failed")
        raise HTTPException(status_code=401, detail="인증이 필요합니다.", headers={"WWW-Authenticate": "Bearer"})


async def _read_body(request: Request, limit: int) -> bytes:
    """본문을 크기 제한을 두고 읽는다. Content-Length를 속여도 읽는 도중 끊는다."""
    declared = request.headers.get("content-length")
    if declared is not None and (not declared.isdigit() or int(declared) > limit):
        raise HTTPException(status_code=413, detail="요청 본문이 너무 큽니다.")
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise HTTPException(status_code=413, detail="요청 본문이 너무 큽니다.")
        chunks.append(chunk)
    return b"".join(chunks)


async def read_limited_body(request: Request, settings: SettingsDep) -> bytes:
    return await _read_body(request, max(settings.evidence_max_screenshot_bytes, settings.evidence_max_json_bytes))


async def read_csv_body(request: Request, settings: SettingsDep) -> bytes:
    return await _read_body(request, settings.report_import_max_bytes)
