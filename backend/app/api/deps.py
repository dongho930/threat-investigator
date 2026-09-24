import hmac
import logging
import uuid
from collections.abc import Callable
from functools import lru_cache
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.db.models import Case, User, UserSession
from app.db.session import get_db
from app.security import rbac
from app.security.rbac import Permission
from app.services import auth
from app.services.evidence_store import LocalEvidenceStore
from app.services.live import FrameStore, get_frame_store

logger = logging.getLogger(__name__)

DbDep = Annotated[Session, Depends(get_db)]
SettingsDep = Annotated[Settings, Depends(get_settings)]


@lru_cache
def _store_for(root: str) -> LocalEvidenceStore:
    return LocalEvidenceStore(root)


def get_evidence_store(settings: SettingsDep) -> LocalEvidenceStore:
    return _store_for(settings.evidence_dir)


StoreDep = Annotated[LocalEvidenceStore, Depends(get_evidence_store)]
FrameStoreDep = Annotated[FrameStore, Depends(get_frame_store)]


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


SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def get_current_session(
    request: Request,
    db: DbDep,
    settings: SettingsDep,
    x_csrf_token: Annotated[str | None, Header()] = None,
) -> UserSession:
    """세션 쿠키로 로그인 사용자를 확인한다. 상태를 바꾸는 요청은 CSRF 토큰도 대조한다."""
    session = auth.resolve_session(db, settings, request.cookies.get(auth.SESSION_COOKIE))
    if request.method not in SAFE_METHODS:
        auth.check_csrf(session, x_csrf_token)
    return session


SessionDep = Annotated[UserSession, Depends(get_current_session)]


def get_current_user(session: SessionDep) -> User:
    return session.user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require(permission: Permission) -> Callable[[User], User]:
    """역할에 해당 권한이 없으면 403. 모든 콘솔 API는 이 의존성을 거친다."""

    def dependency(user: CurrentUser) -> User:
        if not rbac.has_permission(user, permission):
            logger.warning("permission denied user=%s role=%s need=%s", user.username, user.role.value, permission)
            raise auth.forbidden()
        return user

    return dependency


def get_accessible_case(case_id: uuid.UUID, db: DbDep, user: CurrentUser) -> Case:
    """사건 단위 접근 확인. 볼 수 없는 사건은 없는 사건과 똑같이 404로 답한다(존재 여부 노출 방지)."""
    case = db.get(Case, case_id)
    if case is None or not rbac.can_access_case(user, case):
        if case is not None:
            logger.warning("case access denied user=%s case=%s", user.username, case_id)
        raise HTTPException(status_code=404, detail="사건을 찾을 수 없습니다.")
    return case


AccessibleCase = Annotated[Case, Depends(get_accessible_case)]


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
    limit = max(
        settings.evidence_max_screenshot_bytes, settings.evidence_max_json_bytes, settings.evidence_max_video_bytes
    )
    return await _read_body(request, limit)


async def read_live_frame(request: Request, settings: SettingsDep) -> bytes:
    return await _read_body(request, settings.live_frame_max_bytes)


async def read_csv_body(request: Request, settings: SettingsDep) -> bytes:
    return await _read_body(request, settings.report_import_max_bytes)
