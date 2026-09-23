"""콘솔 로그인·세션.

- 세션 토큰은 32바이트 난수. 쿠키에만 원문이 있고 DB에는 SHA-256만 저장한다.
- 로그인할 때마다 새 세션을 만든다(세션 고정 방지). 유휴 만료·절대 만료를 모두 적용한다.
- 로그인 실패는 계정 이름 단위로 센다. 마지막 성공 이후 제한 시간 안에 실패가 상한에 닿으면 비밀번호를
  확인하지 않고 거부한다. IP 단위 제한은 앞단 nginx(limit_req)가 맡는다.
- 없는 계정·틀린 비밀번호·비활성 계정은 모두 같은 응답을 준다(계정 존재 여부 노출 방지).
"""

import hashlib
import hmac
import logging
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.db.models import AuditLog, LoginAttempt, User, UserSession, utcnow
from app.security import passwords
from app.services.investigation import aware

logger = logging.getLogger(__name__)

SESSION_COOKIE = "__Host-ti_session"
# 마지막 활동 시각은 1분에 한 번만 갱신한다(요청마다 DB 쓰기 방지).
_TOUCH_INTERVAL = timedelta(minutes=1)


class AuthError(Exception):
    def __init__(self, code: str, message: str, status_code: int) -> None:
        super().__init__(code)
        self.code = code
        self.message = message
        self.status_code = status_code


def unauthenticated() -> AuthError:
    return AuthError("unauthenticated", "로그인이 필요합니다.", 401)


def forbidden() -> AuthError:
    return AuthError("forbidden", "이 작업을 할 권한이 없습니다.", 403)


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def normalize_username(username: str) -> str:
    return username.strip().lower()


@dataclass
class LoginResult:
    user: User
    token: str
    session: UserSession


def _recent_failures(db: Session, username: str, now: datetime, settings: Settings) -> int:
    window_start = now - timedelta(minutes=settings.login_lockout_minutes)
    last_success = aware(
        db.scalar(
            select(func.max(LoginAttempt.created_at)).where(
                LoginAttempt.username == username, LoginAttempt.success.is_(True)
            )
        )
    )
    since = max(window_start, last_success) if last_success is not None else window_start
    return (
        db.scalar(
            select(func.count())
            .select_from(LoginAttempt)
            .where(
                LoginAttempt.username == username,
                LoginAttempt.success.is_(False),
                LoginAttempt.created_at > since,
            )
        )
        or 0
    )


def login(db: Session, settings: Settings, username: str, password: str) -> LoginResult:
    name = normalize_username(username)
    now = utcnow()
    if _recent_failures(db, name, now, settings) >= settings.login_max_failures:
        db.add(AuditLog(actor="anonymous", action="auth.login_locked", target_type="user", target_id=name))
        db.commit()
        logger.warning("login locked username=%s", name)
        raise AuthError("login_locked", "로그인 시도가 너무 많습니다. 잠시 후 다시 시도하세요.", 429)

    user = db.scalar(select(User).where(User.username == name))
    ok = passwords.verify_password(user.password_hash if user is not None else None, password)
    if user is None or not ok or not user.is_active:
        db.add(LoginAttempt(username=name, success=False, created_at=now))
        db.add(AuditLog(actor="anonymous", action="auth.login_failed", target_type="user", target_id=name))
        db.commit()
        logger.info("login failed username=%s", name)
        raise AuthError("invalid_credentials", "아이디 또는 비밀번호가 올바르지 않습니다.", 401)

    if passwords.needs_rehash(user.password_hash):
        user.password_hash = passwords.hash_password(password)

    token = secrets.token_urlsafe(32)
    session = UserSession(
        id=uuid.uuid4(),
        user_id=user.id,
        token_sha256=_token_hash(token),
        csrf_token=secrets.token_urlsafe(32),
        created_at=now,
        last_seen_at=now,
        expires_at=now + timedelta(hours=settings.session_absolute_hours),
    )
    db.add(session)
    db.add(LoginAttempt(username=name, success=True, created_at=now))
    db.add(AuditLog(actor=user.username, action="auth.login", target_type="user", target_id=str(user.id)))
    db.commit()
    logger.info("login ok user=%s role=%s", user.username, user.role.value)
    return LoginResult(user=user, token=token, session=session)


def resolve_session(db: Session, settings: Settings, token: str | None) -> UserSession:
    """쿠키의 토큰으로 유효한 세션을 찾는다. 만료·비활성 계정이면 세션을 지우고 401."""
    if not token or len(token) > 128:
        raise unauthenticated()
    session = db.scalar(select(UserSession).where(UserSession.token_sha256 == _token_hash(token)))
    if session is None:
        raise unauthenticated()
    now = utcnow()
    idle_limit = aware(session.last_seen_at) + timedelta(minutes=settings.session_idle_minutes)
    if now >= aware(session.expires_at) or now >= idle_limit or not session.user.is_active:
        db.delete(session)
        db.commit()
        raise unauthenticated()
    if now - aware(session.last_seen_at) >= _TOUCH_INTERVAL:
        session.last_seen_at = now
        db.commit()
    return session


def check_csrf(session: UserSession, supplied: str | None) -> None:
    if not supplied or not hmac.compare_digest(supplied.encode(), session.csrf_token.encode()):
        logger.warning("csrf check failed user=%s", session.user.username)
        raise AuthError("csrf_failed", "요청 검증에 실패했습니다. 페이지를 새로 고친 뒤 다시 시도하세요.", 403)


def logout(db: Session, session: UserSession) -> None:
    db.add(
        AuditLog(actor=session.user.username, action="auth.logout", target_type="user", target_id=str(session.user_id))
    )
    db.delete(session)
    db.commit()


def discard_token(db: Session, token: str | None) -> None:
    if token and len(token) <= 128:
        db.execute(delete(UserSession).where(UserSession.token_sha256 == _token_hash(token)))
        db.commit()


def revoke_user_sessions(db: Session, user_id: uuid.UUID) -> None:
    db.execute(delete(UserSession).where(UserSession.user_id == user_id))
