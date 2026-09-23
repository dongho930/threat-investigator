from fastapi import APIRouter, Request, Response, status

from app.api.deps import DbDep, SessionDep, SettingsDep
from app.db.models import User, UserSession
from app.schemas.auth import LoginRequest, MeOut
from app.security.rbac import permissions_of
from app.services import auth

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

# __Host- 접두사: Secure·Path=/·Domain 없음이 강제되어 하위 도메인이 쿠키를 덮어쓸 수 없다.
_COOKIE_FLAGS = {"path": "/", "secure": True, "httponly": True, "samesite": "strict"}


def _me(user: User, session: UserSession) -> MeOut:
    return MeOut(
        id=user.id,
        username=user.username,
        role=user.role,
        permissions=sorted(p.value for p in permissions_of(user)),
        csrf_token=session.csrf_token,
    )


@router.post("/login", response_model=MeOut)
def login(body: LoginRequest, request: Request, response: Response, db: DbDep, settings: SettingsDep) -> MeOut:
    result = auth.login(db, settings, body.username, body.password)
    # 같은 브라우저에 남아 있던 이전 세션은 지운다(로그인할 때마다 새 세션).
    auth.discard_token(db, request.cookies.get(auth.SESSION_COOKIE))
    response.set_cookie(
        auth.SESSION_COOKIE, result.token, max_age=settings.session_absolute_hours * 3600, **_COOKIE_FLAGS
    )
    return _me(result.user, result.session)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(session: SessionDep, db: DbDep) -> Response:
    auth.logout(db, session)
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    response.delete_cookie(auth.SESSION_COOKIE, **_COOKIE_FLAGS)
    return response


@router.get("/me", response_model=MeOut)
def me(session: SessionDep) -> MeOut:
    return _me(session.user, session)
