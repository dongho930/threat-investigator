"""공통 보안 헤더, 요청 ID, 예외 처리.

- 오류 응답에는 내부 정보(스택, SQL, 경로)를 넣지 않고 request_id만 준다. 상세는 서버 로그에 남긴다.
- 검증 오류 응답에서 사용자가 보낸 원본 입력값(input)을 되돌려주지 않는다.
"""

import logging
import uuid

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.security.url_policy import UrlPolicyError
from app.services.auth import AuthError
from app.services.cases import CaseError
from app.services.investigation import InvestigationError
from app.services.reports import ReportImportError

logger = logging.getLogger(__name__)

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
    "Cross-Origin-Resource-Policy": "same-origin",
}


# 상태를 바꾸는 요청이 다른 사이트에서 왔으면(브라우저가 붙이는 Sec-Fetch-Site) 세션 확인 전에 거절한다.
# CSRF 토큰·SameSite=Strict 쿠키에 더한 한 겹이며, 로그인 요청(로그인 CSRF)도 막는다.
_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_ALLOWED_FETCH_SITES = frozenset({"same-origin", "none"})


def _request_id(request: Request) -> str:
    return getattr(request.state, "request_id", "-")


def install(app: FastAPI) -> None:
    @app.middleware("http")
    async def security_headers(request: Request, call_next):  # type: ignore[no-untyped-def]
        request.state.request_id = uuid.uuid4().hex
        fetch_site = request.headers.get("sec-fetch-site")
        if (
            request.method in _UNSAFE_METHODS
            and request.url.path.startswith("/api/")
            and fetch_site is not None
            and fetch_site not in _ALLOWED_FETCH_SITES
        ):
            logger.warning("cross-site request blocked path=%s site=%s", request.url.path, fetch_site)
            response = JSONResponse(
                status_code=403,
                content={"code": "cross_site_request", "detail": "다른 사이트에서 온 요청은 받지 않습니다."},
            )
        else:
            response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        response.headers["X-Request-ID"] = request.state.request_id
        return response

    @app.exception_handler(UrlPolicyError)
    async def url_policy_error(request: Request, exc: UrlPolicyError) -> JSONResponse:
        return JSONResponse(status_code=400, content={"code": exc.code, "detail": exc.message})

    @app.exception_handler(InvestigationError)
    async def investigation_error(request: Request, exc: InvestigationError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content={"code": exc.code, "detail": exc.message})

    @app.exception_handler(AuthError)
    async def auth_error(request: Request, exc: AuthError) -> JSONResponse:
        headers = {"WWW-Authenticate": "Session"} if exc.status_code == 401 else None
        return JSONResponse(
            status_code=exc.status_code, content={"code": exc.code, "detail": exc.message}, headers=headers
        )

    @app.exception_handler(CaseError)
    async def case_error(request: Request, exc: CaseError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content={"code": exc.code, "detail": exc.message})

    @app.exception_handler(ReportImportError)
    async def report_import_error(request: Request, exc: ReportImportError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content={"code": exc.code, "detail": exc.message})

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        errors = [{"loc": list(e.get("loc", [])), "type": e.get("type"), "msg": e.get("msg")} for e in exc.errors()]
        return JSONResponse(status_code=422, content={"code": "validation_error", "errors": errors})

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        detail = exc.detail if isinstance(exc.detail, str) else "요청을 처리할 수 없습니다."
        return JSONResponse(status_code=exc.status_code, content={"code": "http_error", "detail": detail})

    @app.exception_handler(Exception)
    async def unhandled_error(request: Request, exc: Exception) -> JSONResponse:
        rid = _request_id(request)
        logger.exception("unhandled error request_id=%s", rid)
        return JSONResponse(
            status_code=500,
            content={"code": "internal_error", "detail": "내부 오류가 발생했습니다.", "request_id": rid},
        )
