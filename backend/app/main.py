from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import cases, evidence, health, internal, reports, verdicts
from app.core import http
from app.core.config import get_settings
from app.core.logging import configure_logging


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging()

    # 운영 환경에서는 API 문서를 끈다(내부 구조 노출 방지).
    docs = not settings.is_production
    app = FastAPI(
        title="Threat Investigator API",
        version="0.1.0",
        docs_url="/api/docs" if docs else None,
        redoc_url=None,
        openapi_url="/api/openapi.json" if docs else None,
    )

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST"],
            allow_headers=["Content-Type", "X-CSRF-Token"],
        )

    http.install(app)
    app.include_router(health.router)
    app.include_router(cases.router)
    app.include_router(evidence.router)
    app.include_router(reports.router)
    app.include_router(verdicts.router)
    app.include_router(internal.router)
    return app


app = create_app()
