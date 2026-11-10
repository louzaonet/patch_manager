"""
Patch Manager AI: FastAPI entry point (web dashboard, API, webhooks).
"""

from __future__ import annotations

import logging
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import structlog
import uvicorn
from fastapi import Depends, FastAPI, Request
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.api.routes import router
from app.config import get_settings
from app.security import Principal, require_user
from app.tools.llm_router import get_active_models

VERSION = "1.0.1"


def _configure_logging(level_name: str) -> None:
    level = logging.getLevelName(level_name.upper())
    if not isinstance(level, int):
        level = logging.INFO
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(level),
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.format_exc_info,
            structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty()),
        ],
    )


settings = get_settings()
_configure_logging(settings.log_level)
logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    problems = get_settings().startup_problems()
    if problems:
        for problem in problems:
            logger.error("config_error", problem=problem)
        raise RuntimeError("Invalid configuration: " + " | ".join(problems))
    s = get_settings()
    if s.app_auth_disabled:
        logger.warning("auth_disabled", hint="APP_AUTH_DISABLED=true is for local development only")
    logger.info("starting", version=VERSION, llm=get_active_models(),
                slack=s.slack_enabled, teams=s.teams_enabled)
    yield
    logger.info("shutting_down")


app = FastAPI(
    title="Patch Manager AI",
    description="AI orchestration layer for multi-platform patch management",
    version=VERSION,
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

base_dir = Path(__file__).parent
app.mount("/static", StaticFiles(directory=base_dir / "static"), name="static")
templates = Jinja2Templates(directory=base_dir / "templates")
app.include_router(router)

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    if response.headers.get("content-type", "").startswith("text/html") and request.url.path != "/docs":
        response.headers.setdefault("Content-Security-Policy", CSP)
        response.headers.setdefault("X-Frame-Options", "DENY")
    if request.url.path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.get("/", include_in_schema=False)
async def index(request: Request, user: Principal = Depends(require_user)):
    return templates.TemplateResponse(request, "index.html", {"version": VERSION, "user": user.name})


if settings.app_enable_docs:
    # Authenticated docs. Swagger UI assets load from a CDN, so no CSP here.
    @app.get("/openapi.json", include_in_schema=False)
    async def openapi_json(user: Principal = Depends(require_user)):
        return app.openapi()

    @app.get("/docs", include_in_schema=False)
    async def docs(user: Principal = Depends(require_user)):
        # Relative URL so it also works behind a path prefix such as /ai/.
        return get_swagger_ui_html(openapi_url="openapi.json", title="Patch Manager AI API")


if __name__ == "__main__":
    uvicorn.run("app.main:app", host=settings.app_host, port=settings.app_port)
