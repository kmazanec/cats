"""FastAPI app factory. Mounts route modules, static assets, and SSE.
Bootstraps the admin user from env on startup so a fresh deploy has a
valid login on first hit."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from cats.api.auth import Principal, current_principal
from cats.api.context import build_overview_context
from cats.api.routes import (
    audit,
    auth_routes,
    bus,
    campaigns,
    findings,
    health,
    projects,
    sse,
    traces,
    user_admin,
    webhooks,
)
from cats.api.templating import templates
from cats.config import settings
from cats.db.engine import session_scope
from cats.db.repositories.user_repo import ensure_admin_seeded
from cats.health.checks import HealthCheckResult, run_all_checks
from cats.health.workers import check_workers, workers_all_healthy
from cats.logging import configure_logging, get_logger
from cats.security.csrf import attach_cookie_if_new, ensure_token

STATIC_DIR = Path(__file__).parent / "static"


class CsrfMiddleware(BaseHTTPMiddleware):
    """Ensures every request has a CSRF token on `request.state`, and sets
    the cookie on the response if a fresh token was minted.

    This is the only place the cookie touches the wire — every template
    just reads `request.state.csrf_token`.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Any) -> Any:
        ensure_token(request)
        response = await call_next(request)
        attach_cookie_if_new(request, response)
        return response


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    log = get_logger(__name__)
    if settings.admin_email and settings.admin_password:
        try:
            async with session_scope() as session:
                created = await ensure_admin_seeded(
                    session,
                    email=settings.admin_email,
                    password=settings.admin_password,
                )
            if created:
                log.info("auth.admin_seeded", email=settings.admin_email)
        except Exception as exc:
            log.warning("auth.admin_seed_failed", error=repr(exc))
    else:
        log.warning(
            "auth.admin_not_configured",
            hint="Set CATS_ADMIN_EMAIL and CATS_ADMIN_PASSWORD to bootstrap the first user.",
        )
    yield


def create_app() -> FastAPI:
    configure_logging()
    app = FastAPI(title="CATS", version="0.1.0", lifespan=_lifespan)

    app.add_middleware(CsrfMiddleware)

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        """Liveness + per-dependency + per-worker health.

        HTTP status stays 200 even when individual deps or workers are
        unhealthy — orchestration layers care about reachability, not
        readiness. Read the body's ``ok`` field for the aggregate.
        """

        def _check_dict(r: HealthCheckResult) -> dict[str, Any]:
            # `not_configured` is neutral — treat as ok for the per-dep flag,
            # mirroring HealthReport.overall_ok semantics in checks.py.
            return {"ok": not r.is_blocking, "status": r.status, "detail": r.detail}

        try:
            report = await run_all_checks()
        except Exception as exc:  # pragma: no cover - defensive
            return {
                "ok": False,
                "error": f"{type(exc).__name__}: {exc}",
            }

        by_name = {c.name: c for c in report.checks}
        workers_block: dict[str, Any]
        try:
            workers = await check_workers()
            workers_block = {name: w.as_dict() for name, w in workers.items()}
            workers_ok = workers_all_healthy(workers)
        except Exception as exc:
            workers_block = {"error": f"{type(exc).__name__}: {exc}"}
            workers_ok = False

        payload: dict[str, Any] = {
            "ok": report.overall_ok and workers_ok,
            "postgres": _check_dict(by_name["postgres"]),
            "redis": _check_dict(by_name["redis"]),
            "openrouter": _check_dict(by_name["openrouter"]),
            "langsmith": _check_dict(by_name["langsmith"]),
            "workers": workers_block,
        }
        return payload

    @app.get("/")
    async def index(
        request: Request,
        principal: Principal | None = Depends(current_principal),
    ) -> Any:
        if principal is None:
            return RedirectResponse(url="/login", status_code=302)
        async with session_scope() as session:
            ctx = await build_overview_context(session)
        ctx["principal"] = principal
        return templates.TemplateResponse(request, "index.html", ctx)

    @app.exception_handler(StarletteHTTPException)
    async def _http_exception_handler(request: Request, exc: StarletteHTTPException) -> Any:
        accept = request.headers.get("accept", "").lower()
        wants_html = "text/html" in accept
        if exc.status_code == 401 and wants_html:
            return RedirectResponse(url="/login", status_code=302)
        if exc.status_code == 403 and wants_html:
            return templates.TemplateResponse(
                request,
                "forbidden.html",
                {
                    "active": "",
                    "principal": getattr(request.state, "principal", None),
                    "env_tag": settings.default_target_env,
                    "build_tag": settings.build_sha,
                    "now_utc": "",
                    "db_status": "—",
                    "redis_status": "—",
                    "openrouter_status": "—",
                    "detail": exc.detail,
                },
                status_code=403,
            )
        from starlette.responses import JSONResponse

        return JSONResponse(
            {"detail": exc.detail}, status_code=exc.status_code, headers=exc.headers
        )

    app.include_router(auth_routes.router, tags=["auth"])
    app.include_router(projects.router, prefix="/projects", tags=["projects"])
    app.include_router(user_admin.router, prefix="/users", tags=["users"])
    app.include_router(audit.router, prefix="/audit", tags=["audit"])
    app.include_router(health.router, prefix="/health", tags=["health"])
    app.include_router(campaigns.router, prefix="/campaigns", tags=["campaigns"])
    app.include_router(findings.router, prefix="/findings", tags=["findings"])
    app.include_router(webhooks.router, prefix="/webhooks", tags=["webhooks"])
    app.include_router(sse.router, prefix="/events", tags=["events"])
    app.include_router(traces.router, prefix="/traces", tags=["traces"])
    app.include_router(bus.router, prefix="/bus", tags=["bus"])
    return app


app = create_app()
