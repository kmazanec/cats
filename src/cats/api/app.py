"""FastAPI app factory. Mounts route modules, static assets, and SSE."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from cats.api.context import build_overview_context
from cats.api.routes import campaigns, findings, projects, sse, webhooks
from cats.db.engine import session_scope
from cats.logging import configure_logging

TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.filters["pluralize"] = lambda n, suffix="s": "" if n == 1 else suffix


def create_app() -> FastAPI:
    configure_logging()
    app = FastAPI(title="CATS", version="0.1.0")

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        return {"ok": True}

    @app.get("/")
    async def index(request: Request) -> Any:
        async with session_scope() as session:
            ctx = await build_overview_context(session)
        return templates.TemplateResponse(request, "index.html", ctx)

    app.include_router(projects.router, prefix="/projects", tags=["projects"])
    app.include_router(campaigns.router, prefix="/campaigns", tags=["campaigns"])
    app.include_router(findings.router, prefix="/findings", tags=["findings"])
    app.include_router(webhooks.router, prefix="/webhooks", tags=["webhooks"])
    app.include_router(sse.router, prefix="/events", tags=["events"])
    return app


app = create_app()
