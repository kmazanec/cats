"""FastAPI app factory. Mounts route modules + the SSE channel."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from cats.api.routes import campaigns, findings, projects, sse, webhooks
from cats.logging import configure_logging

TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def create_app() -> FastAPI:
    configure_logging()
    app = FastAPI(title="CATS", version="0.1.0")

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        return {"ok": True}

    @app.get("/", response_class=HTMLResponse)
    async def index() -> HTMLResponse:
        tpl_path = TEMPLATES_DIR / "base.html"
        return HTMLResponse(tpl_path.read_text())

    app.include_router(projects.router, prefix="/projects", tags=["projects"])
    app.include_router(campaigns.router, prefix="/campaigns", tags=["campaigns"])
    app.include_router(findings.router, prefix="/findings", tags=["findings"])
    app.include_router(webhooks.router, prefix="/webhooks", tags=["webhooks"])
    app.include_router(sse.router, prefix="/events", tags=["events"])
    return app


app = create_app()
