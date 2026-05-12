"""Reachability healthcheck endpoint + dashboard view."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates

from cats.api.auth import Principal, require_user
from cats.config import settings
from cats.health.checks import HealthCheckResult, run_all_checks

router = APIRouter()

TEMPLATES_DIR = Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def _result_dict(r: HealthCheckResult) -> dict[str, str]:
    return {"name": r.name, "status": r.status, "detail": r.detail}


@router.get("/full")
async def full_health(
    principal: Principal = Depends(require_user),
) -> JSONResponse:
    _ = principal
    report = await run_all_checks()
    payload: dict[str, Any] = {
        "ok": report.overall_ok,
        "checks": [_result_dict(c) for c in report.checks],
    }
    status_code = 200 if report.overall_ok else 503
    return JSONResponse(payload, status_code=status_code)


@router.get("")
async def health_page(
    request: Request,
    principal: Principal = Depends(require_user),
) -> Any:
    report = await run_all_checks()
    ctx: dict[str, Any] = {
        "active": "health",
        "principal": principal,
        "env_tag": settings.default_target_env,
        "build_tag": settings.build_sha,
        "build_pipeline_url": settings.gitlab_pipeline_url,
        "now_utc": "",
        "db_status": "—",
        "redis_status": "—",
        "openrouter_status": "—",
        "report": report,
    }
    return templates.TemplateResponse(request, "health.html", ctx)
