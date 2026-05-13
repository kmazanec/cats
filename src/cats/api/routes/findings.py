"""Findings list + detail."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request

from cats.api.auth import Principal, require_user
from cats.api.templating import templates
from cats.config import settings
from cats.db.engine import session_scope
from cats.db.repositories.campaign_repo import (
    get_finding_with_report,
    list_executions_for_run,
)
from cats.db.repositories.campaign_repo import (
    list_findings as repo_list_findings,
)

router = APIRouter()


def _chrome_ctx(principal: Principal) -> dict[str, Any]:
    return {
        "active": "findings",
        "principal": principal,
        "env_tag": settings.default_target_env,
        "build_tag": settings.build_sha,
        "build_pipeline_url": settings.gitlab_pipeline_url,
        "now_utc": "",
        "db_status": "—",
        "redis_status": "—",
        "openrouter_status": "—",
        "langsmith_url_base": settings.langsmith_url_base.rstrip("/"),
    }


_SEVERITIES = ("critical", "high", "medium", "low", "info")


@router.get("")
async def list_findings_page(
    request: Request,
    principal: Principal = Depends(require_user),
) -> Any:
    async with session_scope() as session:
        rows = await repo_list_findings(session, limit=200)
    tally = {sev: 0 for sev in _SEVERITIES}
    for f in rows:
        sev = f.get("severity")
        if sev in tally:
            tally[sev] += 1
    ctx = _chrome_ctx(principal)
    ctx.update({"findings": rows, "tally": tally})
    return templates.TemplateResponse(request, "findings_list.html", ctx)


@router.get("/{finding_id}")
async def finding_detail(
    request: Request,
    finding_id: UUID,
    principal: Principal = Depends(require_user),
) -> Any:
    async with session_scope() as session:
        finding = await get_finding_with_report(session, finding_id=finding_id)
        if finding is None:
            raise HTTPException(status_code=404, detail="finding not found")
        executions = await list_executions_for_run(session, run_id=finding["run_id"])
    ctx = _chrome_ctx(principal)
    ctx.update({"finding": finding, "executions": executions})
    return templates.TemplateResponse(request, "finding_detail.html", ctx)
