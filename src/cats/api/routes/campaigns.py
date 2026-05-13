"""Campaign routes. Operator+ fires; the run executes in a background
task so the POST returns immediately. The live page subscribes to SSE
events to render progress."""

from __future__ import annotations

import asyncio
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse

from cats.api.auth import Principal, require_role, require_user
from cats.api.templating import templates
from cats.config import settings
from cats.db.engine import session_scope
from cats.db.repositories.audit_repo import write_audit
from cats.db.repositories.campaign_repo import (
    create_campaign_and_run,
    get_campaign_with_project,
    list_campaigns,
    list_executions_for_run,
    list_findings_for_run,
    list_runs_for_campaign,
)
from cats.db.repositories.project_repo import get_project, list_projects
from cats.logging import get_logger
from cats.security.csrf import require_csrf
from cats.workers.campaign_worker import run_one

log = get_logger(__name__)
router = APIRouter()

# Strong refs to in-flight background dispatches so asyncio doesn't GC
# them before they complete (see RUF006 / asyncio.create_task contract).
_BG_TASKS: set[asyncio.Task[None]] = set()


def _chrome_ctx(principal: Principal) -> dict[str, Any]:
    return {
        "active": "campaigns",
        "principal": principal,
        "env_tag": settings.default_target_env,
        "build_tag": settings.build_sha,
        "build_pipeline_url": settings.gitlab_pipeline_url,
        "now_utc": "",
        "db_status": "—",
        "redis_status": "—",
        "openrouter_status": "—",
    }


async def _dispatch_run(*, campaign_id: UUID, run_id: UUID, project_version_id: UUID) -> None:
    """Run the graph end-to-end. Errors are caught so the background task
    doesn't crash the app loop; the Run row carries the error state."""
    try:
        await run_one(
            campaign_id=campaign_id,
            run_id=run_id,
            project_version_id=project_version_id,
            smoke_mode=False,
        )
    except Exception as exc:
        log.exception("campaign.run_failed", run_id=str(run_id), error=repr(exc))


@router.get("")
async def campaigns_list_page(
    request: Request,
    principal: Principal = Depends(require_user),
) -> Any:
    async with session_scope() as session:
        rows = await list_campaigns(session, limit=200)
    ctx = _chrome_ctx(principal)
    ctx["campaigns"] = rows
    return templates.TemplateResponse(request, "campaigns_list.html", ctx)


@router.get("/new")
async def new_campaign_form(
    request: Request,
    principal: Principal = Depends(require_role("operator")),
) -> Any:
    async with session_scope() as session:
        projects_view = await list_projects(session)
    ctx = _chrome_ctx(principal)
    ctx["projects"] = projects_view
    return templates.TemplateResponse(request, "campaign_new.html", ctx)


@router.post("", dependencies=[Depends(require_csrf)])
async def fire_campaign(
    request: Request,
    project_id: Annotated[UUID, Form()],
    category: Annotated[str, Form()] = "injection",
    budget_usd: Annotated[float, Form()] = 5.0,
    principal: Principal = Depends(require_role("operator")),
) -> Any:
    _ = request
    if category != "injection":
        raise HTTPException(
            status_code=400,
            detail=f"R2 ships injection only (got {category!r})",
        )
    async with session_scope() as session:
        project = await get_project(session, project_id)
        if project is None:
            raise HTTPException(status_code=404, detail="project not found")
        if not project.get("allow_run_against"):
            raise HTTPException(
                status_code=400,
                detail=(
                    "Project.allow_run_against is False — flip the toggle "
                    "in the project edit form to authorize attacks."
                ),
            )
        campaign_id, run_id, project_version_id = await create_campaign_and_run(
            session,
            project_id=project_id,
            name=f"{category} · {project['name']}",
            category=category,
            budget_usd=budget_usd,
        )
        await write_audit(
            session,
            actor=principal.email,
            action="campaign.fired",
            target_kind="campaign",
            target_id=campaign_id,
            payload={
                "category": category,
                "budget_usd": budget_usd,
                "project_id": str(project_id),
                "run_id": str(run_id),
            },
        )

    # Dispatch the graph as a background task; HTTP returns immediately.
    # Keep a strong reference on the module so the task doesn't get GC'd
    # mid-flight (the RUF006 ruff rule catches this footgun).
    task = asyncio.create_task(
        _dispatch_run(
            campaign_id=campaign_id,
            run_id=run_id,
            project_version_id=project_version_id,
        )
    )
    _BG_TASKS.add(task)
    task.add_done_callback(_BG_TASKS.discard)
    return RedirectResponse(url=f"/campaigns/{campaign_id}", status_code=303)


@router.get("/{campaign_id}")
async def campaign_detail(
    request: Request,
    campaign_id: UUID,
    principal: Principal = Depends(require_user),
) -> Any:
    async with session_scope() as session:
        campaign = await get_campaign_with_project(session, campaign_id=campaign_id)
        if campaign is None:
            raise HTTPException(status_code=404, detail="campaign not found")
        runs = await list_runs_for_campaign(session, campaign_id=campaign_id)
        # Per-run findings + executions for the most-recent run (R2: one
        # run per campaign).
        latest_run = runs[0] if runs else None
        findings = []
        executions = []
        if latest_run is not None:
            findings = await list_findings_for_run(session, run_id=latest_run["id"])
            executions = await list_executions_for_run(session, run_id=latest_run["id"])

    ctx = _chrome_ctx(principal)
    ctx.update(
        {
            "campaign": campaign,
            "runs": runs,
            "latest_run": latest_run,
            "findings": findings,
            "executions": executions,
            "cost_by_agent": _cost_by_agent(executions),
            "langsmith_url_base": settings.langsmith_url_base.rstrip("/"),
        }
    )
    return templates.TemplateResponse(request, "campaign_detail.html", ctx)


def _cost_by_agent(executions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Aggregate `attack_executions.agent_role` into a per-role total
    for the cost breakdown panel."""
    by_role: dict[str, dict[str, Any]] = {}
    for e in executions:
        role = e.get("agent_role") or "unknown"
        slot = by_role.setdefault(role, {"role": role, "tokens_in": 0, "tokens_out": 0, "usd": 0.0})
        slot["tokens_in"] += int(e.get("tokens_in") or 0)
        slot["tokens_out"] += int(e.get("tokens_out") or 0)
        slot["usd"] += float(e.get("usd") or 0.0)
    return sorted(by_role.values(), key=lambda r: r["usd"], reverse=True)
