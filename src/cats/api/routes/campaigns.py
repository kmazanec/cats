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
    get_execution_full,
    get_run_with_campaign,
    list_campaigns,
    list_executions_for_run,
    list_executions_full,
    list_findings_for_run,
    list_runs_for_campaign,
)
from cats.db.repositories.project_repo import get_project, list_projects
from cats.logging import get_logger
from cats.messaging import (
    CampaignRequestedPayload,
    Envelope,
    MessageKind,
)
from cats.messaging.bus import Bus
from cats.security.csrf import require_csrf

log = get_logger(__name__)
router = APIRouter()

# R3-era background task set kept for backwards compatibility with
# legacy code paths. R4's dispatch flow is bus-mediated and does NOT
# spawn asyncio tasks — the Orchestrator worker handles CampaignRequested.
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


async def _emit_campaign_requested(
    *,
    campaign_id: UUID,
    project_id: UUID,
    project_version_id: UUID,
    budget_usd: float,
    operator_user_id: UUID | None,
    name: str,
) -> None:
    """R4: emit a ``CampaignRequested`` envelope onto the Orchestrator's
    inbox. The Orchestrator worker authors a plan, the operator approves
    it, and only then does the Red Team worker fire — none of that work
    happens in the HTTP request lifetime anymore.

    The API has already created the ``campaigns`` row; the Orchestrator
    plans against THAT campaign rather than creating a duplicate."""
    bus = Bus()
    envelope = Envelope[CampaignRequestedPayload](
        kind=MessageKind.CAMPAIGN_REQUESTED,
        from_agent="trigger",
        to_agent="orchestrator",
        payload=CampaignRequestedPayload(
            project_id=project_id,
            project_version_id=project_version_id,
            budget_usd=budget_usd,
            operator_user_id=operator_user_id,
            name=name,
            campaign_id=campaign_id,
        ),
        campaign_id=campaign_id,
        idempotency_key=f"trigger:campaign_requested:{campaign_id}",
    )
    async with session_scope() as session:
        await bus.emit(session, envelope)
        await session.commit()


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
    budget_usd: Annotated[float, Form()] = 5.0,
    category: Annotated[str, Form()] = "",  # R4: ignored; Orchestrator picks
    principal: Principal = Depends(require_role("operator")),
) -> Any:
    """R4: the route emits a ``CampaignRequested`` onto the
    Orchestrator's inbox. The Orchestrator authors a plan; the operator
    approves it; the Red Team executes. The legacy ``category`` form
    field is accepted but ignored — kept so R3 tests/fixtures keep
    parsing without immediate breakage."""
    _ = request
    _ = category  # R4: Orchestrator picks; legacy field still parsed
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
        # Reuse the existing helper to materialize a project_version_id
        # (and a throwaway campaign + run). The Orchestrator worker's
        # stub planner will create its own campaign row when it
        # processes the envelope; we just need a valid
        # project_version_id reference for the envelope. The Red Team
        # worker creates its own per-attempt runs against this campaign;
        # the row created here is the canonical campaign the Orchestrator
        # plans against (NOT a duplicate-creating throwaway).
        campaign_id, _stub_run_id, project_version_id = await create_campaign_and_run(
            session,
            project_id=project_id,
            name=f"trigger · {project['name']}",
            category="injection",
            budget_usd=budget_usd,
        )
        await write_audit(
            session,
            actor=principal.email,
            action="campaign.requested",
            target_kind="campaign",
            target_id=campaign_id,
            payload={
                "budget_usd": budget_usd,
                "project_id": str(project_id),
                "project_version_id": str(project_version_id),
            },
        )

    await _emit_campaign_requested(
        campaign_id=campaign_id,
        project_id=project_id,
        project_version_id=project_version_id,
        budget_usd=budget_usd,
        operator_user_id=None,
        name=f"trigger · {project['name']}",
    )
    return RedirectResponse(url=f"/campaigns/{campaign_id}", status_code=303)


@router.get("/{campaign_id}")
async def campaign_detail(
    request: Request,
    campaign_id: UUID,
    principal: Principal = Depends(require_user),
) -> Any:
    from sqlalchemy import text as _text

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
        # R4 Commit B: surface the latest plan row's status on the detail
        # page so an awaiting-approval campaign is one click from the editor.
        plan_status_row = (
            await session.execute(
                _text(
                    """
                    SELECT status FROM campaign_plans
                    WHERE campaign_id = :cid
                    ORDER BY created_at DESC
                    LIMIT 1
                    """
                ),
                {"cid": campaign_id},
            )
        ).first()
        latest_plan_status = plan_status_row.status if plan_status_row else None

    ctx = _chrome_ctx(principal)
    ctx.update(
        {
            "campaign": campaign,
            "runs": runs,
            "latest_run": latest_run,
            "findings": findings,
            "executions": executions,
            "cost_by_agent": _cost_by_agent(executions),
            "latest_plan_status": latest_plan_status,
            "langsmith_url_base": settings.langsmith_url_base.rstrip("/"),
        }
    )
    return templates.TemplateResponse(request, "campaign_detail.html", ctx)


@router.get("/{campaign_id}/runs/{run_id}")
async def run_detail(
    request: Request,
    campaign_id: UUID,
    run_id: UUID,
    principal: Principal = Depends(require_user),
) -> Any:
    """Per-run forensic view — every execution fired in this Run, plus the
    findings it produced. The campaign detail page links here once a Run
    is visible in its table."""
    async with session_scope() as session:
        run = await get_run_with_campaign(session, run_id=run_id, campaign_id=campaign_id)
        if run is None:
            raise HTTPException(status_code=404, detail="run not found for this campaign")
        executions = await list_executions_full(session, run_id=run_id)
        run_findings = await list_findings_for_run(session, run_id=run_id)

    ctx = _chrome_ctx(principal)
    ctx.update(
        {
            "run": run,
            "executions": executions,
            "findings": run_findings,
            "cost_by_agent": _cost_by_agent(executions),
            "langsmith_url_base": settings.langsmith_url_base.rstrip("/"),
        }
    )
    return templates.TemplateResponse(request, "run_detail.html", ctx)


@router.get("/{campaign_id}/runs/{run_id}/executions/{execution_id}")
async def execution_fragment(
    request: Request,
    campaign_id: UUID,
    run_id: UUID,
    execution_id: UUID,
    principal: Principal = Depends(require_user),
) -> Any:
    """HTML fragment for one execution, swapped into the run detail page
    via HTMX when a row is clicked. Returns the expanded payload, target
    response, output-filter reason, and judge rationale + evidence."""
    _ = principal
    async with session_scope() as session:
        # Bind the execution to the (campaign, run) pair so the fragment
        # can't be used to read executions from another campaign.
        run = await get_run_with_campaign(session, run_id=run_id, campaign_id=campaign_id)
        if run is None:
            raise HTTPException(status_code=404, detail="run not found for this campaign")
        execution = await get_execution_full(session, execution_id=execution_id, run_id=run_id)
        if execution is None:
            raise HTTPException(status_code=404, detail="execution not found for this run")

    return templates.TemplateResponse(
        request,
        "_execution_detail.html",
        {
            "execution": execution,
            "langsmith_url_base": settings.langsmith_url_base.rstrip("/"),
        },
    )


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
