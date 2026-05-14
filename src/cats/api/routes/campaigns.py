"""Campaign routes. Operator+ fires; the run executes in a background
task so the POST returns immediately. The live page subscribes to SSE
events to render progress."""

from __future__ import annotations

import asyncio
import json
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from cats.api.auth import Principal, require_role, require_user
from cats.api.templating import templates
from cats.config import settings
from cats.db.engine import session_scope
from cats.db.repositories.audit_repo import write_audit
from cats.db.repositories.campaign_repo import (
    create_campaign,
    get_campaign_with_project,
    get_execution_full,
    get_run_with_campaign,
    list_campaign_timeline,
    list_campaigns,
    list_executions_for_run,
    list_executions_full,
    list_findings_for_run,
    list_runs_for_campaign,
)
from cats.db.repositories.campaign_report_repo import get_campaign_report
from cats.db.repositories.kickoff_repo import get_for_run as _get_kickoff_for_run
from cats.db.repositories.project_repo import get_project, list_projects
from cats.db.repositories.run_repo import get_attack_artifact
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
        # Create the campaign row only — the Red Team worker
        # materializes its own per-attempt runs as it walks the
        # approved plan. Creating a stub run here used to leave a
        # permanently-pending row in the run list.
        campaign_id, project_version_id = await create_campaign(
            session,
            project_id=project_id,
            name=f"trigger · {project['name']}",
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
        # Also pull the approved/proposed plan body so we know the total
        # number of attempts the Orchestrator authored — that's what drives
        # the progress-bar segment count on the detail page.
        plan_row = (
            await session.execute(
                _text(
                    """
                    SELECT status, approved_plan, proposed_plan
                    FROM campaign_plans
                    WHERE campaign_id = :cid
                    ORDER BY created_at DESC
                    LIMIT 1
                    """
                ),
                {"cid": campaign_id},
            )
        ).first()
        latest_plan_status = plan_row.status if plan_row else None
        plan_attempts = _plan_attempts_from_row(plan_row)
        report_row = await get_campaign_report(session, campaign_id=campaign_id)
        report_status = report_row["status"] if report_row else None

    report_ready = report_status == "completed"
    campaign_terminal = report_status in ("completed", "failed")
    progress = _build_progress(
        runs=runs,
        plan_attempts=plan_attempts,
        campaign_terminal=campaign_terminal,
    )
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
            "report_ready": report_ready,
            "progress": progress,
            "stage": _initial_stage(
                plan_status=latest_plan_status,
                runs=runs,
                report_status=report_status,
            ),
            "langsmith_url_base": settings.langsmith_url_base.rstrip("/"),
        }
    )
    return templates.TemplateResponse(request, "campaign_detail.html", ctx)


def _plan_attempts_from_row(plan_row: Any) -> list[dict[str, Any]]:
    """Return the list of attempts the Orchestrator authored, preferring
    the operator-edited ``approved_plan`` over the original
    ``proposed_plan``. Returns ``[]`` if no plan row exists yet."""
    if plan_row is None:
        return []
    for blob in (plan_row.approved_plan, plan_row.proposed_plan):
        if not isinstance(blob, dict):
            continue
        attempts = blob.get("attempts")
        if isinstance(attempts, list) and attempts:
            return [a for a in attempts if isinstance(a, dict)]
    return []


def _build_progress(
    *,
    runs: list[dict[str, Any]],
    plan_attempts: list[dict[str, Any]],
    campaign_terminal: bool,
) -> dict[str, Any]:
    """Compute the campaign-detail progress strip + elapsed-clock anchors.

    Runs come in newest-first from ``list_runs_for_campaign``; the
    progress bar reads left-to-right in plan order so we reverse here.
    The strip has one segment per planned attempt — runs are matched
    against attempts positionally (the Red Team worker materializes
    runs in plan order). For campaigns where the plan hasn't been
    written yet or has fewer entries than runs (shouldn't happen, but
    defends the UI), we fall back to the run count so the bar still
    paints.

    Elapsed-clock anchors track the *attack window* per the operator's
    preference: ``started_at`` = earliest run start, ``ended_at`` =
    latest run end (only when the campaign is terminal — while live we
    leave ``ended_at`` null so the browser ticks the clock forward).
    """
    runs_ordered = list(reversed(runs))  # oldest-first
    planned_count = max(len(plan_attempts), len(runs_ordered))
    segments: list[dict[str, Any]] = []
    for i in range(planned_count):
        run = runs_ordered[i] if i < len(runs_ordered) else None
        attempt = plan_attempts[i] if i < len(plan_attempts) else None
        if run is None:
            status = "pending"
        elif run["status"] == "completed":
            status = "completed"
        elif run["status"] == "failed":
            status = "failed"
        elif run["status"] == "running":
            status = "running"
        else:
            status = "pending"  # 'pending' DB status
        seg: dict[str, Any] = {
            "status": status,
            "run_id": str(run["id"]) if run else None,
            "technique": (run and run.get("technique")) or (attempt and attempt.get("technique")),
            "category": (run and run.get("category")) or (attempt and attempt.get("category")),
        }
        segments.append(seg)

    started_dts = [r["started_at"] for r in runs if r.get("started_at") is not None]
    ended_dts = [r["ended_at"] for r in runs if r.get("ended_at") is not None]
    started_at = min(started_dts) if started_dts else None
    # Freeze the clock once the campaign is terminal AND every run has an
    # end timestamp; otherwise leave it open so the browser keeps ticking.
    ended_at = (
        max(ended_dts) if campaign_terminal and ended_dts and len(ended_dts) == len(runs) else None
    )
    return {
        "segments": segments,
        "planned_count": planned_count,
        "completed_count": sum(1 for s in segments if s["status"] == "completed"),
        "failed_count": sum(1 for s in segments if s["status"] == "failed"),
        "running_count": sum(1 for s in segments if s["status"] == "running"),
        "pending_count": sum(1 for s in segments if s["status"] == "pending"),
        "started_at": started_at.isoformat() if started_at else None,
        "ended_at": ended_at.isoformat() if ended_at else None,
    }


_STAGE_META: dict[str, dict[str, str]] = {
    "orchestrator": {"label": "Orchestrator planning", "img": "/static/img/orchestrator.png"},
    "red_team": {"label": "Red Team attacking", "img": "/static/img/red-team.png"},
    "judge": {"label": "Judge evaluating", "img": "/static/img/judge.png"},
    "documentor": {"label": "Documentor writing", "img": "/static/img/documentor.png"},
    "complete": {"label": "Campaign complete", "img": "/static/img/documentor.png"},
    "failed": {"label": "Campaign failed", "img": "/static/img/orchestrator.png"},
    "idle": {"label": "Awaiting trigger", "img": "/static/img/orchestrator.png"},
}


def _initial_stage(
    *,
    plan_status: str | None,
    runs: list[dict[str, Any]],
    report_status: str | None,
) -> dict[str, str]:
    """Pick the avatar to show on page load. The SSE handler updates
    this in the browser as events arrive — this is the cold-start
    fallback so the page never paints with no avatar.

    A campaign is "complete" only once the Documentation agent has
    written the rollup report (``campaign_reports.status == 'completed'``).
    A single terminal run does NOT mean the campaign is done — the
    Orchestrator may have queued many ``(category, technique)`` runs
    and the documenter only fires after all of them land.
    """
    if plan_status in (None, "proposed"):
        key = "orchestrator"
    elif plan_status in ("failed", "rejected"):
        key = "failed"
    elif not runs or any(r["status"] in ("pending", "running") for r in runs):
        key = "red_team"
    elif report_status == "completed":
        key = "complete"
    elif report_status == "failed":
        key = "failed"
    else:
        # All runs are terminal but the rollup report isn't done yet —
        # the Documentation agent is either generating or about to be
        # enqueued.
        key = "documentor"
    meta = _STAGE_META[key]
    return {"key": key, "label": meta["label"], "img": meta["img"]}


@router.get("/{campaign_id}/timeline")
async def campaign_timeline(
    campaign_id: UUID,
    principal: Principal = Depends(require_user),
) -> list[dict[str, Any]]:
    """JSON history of the campaign's events, ordered oldest-first, in
    the same envelope shape SSE emits. The campaign-detail page fetches
    this once on load and prepends each row before the live EventSource
    starts, so the event log survives a page reload."""
    _ = principal
    async with session_scope() as session:
        campaign = await get_campaign_with_project(session, campaign_id=campaign_id)
        if campaign is None:
            raise HTTPException(status_code=404, detail="campaign not found")
        return await list_campaign_timeline(session, campaign_id=campaign_id)


@router.get("/{campaign_id}/runs/{run_id}")
async def run_detail(
    request: Request,
    campaign_id: UUID,
    run_id: UUID,
    principal: Principal = Depends(require_user),
) -> Any:
    """Per-run forensic view — chat-style replay of the multi-turn
    conversation the Red Team agent fired, with the single run-level
    Judge verdict rendered as a hero banner at the top and per-turn
    execution detail available in a slide-out drawer.

    The Red Team agent emits one ``AttackEvent`` per run; the
    transcript field on that envelope carries the ordered list of
    (user_message, target_response) turns. We weld each turn to its
    ``attack_executions`` row via ``seed_idx`` so a click on a chat
    bubble loads the full execution fragment into the side drawer."""
    async with session_scope() as session:
        run = await get_run_with_campaign(session, run_id=run_id, campaign_id=campaign_id)
        if run is None:
            raise HTTPException(status_code=404, detail="run not found for this campaign")
        executions = await list_executions_full(session, run_id=run_id)
        run_findings = await list_findings_for_run(session, run_id=run_id)
        transcript = await _load_run_transcript(session, run_id=run_id)
        run_judgment = _run_judgment(executions)
        kickoff = await _load_kickoff(session, run_id=run_id)

    # Map seed_idx -> execution row so the chat view can dereference
    # each turn into the execution that backed it without a second
    # round-trip. Falls back to None when the agent transcript and
    # the execution table disagree (shouldn't happen, but defends the
    # template from a KeyError).
    exec_by_seed: dict[int, dict[str, Any]] = {}
    for e in executions:
        seed = e.get("seed_idx")
        if isinstance(seed, int) and seed not in exec_by_seed:
            exec_by_seed[seed] = e

    if transcript is not None:
        merged_turns: list[dict[str, Any]] = []
        for t in transcript["turns"]:
            if not isinstance(t, dict):
                continue
            seed = t.get("seed_idx")
            ex = exec_by_seed.get(seed) if isinstance(seed, int) else None
            assistant_msg = _parse_assistant_message(t.get("target_response") or "")
            merged_turns.append(
                {
                    **t,
                    "execution": ex,
                    "execution_id": (str(ex["id"]) if ex else None),
                    "assistant_message": assistant_msg,
                }
            )
        transcript = {**transcript, "turns": merged_turns}

    ctx = _chrome_ctx(principal)
    ctx.update(
        {
            "run": run,
            "executions": executions,
            "findings": run_findings,
            "transcript": transcript,
            "run_judgment": run_judgment,
            "kickoff": kickoff,
            "cost_by_agent": _cost_by_agent(executions),
            "langsmith_url_base": settings.langsmith_url_base.rstrip("/"),
        }
    )
    return templates.TemplateResponse(request, "run_detail.html", ctx)


async def _load_kickoff(session: AsyncSession, *, run_id: UUID) -> dict[str, Any] | None:
    """Load the per-Run kickoff turn for the chat view. Returns the
    parsed AssistantMessage from the canned briefing plus the wire-
    level metadata (latency, status code, conversationId, error). The
    template renders this as a target-side bubble before T0 of the
    attacker conversation. Returns ``None`` when no kickoff row exists
    (legacy runs from before the kickoff table was introduced — those
    runs went through the bypass path and don't have a kickoff to
    show)."""
    row = await _get_kickoff_for_run(session, run_id=run_id)
    if row is None:
        return None
    raw_text = ""
    if isinstance(row.target_response, dict):
        raw = row.target_response.get("text")
        if isinstance(raw, str):
            raw_text = raw
    return {
        "id": str(row.id),
        "conversation_id": row.conversation_id,
        "target_status_code": row.target_status_code,
        "target_latency_ms": row.target_latency_ms,
        "error": row.error,
        "assistant_message": _parse_assistant_message(raw_text),
        "raw_text_excerpt": raw_text[:8000],
    }


def _run_judgment(executions: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Pick the single run-level Judge verdict to display in the hero
    banner. The Red Team submits the whole conversation once at the
    end of a run, so at most one execution row carries a judge verdict
    — typically the last turn the agent fired. We pick the latest
    execution with a non-null verdict; if none is present (run failed
    before submission) we return ``None`` and the template renders a
    "pending" placeholder."""
    judged = [e for e in executions if e.get("judge_verdict")]
    if not judged:
        return None
    decisive = judged[-1]
    return {
        "verdict": decisive.get("judge_verdict"),
        "exploitability": decisive.get("judge_exploitability"),
        "rationale": decisive.get("judge_rationale") or "",
        "evidence": decisive.get("judge_evidence") or {},
        "model": decisive.get("judge_model") or "",
        "decisive_seed_idx": decisive.get("seed_idx"),
        "decisive_execution_id": str(decisive["id"]) if decisive.get("id") else None,
    }


def _parse_assistant_message(target_response: str) -> dict[str, Any] | None:
    """Scan one turn's verbatim SSE body for the final
    ``assistantMessage`` JSON frame and return the inner ``message``
    object — the actual ``AssistantMessage`` shape (``segments``,
    ``claimGroups``, ``gaps``, ``suggestedFollowUps``,
    ``archetypeFlags``) the OpenEMR copilot panel renders.

    Returns ``None`` when the target produced no assistantMessage
    event (errors, refusals, mangled envelopes). The full SSE stream
    is always available in the side drawer for forensics; only the
    chat bubble strips the SSE envelope.

    Wire shape: each SSE frame is ``event: assistantMessage`` paired
    with a ``data:`` line carrying
    ``{"type":"assistantMessage","message":{...AssistantMessage}}``.
    We honor both the ``event:`` framing and the redundant
    ``"type":"assistantMessage"`` self-declaration in the payload."""
    if not target_response:
        return None
    current_event = ""
    last_message: dict[str, Any] | None = None
    for line in target_response.splitlines():
        stripped = line.strip()
        if not stripped:
            current_event = ""
            continue
        if stripped.startswith("event:"):
            current_event = stripped[len("event:") :].strip()
            continue
        if stripped.startswith("data:"):
            payload = stripped[len("data:") :].strip()
            if not payload or payload == "[DONE]":
                continue
            try:
                obj = json.loads(payload)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict):
                continue
            self_type = obj.get("type") if isinstance(obj.get("type"), str) else None
            if current_event == "assistantMessage" or self_type == "assistantMessage":
                inner = obj.get("message")
                if isinstance(inner, dict):
                    last_message = inner
    return last_message


async def _load_run_transcript(session: AsyncSession, *, run_id: UUID) -> dict[str, Any] | None:
    """Pull the agent's conversation transcript for one run from the
    ``AttackEvent`` envelope on the bus. Returns a dict with
    ``category``, ``technique``, ``stop_reason``, and ``turns`` (list
    of ``{seed_idx, user_message, target_response, target_status_code,
    target_latency_ms, target_error}`` dicts in firing order). Returns
    None when the agent never emitted an AttackEvent (e.g. crashed
    before turn 0)."""
    row = (
        await session.execute(
            text(
                """
                SELECT payload_json
                FROM agent_messages
                WHERE kind = 'AttackEvent'
                  AND (payload_json->>'run_id')::uuid = :run_id
                ORDER BY created_at ASC
                LIMIT 1
                """
            ),
            {"run_id": run_id},
        )
    ).first()
    if row is None:
        return None
    payload = row.payload_json
    if not isinstance(payload, dict):
        return None
    turns = payload.get("transcript") or []
    if not isinstance(turns, list):
        turns = []
    return {
        "category": str(payload.get("category", "")),
        "technique": str(payload.get("technique", "")),
        "stop_reason": str(payload.get("conversation_stop_reason", "")),
        "canary": str(payload.get("canary", "")),
        "turns": turns,
    }


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
        # Surface whether this execution's (run, category, signature) is
        # already in the regression suite so the drawer can disable the
        # "Promote to regression" button rather than fire a duplicate POST.
        from cats.db.schema import findings as _findings_t
        from cats.db.schema import regression_cases as _regression_cases_t

        existing_case_row = (
            await session.execute(
                select(_regression_cases_t.c.id)
                .select_from(
                    _regression_cases_t.join(
                        _findings_t,
                        _findings_t.c.id == _regression_cases_t.c.source_finding_id,
                    )
                )
                .where(_findings_t.c.run_id == run_id)
                .where(_findings_t.c.category == execution["attack_category"])
                .where(_findings_t.c.signature == execution["attack_signature"])
            )
        ).first()
        existing_regression_case_id = (
            UUID(str(existing_case_row.id)) if existing_case_row is not None else None
        )

    return templates.TemplateResponse(
        request,
        "_execution_detail.html",
        {
            "execution": execution,
            "campaign_id": campaign_id,
            "run_id": run_id,
            "regression_case_id": existing_regression_case_id,
            "langsmith_url_base": settings.langsmith_url_base.rstrip("/"),
        },
    )


_SHA256_HEX_LEN = 64


@router.get("/{campaign_id}/runs/{run_id}/executions/{execution_id}/artifact/{sha256}")
async def execution_artifact(
    campaign_id: UUID,
    run_id: UUID,
    execution_id: UUID,
    sha256: str,
    principal: Principal = Depends(require_user),
) -> Response:
    """Stream the raw bytes of the file-borne attack payload an execution
    uploaded (R5 indirect_injection .docx and any future upload-channel
    techniques). The route is bound by the (campaign, run, execution)
    triple so artifacts from other runs aren't reachable via a guessed
    URL — the sha256 alone isn't an authorization token.

    Returns 404 when (a) the run isn't part of this campaign, (b) the
    execution isn't part of this run, or (c) the artifact row isn't
    attached to that execution's attack."""
    _ = principal
    # Cheap input validation: a malformed sha256 means a bogus link,
    # not a missing artifact — short-circuit before hitting the DB.
    if len(sha256) != _SHA256_HEX_LEN or not all(c in "0123456789abcdef" for c in sha256.lower()):
        raise HTTPException(status_code=404, detail="artifact not found")
    async with session_scope() as session:
        run = await get_run_with_campaign(session, run_id=run_id, campaign_id=campaign_id)
        if run is None:
            raise HTTPException(status_code=404, detail="run not found for this campaign")
        execution = await get_execution_full(session, execution_id=execution_id, run_id=run_id)
        if execution is None:
            raise HTTPException(status_code=404, detail="execution not found for this run")
        attack_id = execution.get("attack_id")
        if attack_id is None:
            raise HTTPException(status_code=404, detail="execution has no attack")
        artifact = await get_attack_artifact(session, attack_id=attack_id, sha256=sha256.lower())
    if artifact is None:
        raise HTTPException(status_code=404, detail="artifact not found")
    # ASCII-only safe filename for the Content-Disposition header. The
    # synthesized filenames we generate are already ASCII (e.g.
    # ``referral-CATS-DOCX-XXXX.docx``) so this is defensive against
    # unicode in user-supplied filenames future categories may emit.
    safe_name = (
        "".join(c if (c.isalnum() or c in "._-") else "_" for c in artifact["filename"])[:255]
        or "artifact.bin"
    )
    return Response(
        content=artifact["data"],
        media_type=artifact["content_type"] or "application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{safe_name}"',
            "X-Artifact-Sha256": artifact["sha256"],
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
