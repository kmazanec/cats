"""Operator HITL plan-approval routes.

The Orchestrator worker emits ``CampaignPlanProposed`` onto the
``operator`` inbox and writes a ``campaign_plans`` row in ``proposed``
state. This module is the operator-facing surface that consumes that
row: a full-page editor at ``GET /campaigns/{id}/plan`` and three
mutating endpoints (``approve`` / ``reject`` / ``retry``).

Form parsing strategy:
    The plan editor is one row per :class:`PlanAttempt` plus three
    top-level numeric inputs. FastAPI's ``Form()`` can't natively parse
    arrays-of-objects, so the editor template serializes the form into a
    single ``plan_json`` hidden field at submit time (a ~20-line inline
    script walks the inputs). The server parses + validates that JSON
    against :class:`PlannedCampaign` — which gives us pydantic's strict
    validation for free.

Diff shape:
    :func:`_compute_diff` returns a dict with four keys: ``added`` /
    ``removed`` / ``reordered`` / ``budget_changes``. The shape is
    stable so the audit log + the bus envelope's ``diff_summary``
    both consume it as-is.

Auto-approval interplay:
    When ``settings.orchestrator_auto_approve`` is on (the Commit-A
    default), the Orchestrator worker self-approves and the row is in
    ``approved`` state by the time the operator clicks through. We
    detect that and surface a banner instead of the editor — clicking
    Approve on an already-approved row is a no-op redirect with a flash
    message rather than a double-emit (the bus would dedupe anyway via
    the ``idempotency_key`` unique index, but failing visibly here is
    friendlier).
"""

from __future__ import annotations

import json
from typing import Annotated, Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from cats.agents.orchestrator.tools import list_attack_categories
from cats.api.auth import Principal, require_role, require_user
from cats.api.templating import templates
from cats.config import settings
from cats.db.engine import session_scope
from cats.db.repositories.audit_repo import write_audit
from cats.db.repositories.campaign_repo import get_campaign_with_project
from cats.logging import get_logger
from cats.messaging import (
    CampaignPlanApprovedPayload,
    CampaignRequestedPayload,
    Envelope,
    MessageKind,
    PlanAttempt,
    PlannedCampaign,
)
from cats.messaging.bus import Bus
from cats.security.csrf import require_csrf

log = get_logger(__name__)
router = APIRouter()


# ---------------------------------------------------------------------------
# Page-chrome ctx (matches other route modules)
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------


async def _latest_plan_for_campaign(
    session: AsyncSession, *, campaign_id: UUID
) -> dict[str, Any] | None:
    """Most-recent ``campaign_plans`` row for the campaign, or None.

    Multiple rows can exist if the operator hit Retry on a previous
    ``failed`` plan; we always show the newest by ``created_at``.
    """
    row = (
        await session.execute(
            text(
                """
                SELECT id, campaign_id, status, proposed_plan,
                       approved_plan, tool_transcript, rationale,
                       approver_user_id, approved_at, diff_summary,
                       created_at
                FROM campaign_plans
                WHERE campaign_id = :cid
                ORDER BY created_at DESC
                LIMIT 1
                """
            ),
            {"cid": campaign_id},
        )
    ).first()
    if row is None:
        return None
    return {
        "id": row.id,
        "campaign_id": row.campaign_id,
        "status": row.status,
        "proposed_plan": row.proposed_plan or {},
        "approved_plan": row.approved_plan,
        "tool_transcript": row.tool_transcript or [],
        "rationale": row.rationale or "",
        "approver_user_id": row.approver_user_id,
        "approved_at": row.approved_at,
        "diff_summary": row.diff_summary or {},
        "created_at": row.created_at,
    }


async def _campaign_budget_usd(session: AsyncSession, *, campaign_id: UUID) -> float:
    """Pull ``campaigns.budget->>'usd'`` for the Retry path. The
    CampaignRequested envelope needs a ``budget_usd``; we round-trip the
    original cap rather than asking the operator again."""
    row = (
        await session.execute(
            text("SELECT budget FROM campaigns WHERE id = :cid"),
            {"cid": campaign_id},
        )
    ).first()
    if row is None or not isinstance(row.budget, dict):
        return 5.0
    return float(row.budget.get("usd", 5.0) or 5.0)


async def _campaign_project_id(session: AsyncSession, *, campaign_id: UUID) -> UUID | None:
    """Pull ``campaigns.project_id`` directly. Lighter than
    :func:`get_campaign_with_project` when all we need is the FK."""
    row = (
        await session.execute(
            text("SELECT project_id FROM campaigns WHERE id = :cid"),
            {"cid": campaign_id},
        )
    ).first()
    return row.project_id if row is not None else None


async def _project_version_id(session: AsyncSession, *, project_id: UUID) -> UUID | None:
    """Pull the latest project_version_id for the project. Mirrors the
    behaviour of :func:`create_campaign_and_run`; we don't create one
    here because the campaign already references one."""
    row = (
        await session.execute(
            text(
                """
                SELECT id FROM project_versions
                WHERE project_id = :pid
                ORDER BY deployed_at DESC
                LIMIT 1
                """
            ),
            {"pid": project_id},
        )
    ).first()
    return row.id if row is not None else None


# ---------------------------------------------------------------------------
# Diff computation
# ---------------------------------------------------------------------------


def _compute_diff(proposed: PlannedCampaign, edited: PlannedCampaign) -> dict[str, Any]:
    """Diff two plans for the audit log + envelope.

    Returns a stable dict with four keys:
      - ``added``: list of ``{index, category, technique}`` for attempts
        present in ``edited`` but not in ``proposed`` (by category +
        technique pair).
      - ``removed``: same shape, for attempts present in ``proposed``
        but not in ``edited``.
      - ``reordered``: ``True`` if the surviving attempts appear in a
        different order in ``edited`` vs ``proposed`` (ignores additions
        and removals — purely about position of the common subset).
      - ``budget_changes``: a flat dict of per-attempt budget tweaks
        (``{ "injection/system_prompt_override": {"old": 0.5,
        "new": 0.6} }``) plus three top-level keys
        (``halt_on_consecutive_fails``, ``halt_on_judge_errors``,
        ``budget_usd_cap``) for the top-level halt-condition / cap
        changes.

    The shape is deliberately JSON-serializable for ``diff_summary``
    JSONB storage and for the ``CampaignPlanApproved`` envelope.
    """
    proposed_pairs = [(a.category, a.technique) for a in proposed.attempts]
    edited_pairs = [(a.category, a.technique) for a in edited.attempts]

    proposed_set = set(proposed_pairs)
    edited_set = set(edited_pairs)

    added = [
        {"index": i, "category": cat, "technique": tech}
        for i, (cat, tech) in enumerate(edited_pairs)
        if (cat, tech) not in proposed_set
    ]
    removed = [
        {"index": i, "category": cat, "technique": tech}
        for i, (cat, tech) in enumerate(proposed_pairs)
        if (cat, tech) not in edited_set
    ]

    # Reordered: walk the intersection in each list's order; if the two
    # walks disagree, the surviving attempts have been moved around.
    common = proposed_set & edited_set
    proposed_common = [p for p in proposed_pairs if p in common]
    edited_common = [p for p in edited_pairs if p in common]
    reordered = proposed_common != edited_common

    # Per-attempt budget / max-partials changes for the common subset.
    proposed_by_pair = {(a.category, a.technique): a for a in proposed.attempts}
    edited_by_pair = {(a.category, a.technique): a for a in edited.attempts}
    budget_changes: dict[str, Any] = {}
    for pair in sorted(common):
        before = proposed_by_pair[pair]
        after = edited_by_pair[pair]
        key = f"{pair[0]}/{pair[1]}"
        cell: dict[str, Any] = {}
        if before.per_attempt_budget_usd != after.per_attempt_budget_usd:
            cell["per_attempt_budget_usd"] = {
                "old": before.per_attempt_budget_usd,
                "new": after.per_attempt_budget_usd,
            }
        if before.max_consecutive_partials != after.max_consecutive_partials:
            cell["max_consecutive_partials"] = {
                "old": before.max_consecutive_partials,
                "new": after.max_consecutive_partials,
            }
        if cell:
            budget_changes[key] = cell

    for top_field in (
        "halt_on_consecutive_fails",
        "halt_on_judge_errors",
        "budget_usd_cap",
    ):
        before_val = getattr(proposed, top_field)
        after_val = getattr(edited, top_field)
        if before_val != after_val:
            budget_changes[top_field] = {"old": before_val, "new": after_val}

    return {
        "added": added,
        "removed": removed,
        "reordered": reordered,
        "budget_changes": budget_changes,
    }


def _diff_is_empty(diff: dict[str, Any]) -> bool:
    return (
        not diff.get("added")
        and not diff.get("removed")
        and not diff.get("reordered")
        and not diff.get("budget_changes")
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/{campaign_id}/plan")
async def plan_page(
    request: Request,
    campaign_id: UUID,
    principal: Principal = Depends(require_user),
) -> Any:
    """Full page render. Branches on plan ``status``.

    - ``proposed`` → editor: rationale, tool transcript, editable attempts.
    - ``approved`` / ``edited`` → read-only view + diff summary.
    - ``rejected`` → rejection-reason panel.
    - ``failed`` → error panel + Retry button.
    - no plan row yet → "waiting on the Orchestrator" placeholder.
    """
    async with session_scope() as session:
        campaign = await get_campaign_with_project(session, campaign_id=campaign_id)
        if campaign is None:
            raise HTTPException(status_code=404, detail="campaign not found")
        plan_row = await _latest_plan_for_campaign(session, campaign_id=campaign_id)
        catalog = await list_attack_categories()

    ctx = _chrome_ctx(principal)
    # Build the (category, technique) pair list for the Add Attempt dropdown.
    catalog_pairs: list[dict[str, str]] = []
    for cat in catalog.rows:
        for tech in cat.techniques:
            catalog_pairs.append(
                {
                    "category": cat.category,
                    "technique": tech,
                    "label": f"{cat.category} / {tech}",
                }
            )

    ctx.update(
        {
            "campaign": campaign,
            "plan_row": plan_row,
            # The editor template's inline JS lives in {% block scripts %}
            # which is a sibling of the main body block — Jinja's
            # {% set %} doesn't cross block boundaries, so `proposed`
            # has to come through the context dict rather than being
            # set on the page body. Empty dict when no row yet.
            "proposed": (plan_row or {}).get("proposed_plan") or {},
            "catalog_pairs": catalog_pairs,
            "auto_approve_on": settings.orchestrator_auto_approve,
        }
    )
    return templates.TemplateResponse(request, "plan_approval.html", ctx)


@router.post(
    "/{campaign_id}/plan/approve",
    dependencies=[Depends(require_csrf)],
)
async def approve_plan(
    request: Request,
    campaign_id: UUID,
    plan_json: Annotated[str, Form()],
    principal: Principal = Depends(require_role("operator")),
) -> Any:
    """Operator-approved (possibly edited) plan.

    Parses ``plan_json`` against :class:`PlannedCampaign`, computes the
    diff vs the originally-proposed plan, updates ``campaign_plans``
    (status ``approved`` when diff is empty, ``edited`` otherwise),
    audit-logs the action with the diff payload, and emits
    ``CampaignPlanApproved`` onto the Red Team's inbox.
    """
    _ = request
    try:
        plan_dict = json.loads(plan_json)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"plan_json is not valid JSON: {exc}") from exc
    try:
        edited_plan = PlannedCampaign.model_validate(plan_dict)
    except ValidationError as exc:
        raise HTTPException(
            status_code=400, detail=f"plan failed structural validation: {exc}"
        ) from exc

    bus = Bus()
    async with session_scope() as session:
        plan_row = await _latest_plan_for_campaign(session, campaign_id=campaign_id)
        if plan_row is None:
            raise HTTPException(status_code=404, detail="no plan row for this campaign")
        if plan_row["status"] in ("rejected", "dispatched"):
            raise HTTPException(
                status_code=409,
                detail=f"plan is {plan_row['status']}; cannot approve",
            )
        # Already approved (auto-approve path) — redirect with a banner.
        if plan_row["status"] in ("approved", "edited"):
            return RedirectResponse(
                url=f"/campaigns/{campaign_id}/plan?notice=already-approved",
                status_code=303,
            )

        try:
            proposed_plan = PlannedCampaign.model_validate(plan_row["proposed_plan"])
        except ValidationError as exc:
            raise HTTPException(
                status_code=500,
                detail=f"stored proposed_plan failed validation: {exc}",
            ) from exc

        diff = _compute_diff(proposed_plan, edited_plan)
        new_status = "approved" if _diff_is_empty(diff) else "edited"

        await session.execute(
            text(
                """
                UPDATE campaign_plans
                SET status = :status,
                    approved_plan = CAST(:approved AS jsonb),
                    diff_summary = CAST(:diff AS jsonb),
                    approver_user_id = :uid,
                    approved_at = now()
                WHERE id = :pid
                """
            ),
            {
                "status": new_status,
                "approved": json.dumps(edited_plan.model_dump(mode="json")),
                "diff": json.dumps(diff),
                "uid": principal.user_id,
                "pid": plan_row["id"],
            },
        )

        # Project version id is needed on the envelope so the Red Team
        # records its work against the right snapshot.
        project_id = await _campaign_project_id(session, campaign_id=campaign_id)
        if project_id is None:
            raise HTTPException(status_code=404, detail="campaign not found")
        pv_id = await _project_version_id(session, project_id=project_id)
        if pv_id is None:
            # Defensive — every campaign created via the API has one.
            raise HTTPException(
                status_code=500,
                detail="no project_version_id available for this campaign's project",
            )

        await bus.emit(
            session,
            Envelope[CampaignPlanApprovedPayload](
                kind=MessageKind.CAMPAIGN_PLAN_APPROVED,
                from_agent="operator",
                to_agent="red_team",
                payload=CampaignPlanApprovedPayload(
                    campaign_id=campaign_id,
                    plan=edited_plan,
                    proposed_plan=proposed_plan,
                    diff_summary=diff,
                    approver_user_id=principal.user_id,
                    plan_id=plan_row["id"],
                    project_version_id=pv_id,
                ),
                campaign_id=campaign_id,
                idempotency_key=f"operator:plan_approved:{plan_row['id']}",
            ),
        )

        await write_audit(
            session,
            actor=principal.email,
            action="campaign.plan.approved",
            target_kind="campaign_plan",
            target_id=plan_row["id"],
            payload={
                "campaign_id": str(campaign_id),
                "status": new_status,
                "diff": diff,
            },
        )

    log.info(
        "plan.approved",
        campaign_id=str(campaign_id),
        plan_id=str(plan_row["id"]),
        status=new_status,
        operator=principal.email,
    )
    # Live UI: flip the pill from "Pending Approval" → "Approved"
    # without making the operator refresh the page.
    from cats.graph.events import publish

    await publish(
        kind="plan_approved",
        campaign_id=campaign_id,
        run_id=None,
        payload={
            "plan_id": str(plan_row["id"]),
            "auto_approved": False,
            "status": new_status,
        },
    )
    return RedirectResponse(url=f"/campaigns/{campaign_id}", status_code=303)


@router.post(
    "/{campaign_id}/plan/reject",
    dependencies=[Depends(require_csrf)],
)
async def reject_plan(
    request: Request,
    campaign_id: UUID,
    reject_reason: Annotated[str, Form()] = "",
    principal: Principal = Depends(require_role("operator")),
) -> Any:
    """Operator rejects the proposed plan outright. No envelope emitted —
    the Red Team is never told to fire. The rejection reason lands on
    both the ``campaign_plans`` row (via ``diff_summary.reject_reason``,
    a reasonable home until we add a dedicated column) and the audit
    log."""
    _ = request
    async with session_scope() as session:
        plan_row = await _latest_plan_for_campaign(session, campaign_id=campaign_id)
        if plan_row is None:
            raise HTTPException(status_code=404, detail="no plan row for this campaign")
        if plan_row["status"] in ("approved", "edited", "dispatched"):
            raise HTTPException(
                status_code=409,
                detail=f"plan is {plan_row['status']}; cannot reject",
            )

        reject_reason_clean = (reject_reason or "").strip()[:2000]
        diff_payload = {"reject_reason": reject_reason_clean}

        await session.execute(
            text(
                """
                UPDATE campaign_plans
                SET status = 'rejected',
                    diff_summary = CAST(:diff AS jsonb),
                    approver_user_id = :uid,
                    approved_at = now()
                WHERE id = :pid
                """
            ),
            {
                "diff": json.dumps(diff_payload),
                "uid": principal.user_id,
                "pid": plan_row["id"],
            },
        )

        await write_audit(
            session,
            actor=principal.email,
            action="campaign.plan.rejected",
            target_kind="campaign_plan",
            target_id=plan_row["id"],
            payload={
                "campaign_id": str(campaign_id),
                "reject_reason": reject_reason_clean,
            },
        )

    log.info(
        "plan.rejected",
        campaign_id=str(campaign_id),
        plan_id=str(plan_row["id"]),
        operator=principal.email,
    )
    return RedirectResponse(url=f"/campaigns/{campaign_id}", status_code=303)


@router.post(
    "/{campaign_id}/plan/retry",
    dependencies=[Depends(require_csrf)],
)
async def retry_plan(
    request: Request,
    campaign_id: UUID,
    principal: Principal = Depends(require_role("operator")),
) -> Any:
    """For ``failed`` plans, re-emit a ``CampaignRequested`` so the
    Orchestrator tries again. The retry uses the campaign's original
    project + budget. A fresh ``request_id`` (uuid4) is used for the
    envelope's idempotency key so the unique constraint doesn't collapse
    this retry into the original."""
    _ = request
    bus = Bus()
    async with session_scope() as session:
        plan_row = await _latest_plan_for_campaign(session, campaign_id=campaign_id)
        if plan_row is None:
            raise HTTPException(status_code=404, detail="no plan row for this campaign")
        if plan_row["status"] != "failed":
            raise HTTPException(
                status_code=409,
                detail=f"plan is {plan_row['status']}; retry is only valid for failed plans",
            )
        campaign = await get_campaign_with_project(session, campaign_id=campaign_id)
        if campaign is None:
            raise HTTPException(status_code=404, detail="campaign not found")
        budget_usd = await _campaign_budget_usd(session, campaign_id=campaign_id)
        pv_id = await _project_version_id(session, project_id=campaign["project_id"])
        if pv_id is None:
            raise HTTPException(
                status_code=500,
                detail="no project_version_id available for this campaign's project",
            )

        request_id = uuid4()
        await bus.emit(
            session,
            Envelope[CampaignRequestedPayload](
                kind=MessageKind.CAMPAIGN_REQUESTED,
                from_agent="trigger",
                to_agent="orchestrator",
                payload=CampaignRequestedPayload(
                    project_id=campaign["project_id"],
                    project_version_id=pv_id,
                    budget_usd=budget_usd,
                    operator_user_id=principal.user_id,
                    name=f"retry · {campaign['name']}",
                ),
                idempotency_key=f"trigger:campaign_requested:retry:{request_id}",
            ),
        )

        await write_audit(
            session,
            actor=principal.email,
            action="campaign.plan.retried",
            target_kind="campaign_plan",
            target_id=plan_row["id"],
            payload={
                "campaign_id": str(campaign_id),
                "retry_request_id": str(request_id),
                "budget_usd": budget_usd,
            },
        )

    log.info(
        "plan.retried",
        campaign_id=str(campaign_id),
        plan_id=str(plan_row["id"]),
        operator=principal.email,
    )
    return RedirectResponse(url=f"/campaigns/{campaign_id}/plan", status_code=303)


__all__ = [
    "PlanAttempt",
    "PlannedCampaign",
    "router",
]
