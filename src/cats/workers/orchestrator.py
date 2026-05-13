"""Orchestrator worker process.

Consumes ``CampaignRequested`` and emits ``CampaignPlanProposed``. Plans
come from the LLM planner over the tool surface (see
:mod:`cats.agents.orchestrator.planner`) — rationale-grounded,
structurally validated, with a tool-call transcript persisted on the
``campaign_plans`` row.

Approval routing depends on ``settings.orchestrator_auto_approve``:

- ``True`` — auto-emit ``CampaignPlanApproved`` so the Red Team fires
  immediately. Used by the R4 e2e tests + smoke path.
- ``False`` (production default) — wait for the operator to approve via
  the ``/campaigns/<id>/plan`` page. The page POSTs to the API which
  emits ``CampaignPlanApproved`` with the (possibly edited) plan.
"""

from __future__ import annotations

import asyncio
import json
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from cats.agents.orchestrator.planner import PlanStructuralError, propose_plan
from cats.config import get_settings
from cats.db.repositories.audit_repo import write_audit
from cats.graph.events import publish
from cats.messaging import (
    CampaignPlanApprovedPayload,
    CampaignPlanProposedPayload,
    CampaignRequestedPayload,
    ClaimedMessage,
    Envelope,
    MessageKind,
    PlannedCampaign,
    Worker,
)


class OrchestratorWorker(Worker):
    """Orchestrator agent — drives the LLM planner over the tool surface."""

    agent_name = "orchestrator"
    visibility_timeout_seconds = 300  # ARCHITECTURE.md §2.7 (LLM-driven)

    async def handle(self, session: AsyncSession, message: ClaimedMessage) -> None:
        if message.kind is not MessageKind.CAMPAIGN_REQUESTED:
            self._log.error(
                "orchestrator.unexpected_kind",
                kind=message.kind.value,
                message_id=str(message.message_id),
            )
            return
        payload = CampaignRequestedPayload.model_validate(message.payload_json)
        settings = get_settings()
        campaign_id = await self._ensure_campaign_for_request(session, payload)

        # Live UI: tell the campaign page the Orchestrator picked up
        # the request so the placeholder can flip from "no plan yet"
        # to "planning…" without a manual refresh.
        await publish(
            kind="campaign_requested",
            campaign_id=campaign_id,
            run_id=None,
            payload={"budget_usd": payload.budget_usd},
        )

        plan: PlannedCampaign
        tool_transcript: list[dict[str, object]] = []
        try:
            proposal = await propose_plan(
                project_id=payload.project_id,
                project_version_id=payload.project_version_id,
                budget_usd=payload.budget_usd,
                campaign_id=campaign_id,
            )
            plan = proposal.plan
            # `tool_transcript` carries Pydantic-serialized values
            # through JSON; cast tightens the type for the envelope.
            tool_transcript = list(proposal.tool_transcript)
            self._log.info(
                "orchestrator.plan_proposed",
                campaign_id=str(campaign_id),
                cold_start=proposal.cold_start,
                attempt_count=len(plan.attempts),
                model=proposal.model,
                usd=proposal.cost_usd,
            )
        except PlanStructuralError as exc:
            self._log.exception(
                "orchestrator.plan_failed",
                campaign_id=str(campaign_id),
                error=repr(exc),
            )
            await self._mark_plan_failed(session, campaign_id=campaign_id, error=repr(exc))
            await publish(
                kind="plan_failed",
                campaign_id=campaign_id,
                run_id=None,
                payload={"error": repr(exc)[:300]},
            )
            return

        plan_id = await self._record_proposed_plan(
            session,
            campaign_id=campaign_id,
            plan=plan,
            tool_transcript=tool_transcript,
        )

        # Audit-log every plan emission per the R4 DoD. The actor is
        # the platform here; the *operator's* approval lands its own
        # audit row when the HITL UI POSTs to /approve.
        await write_audit(
            session,
            actor="cats.platform.orchestrator",
            action="campaign.plan.proposed",
            target_kind="campaign_plan",
            target_id=plan_id,
            payload={
                "campaign_id": str(campaign_id),
                "attempt_count": len(plan.attempts),
                "rationale_excerpt": plan.rationale[:200],
            },
            trace_id=message.trace_id or None,
        )

        # Emit CampaignPlanProposed onto the operator's inbox. The HITL
        # UI consumes this; if `orchestrator_auto_approve` is True the
        # worker self-approves below — used by e2e tests + smoke so the
        # bus pipeline runs without a UI hop.
        await self._bus.emit(
            session,
            Envelope[CampaignPlanProposedPayload](
                kind=MessageKind.CAMPAIGN_PLAN_PROPOSED,
                from_agent="orchestrator",
                to_agent="operator",
                payload=CampaignPlanProposedPayload(
                    campaign_id=campaign_id,
                    plan=plan,
                    tool_transcript=tool_transcript,
                    plan_id=plan_id,
                ),
                trace_id=message.trace_id,
                campaign_id=campaign_id,
                idempotency_key=f"orchestrator:plan_proposed:{plan_id}",
            ),
        )
        # Live UI: plan is ready for the operator to review.
        await publish(
            kind="plan_proposed",
            campaign_id=campaign_id,
            run_id=None,
            payload={
                "plan_id": str(plan_id),
                "attempt_count": len(plan.attempts),
                "auto_approve": settings.orchestrator_auto_approve,
            },
        )

        if settings.orchestrator_auto_approve:
            await self._auto_approve(
                session,
                campaign_id=campaign_id,
                plan=plan,
                plan_id=plan_id,
                project_version_id=payload.project_version_id,
                trace_id=message.trace_id,
            )

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    async def _ensure_campaign_for_request(
        self,
        session: AsyncSession,
        payload: CampaignRequestedPayload,
    ) -> UUID:
        """If the envelope names an existing ``campaign_id`` (the API's
        flow), plan against that campaign. Only when no campaign_id was
        supplied — webhook / CLI triggers that don't own a row yet —
        do we materialize one here.

        Creating a campaign in both places (API and worker) led to the
        "campaign detail page shows pending forever" bug: the user's
        browser tracked the API's campaign row while the bus pipeline
        ran against the worker's duplicate."""
        if payload.campaign_id is not None:
            return payload.campaign_id

        from cats.db.repositories.campaign_repo import create_campaign_and_run

        campaign_id, _run_id, _pv_id = await create_campaign_and_run(
            session,
            name=payload.name or f"r4-stub-{payload.project_id}",
            project_id=payload.project_id,
            category="injection",
            budget_usd=payload.budget_usd,
        )
        return campaign_id

    async def _record_proposed_plan(
        self,
        session: AsyncSession,
        *,
        campaign_id: UUID,
        plan: PlannedCampaign,
        tool_transcript: list[dict[str, object]] | None = None,
    ) -> UUID:
        row = (
            await session.execute(
                text(
                    """
                    INSERT INTO campaign_plans
                        (campaign_id, status, proposed_plan, rationale,
                         tool_transcript)
                    VALUES (:cid, 'proposed', CAST(:plan AS jsonb), :rationale,
                            CAST(:transcript AS jsonb))
                    RETURNING id
                    """
                ),
                {
                    "cid": campaign_id,
                    "plan": json.dumps(plan.model_dump(mode="json")),
                    "rationale": plan.rationale,
                    "transcript": json.dumps(tool_transcript or [], default=str),
                },
            )
        ).first()
        if row is None:
            raise RuntimeError("failed to insert campaign_plans row")
        return UUID(str(row.id))

    async def _mark_plan_failed(
        self,
        session: AsyncSession,
        *,
        campaign_id: UUID,
        error: str,
    ) -> None:
        """The LLM planner failed structural validation (or the LLM call
        itself failed). Persist a ``failed`` row so the operator UI
        surfaces the error and offers a retry."""
        await session.execute(
            text(
                """
                INSERT INTO campaign_plans
                    (campaign_id, status, proposed_plan, rationale)
                VALUES (:cid, 'failed', CAST(:plan AS jsonb), :err)
                """
            ),
            {
                "cid": campaign_id,
                "plan": json.dumps({"error": error[:2000]}),
                "err": error[:2000],
            },
        )

    async def _auto_approve(
        self,
        session: AsyncSession,
        *,
        campaign_id: UUID,
        plan: PlannedCampaign,
        plan_id: UUID,
        project_version_id: UUID,
        trace_id: str,
    ) -> None:
        await session.execute(
            text(
                """
                UPDATE campaign_plans
                SET status = 'approved',
                    approved_plan = proposed_plan,
                    approved_at = now()
                WHERE id = :pid
                """
            ),
            {"pid": plan_id},
        )
        await self._bus.emit(
            session,
            Envelope[CampaignPlanApprovedPayload](
                kind=MessageKind.CAMPAIGN_PLAN_APPROVED,
                from_agent="orchestrator",
                to_agent="red_team",
                payload=CampaignPlanApprovedPayload(
                    campaign_id=campaign_id,
                    plan=plan,
                    proposed_plan=plan,
                    diff_summary={"auto_approved": True},
                    approver_user_id=None,
                    plan_id=plan_id,
                    project_version_id=project_version_id,
                ),
                trace_id=trace_id,
                campaign_id=campaign_id,
                idempotency_key=f"orchestrator:plan_approved:{plan_id}",
            ),
        )
        await publish(
            kind="plan_approved",
            campaign_id=campaign_id,
            run_id=None,
            payload={"plan_id": str(plan_id), "auto_approved": True},
        )


def main() -> None:
    """``uv run python -m cats.workers.orchestrator``"""
    asyncio.run(OrchestratorWorker().run())


if __name__ == "__main__":
    main()
