"""Orchestrator worker process.

R4 Commit A — *stub planner.* Consumes ``CampaignRequested`` and
emits a deterministic ``CampaignPlanProposed`` whose plan mirrors
R3's injection ROTATION. The stub also writes the ``campaign_plans``
row and immediately emits a matching ``CampaignPlanApproved`` so the
new four-worker topology preserves R3's end-to-end behavior. The
human-in-the-loop gate is NOT exercised in Commit A — the Commit B
follow-up replaces this body with the real LLM-driven planner and
moves approval to the operator UI.

The contract this stub establishes (what kinds it consumes / emits,
what shape the plan has) is what Commit B's planner will preserve.
"""

from __future__ import annotations

import asyncio
import json
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from cats.agents.red_team.injection.dispatcher import ROTATION as INJECTION_ROTATION
from cats.messaging import (
    CampaignPlanApprovedPayload,
    CampaignPlanProposedPayload,
    CampaignRequestedPayload,
    ClaimedMessage,
    Envelope,
    MessageKind,
    PlanAttempt,
    PlannedCampaign,
    Worker,
)

# Commit-A stub plan: same three injection techniques R3 walked in
# MIN_TECHNIQUES_PER_CAMPAIGN order. Commit B replaces this with an
# LLM tool-call planning loop.
_STUB_NUM_TECHNIQUES = 3


class OrchestratorWorker(Worker):
    """Orchestrator agent. Commit A: deterministic stub planner."""

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
        campaign_id = await self._ensure_campaign_for_request(session, payload)
        plan = self._stub_plan(payload.budget_usd)
        plan_id = await self._record_proposed_plan(session, campaign_id=campaign_id, plan=plan)

        # Emit the proposed plan. The operator UI consumes this kind
        # from the `operator` inbox (Commit B); Commit A skips that
        # by also self-approving below.
        await self._bus.emit(
            session,
            Envelope[CampaignPlanProposedPayload](
                kind=MessageKind.CAMPAIGN_PLAN_PROPOSED,
                from_agent="orchestrator",
                to_agent="operator",
                payload=CampaignPlanProposedPayload(
                    campaign_id=campaign_id,
                    plan=plan,
                    tool_transcript=[],
                    plan_id=plan_id,
                ),
                trace_id=message.trace_id,
                campaign_id=campaign_id,
                idempotency_key=f"orchestrator:plan_proposed:{plan_id}",
            ),
        )

        # Commit-A passthrough: auto-approve the proposed plan so
        # Red Team gets work immediately. Commit B removes this.
        await self._auto_approve(
            session,
            campaign_id=campaign_id,
            plan=plan,
            plan_id=plan_id,
            project_version_id=payload.project_version_id,
            trace_id=message.trace_id,
        )

    # ------------------------------------------------------------------
    # Stub plan
    # ------------------------------------------------------------------

    @staticmethod
    def _stub_plan(budget_usd: float) -> PlannedCampaign:
        per_attempt = max(0.05, budget_usd / max(1, _STUB_NUM_TECHNIQUES))
        attempts = [
            PlanAttempt(
                category="injection",
                technique=technique,
                per_attempt_budget_usd=per_attempt,
                max_consecutive_partials=2,
            )
            for technique in INJECTION_ROTATION[:_STUB_NUM_TECHNIQUES]
        ]
        return PlannedCampaign(
            attempts=attempts,
            rationale=(
                "R4 Commit-A stub planner: walks the first three "
                "injection techniques. The Commit-B LLM planner replaces "
                "this with grounded reasoning over the coverage / "
                "findings / regressions tool surface."
            ),
            confidence="medium",
            halt_on_consecutive_fails=3,
            halt_on_judge_errors=2,
            budget_usd_cap=budget_usd,
        )

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    async def _ensure_campaign_for_request(
        self,
        session: AsyncSession,
        payload: CampaignRequestedPayload,
    ) -> UUID:
        """A CampaignRequested may name an existing campaign_id via
        a row the API created, or — for the stub flow — we create the
        campaign here. Commit B's plan-approval UI relies on a campaign
        row existing, so we always upsert one keyed by project_id.

        For Commit A: we just create a fresh campaign per request and
        return its id. Commit B's API will create the campaign first
        and pass its id in the payload."""
        from cats.db.repositories.campaign_repo import create_campaign_and_run

        # Re-use create_campaign_and_run to get a campaign + first run
        # — but the run will be re-created per plan attempt by the Red
        # Team. The throwaway first run here is harmless; the Red Team
        # never sees it.
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
    ) -> UUID:
        row = (
            await session.execute(
                text(
                    """
                    INSERT INTO campaign_plans
                        (campaign_id, status, proposed_plan, rationale)
                    VALUES (:cid, 'proposed', CAST(:plan AS jsonb), :rationale)
                    RETURNING id
                    """
                ),
                {
                    "cid": campaign_id,
                    "plan": json.dumps(plan.model_dump(mode="json")),
                    "rationale": plan.rationale,
                },
            )
        ).first()
        if row is None:
            raise RuntimeError("failed to insert campaign_plans row")
        return UUID(str(row.id))

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
                    diff_summary={"auto_approved": True, "commit_a_stub": True},
                    approver_user_id=None,
                    plan_id=plan_id,
                    project_version_id=project_version_id,
                ),
                trace_id=trace_id,
                campaign_id=campaign_id,
                idempotency_key=f"orchestrator:plan_approved:{plan_id}",
            ),
        )


def main() -> None:
    """``uv run python -m cats.workers.orchestrator``"""
    asyncio.run(OrchestratorWorker().run())


if __name__ == "__main__":
    main()
