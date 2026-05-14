"""Red Team worker process.

R10-follow-up — the Red Team is now an autonomous LangGraph agent that
owns its own multi-turn conversation. The worker's job here is small:

1. Consume :class:`CampaignPlanApprovedPayload` envelopes from the bus.
2. Create ONE ``runs`` row per approved plan and mark it ``running``.
3. For each :class:`PlanAttempt` in the plan, call
   :func:`run_red_team_agent` with the shared ``run_id``. The agent
   decides what to send, fires at the live target, mutates on its own,
   and submits when it judges that attempt's conversation done. Each
   attempt produces its own :class:`AttackEvent` (so the Judge can
   rule per-attempt) but they all share ``run_id``.
4. Mark the run terminal when every attempt has been walked.

The run boundary is the *agent's whole session against the project*,
not one attempt — that's how an operator naturally reads "a Red Team
run." Multiple ``AttackEvent`` envelopes sharing a ``run_id`` is the
shape the UI and Judge are built for.

The previous worker-driven for-loop (seed 0..K-1) + side-car escalation
strategist is gone — those decisions live inside the agent now. The
partial-verdict variant loop is also gone: the agent already mutates
within an attempt; a Judge ``partial`` ruling is now the verdict (it
doesn't trigger another worker-driven turn).
"""

from __future__ import annotations

import asyncio
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from cats.agents.red_team.agent import (
    RedTeamAgentResult,
    run_red_team_agent,
)
from cats.db.engine import session_scope
from cats.db.repositories.campaign_repo import create_run_in_campaign
from cats.db.repositories.run_repo import (
    mark_run_completed,
    mark_run_failed,
    mark_run_running,
    sweep_orphaned_running_runs,
)
from cats.graph.events import publish
from cats.messaging import (
    AttackEventPayload,
    CampaignPlanApprovedPayload,
    ClaimedMessage,
    Envelope,
    MessageKind,
    VerdictRenderedPayload,
    Worker,
)
from cats.messaging.envelopes import ConversationTurnPayload, PlanAttempt


class RedTeamWorker(Worker):
    """Red Team worker — drives one Red Team agent per PlanAttempt."""

    agent_name = "red_team"
    # R10-follow-up — the LangGraph agent can fire up to MAX_AGENT_TURNS
    # (12) attacker LLM calls per conversation, and each call typically
    # involves a multi-second OpenRouter round-trip plus a multi-second
    # OpenEMR briefing round-trip (the target's own LLM-backed). 300s
    # was tight under the old worker-driven for-loop; under agent
    # control it can run hot. 900s keeps a safety margin without
    # pretending the worker is allowed to hang forever (the campaign
    # supervisor will sweep orphaned runs eventually).
    visibility_timeout_seconds = 900  # ARCHITECTURE.md §2.7

    async def run(self) -> None:
        # See sweep-orphan rationale: ``_handle_plan_approved`` is not
        # checkpointed, so a restart mid-walk leaves runs orphaned at
        # ``running``. Safe one-time sweep since this worker is the only
        # writer of that status and there's only one replica.
        async with session_scope() as session:
            swept = await sweep_orphaned_running_runs(session)
        if swept:
            self._log.info(
                "red_team.orphan_sweep",
                swept_run_ids=[str(r) for r in swept],
                count=len(swept),
            )
        await super().run()

    async def handle(self, session: AsyncSession, message: ClaimedMessage) -> None:
        if message.kind is MessageKind.CAMPAIGN_PLAN_APPROVED:
            payload = CampaignPlanApprovedPayload.model_validate(message.payload_json)
            await self._handle_plan_approved(session, payload, message.trace_id)
        elif message.kind is MessageKind.VERDICT_RENDERED:
            payload_v = VerdictRenderedPayload.model_validate(message.payload_json)
            await self._handle_verdict_rendered(session, payload_v, message.trace_id)
        else:
            self._log.error(
                "red_team.unexpected_kind",
                kind=message.kind.value,
                message_id=str(message.message_id),
            )

    # ------------------------------------------------------------------
    # Plan-approved handler
    # ------------------------------------------------------------------

    async def _handle_plan_approved(
        self,
        session: AsyncSession,
        payload: CampaignPlanApprovedPayload,
        trace_id: str,
    ) -> None:
        """Walk the plan. ONE ``runs`` row covers the whole session;
        the agent walks every :class:`PlanAttempt` inside it. Each
        attempt is a multi-turn conversation that produces its own
        ``AttackEvent`` envelope — all sharing ``run_id`` so the UI
        and Judge can group them by session.

        Run lifecycle:
          - Create the run row and mark ``running`` before the first
            attempt fires.
          - On unrecoverable agent failure (no turns fired), advance
            the ``halt_on_consecutive_fails`` counter; halt the rest
            of the plan if it crosses the threshold.
          - Mark the run ``completed`` once the plan has been walked
            (or the consecutive-fails halt fired).
          - On a bare exception escaping the loop, mark ``failed``.
        """
        plan = payload.plan
        run_id = await create_run_in_campaign(
            session,
            campaign_id=payload.campaign_id,
            project_version_id=payload.project_version_id,
        )
        await mark_run_running(session, run_id=run_id)
        await publish(
            kind="run_started",
            campaign_id=payload.campaign_id,
            run_id=run_id,
            payload={
                "attempt_count": len(plan.attempts),
                "agent_driven": True,
                "multi_turn": True,
            },
        )

        consecutive_fails = 0
        total_budget_usd = 0.0
        try:
            for idx, attempt in enumerate(plan.attempts):
                try:
                    ok, budget_usd = await self._run_one_attempt(
                        session,
                        payload=payload,
                        run_id=run_id,
                        attempt=attempt,
                        attempt_idx=idx,
                        trace_id=trace_id,
                    )
                except Exception as exc:
                    self._log.exception(
                        "red_team.agent_attempt_failed",
                        error=repr(exc),
                        campaign_id=str(payload.campaign_id),
                        attempt_idx=idx,
                    )
                    ok = False
                    budget_usd = 0.0

                total_budget_usd += budget_usd
                if not ok:
                    consecutive_fails += 1
                    if consecutive_fails >= plan.halt_on_consecutive_fails:
                        self._log.info(
                            "red_team.halted",
                            reason="consecutive_fails",
                            campaign_id=str(payload.campaign_id),
                            run_id=str(run_id),
                        )
                        break
                else:
                    consecutive_fails = 0
        except Exception:
            await mark_run_failed(session, run_id=run_id)
            raise
        await mark_run_completed(
            session,
            run_id=run_id,
            budget_consumed_usd=total_budget_usd,
        )

    async def _run_one_attempt(
        self,
        session: AsyncSession,
        *,
        payload: CampaignPlanApprovedPayload,
        run_id: UUID,
        attempt: PlanAttempt,
        attempt_idx: int,
        trace_id: str,
    ) -> tuple[bool, float]:
        """Drive ONE LangGraph agent attempt inside the run. Returns
        ``(ok, budget_consumed_usd)``: ``ok=True`` when at least one
        turn fired and an ``AttackEvent`` was emitted; ``False`` when
        the agent never reached the target.

        The run row is owned by the caller — this function only
        publishes per-attempt SSE events and emits the AttackEvent."""
        await publish(
            kind="attempt_started",
            campaign_id=payload.campaign_id,
            run_id=run_id,
            payload={
                "attempt_idx": attempt_idx,
                "category": attempt.category,
                "technique": attempt.technique,
            },
        )

        agent_result: RedTeamAgentResult = await run_red_team_agent(
            session=session,
            campaign_id=payload.campaign_id,
            run_id=run_id,
            project_version_id=payload.project_version_id,
            attempt=attempt,
            trace_id=trace_id,
        )
        budget_usd = sum(c.usd for c in agent_result.costs)

        if not agent_result.transcript:
            # Agent never fired anything — no AttackEvent to emit.
            self._log.warning(
                "red_team.agent_no_turns",
                campaign_id=str(payload.campaign_id),
                run_id=str(run_id),
                attempt_idx=attempt_idx,
                stop_reason=agent_result.stop_reason,
            )
            return False, budget_usd

        if agent_result.last_attack_id is None or agent_result.last_turn is None:
            # Defensive: transcript non-empty but no last_attack_id is
            # a structural bug — log loudly and treat as a no-turn run.
            self._log.error(
                "red_team.agent_missing_last_attack_id",
                run_id=str(run_id),
                attempt_idx=attempt_idx,
                stop_reason=agent_result.stop_reason,
            )
            return False, budget_usd

        await self._bus.emit(
            session,
            _attack_event_envelope(
                campaign_id=payload.campaign_id,
                run_id=run_id,
                attempt=attempt,
                attempt_idx=attempt_idx,
                trace_id=trace_id,
                transcript=agent_result.transcript,
                last_turn=agent_result.last_turn,
                last_attack_id=agent_result.last_attack_id,
                canary=agent_result.canary,
                stop_reason=agent_result.stop_reason,
            ),
        )
        return True, budget_usd

    # ------------------------------------------------------------------
    # Verdict-rendered handler
    # ------------------------------------------------------------------

    async def _handle_verdict_rendered(
        self,
        session: AsyncSession,
        payload: VerdictRenderedPayload,
        trace_id: str,
    ) -> None:
        """Route partial verdicts to a no-op.

        Pre-R10-follow-up the worker drove a Mutator-based variant loop
        on every Judge ``partial`` ruling. That made sense when the Red
        Team was a single-shot per-seed pipeline. Now that the agent
        owns multi-turn escalation *inside* the conversation, a
        ``partial`` verdict is the agent's own decision — surfacing it
        again here would double-iterate. Log + drop so the bus contract
        still routes partials to this inbox without producing follow-up
        runs."""
        _ = (session, trace_id)
        if payload.verdict == "partial":
            self._log.info(
                "red_team.partial_verdict_noop",
                attack_id=str(payload.attack_id),
                rationale=(
                    "agent already owns escalation; partials no longer "
                    "trigger worker-driven variants"
                ),
            )
        else:
            # Pass/fail/error land on Documentation, not here — log and
            # drop. This branch only fires when bus routing changes
            # underneath us.
            self._log.warning(
                "red_team.unexpected_verdict",
                verdict=payload.verdict,
                attack_id=str(payload.attack_id),
            )


def _attack_event_envelope(
    *,
    campaign_id: UUID,
    run_id: UUID,
    attempt: PlanAttempt,
    attempt_idx: int,
    trace_id: str,
    transcript: list[ConversationTurnPayload],
    last_turn: ConversationTurnPayload,
    last_attack_id: UUID,
    canary: str,
    stop_reason: str,
) -> Envelope[AttackEventPayload]:
    """Build one ``AttackEvent`` per agent attempt. Multiple attempts
    in one run produce multiple envelopes sharing ``run_id`` — they're
    disambiguated by ``attack_execution_id`` (each attempt fires its
    own ``attack_executions`` rows) and the ``attempt_idx``-suffixed
    idempotency key.

    Legacy fields mirror the final realized turn so single-turn-aware
    consumers (the Judge's evidence layer, older reports) keep working
    without transcript-awareness."""
    return Envelope[AttackEventPayload](
        kind=MessageKind.ATTACK_EVENT,
        from_agent="red_team",
        to_agent="judge",
        payload=AttackEventPayload(
            campaign_id=campaign_id,
            run_id=run_id,
            attack_id=last_attack_id,
            attack_execution_id=last_turn.attack_execution_id,
            category=attempt.category,
            technique=attempt.technique,
            payload=last_turn.user_message,
            target_response=last_turn.target_response,
            target_status_code=last_turn.target_status_code,
            target_error=last_turn.target_error,
            target_latency_ms=last_turn.target_latency_ms,
            canary=canary,
            iteration=0,
            seed_idx=last_turn.seed_idx,
            transcript=transcript,
            conversation_stop_reason=stop_reason,
        ),
        trace_id=trace_id,
        campaign_id=campaign_id,
        attack_id=last_attack_id,
        idempotency_key=(
            f"red_team_agent:attack_event:{run_id}:{attempt_idx}:{last_turn.attack_execution_id}"
        ),
    )


def main() -> None:
    """``uv run python -m cats.workers.red_team``"""
    asyncio.run(RedTeamWorker().run())


if __name__ == "__main__":
    main()
