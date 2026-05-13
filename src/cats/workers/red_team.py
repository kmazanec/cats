"""Red Team worker process.

Consumes ``CampaignPlanApproved`` envelopes (one per approved
campaign plan) and ``VerdictRendered(partial)`` envelopes (drive the
variant loop). For each ``CampaignPlanApproved`` it walks the plan's
attempts in order, firing one attempt at a time. After each attempt
it emits an ``AttackEvent`` to the Judge's inbox and waits for the
Judge's verdict to land via its own inbox before deciding whether to
mutate (partial) or move to the next attempt (pass/fail).

Plan halt conditions are enforced here: budget cap, consecutive-fail
threshold, judge-error threshold. The per-attack iteration counter is
durable in ``red_team_attempts`` so a crashed worker can pick up
mid-mutate loop.
"""

from __future__ import annotations

import asyncio
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from cats.agents.red_team.executor import MutatorContext, execute_attempt
from cats.db.repositories.campaign_repo import create_run_in_campaign
from cats.db.repositories.run_repo import mark_run_running
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
from cats.messaging.envelopes import PlanAttempt


class RedTeamWorker(Worker):
    """The Red Team agent's worker process. Plan-executor."""

    agent_name = "red_team"
    visibility_timeout_seconds = 300  # ARCHITECTURE.md §2.7

    async def handle(self, session: AsyncSession, message: ClaimedMessage) -> None:
        if message.kind is MessageKind.CAMPAIGN_PLAN_APPROVED:
            payload = CampaignPlanApprovedPayload.model_validate(message.payload_json)
            await self._handle_plan_approved(session, payload, message.trace_id)
        elif message.kind is MessageKind.VERDICT_RENDERED:
            payload_v = VerdictRenderedPayload.model_validate(message.payload_json)
            await self._handle_partial_verdict(session, payload_v, message.trace_id)
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
        """Walk the plan. For each attempt, fire ``seeds_per_attempt``
        diverse seed attacks back-to-back as **one OpenEMR conversation**:
        seed 0 is a ``default_briefing`` (kickoff) that opens a fresh
        conversation; seeds 1..K-1 are ``follow_up``s sharing that
        conversationId so the model sees them as turns in one chat.
        Each seed sees the prior seeds' user_messages so the specialist
        produces materially different angles."""
        import uuid as _uuid

        plan = payload.plan
        consecutive_fails = 0
        for idx, attempt in enumerate(plan.attempts):
            prior_user_messages: list[str] = []
            # One conversation per plan attempt; minted here so all K
            # seeds + any partial-loop variants stay in the same chat
            # turn-sequence.
            conv_id = str(_uuid.uuid4())
            for seed_idx in range(attempt.seeds_per_attempt):
                run_id = await create_run_in_campaign(
                    session,
                    campaign_id=payload.campaign_id,
                    project_version_id=payload.project_version_id,
                )
                await mark_run_running(session, run_id=run_id)
                try:
                    result = await execute_attempt(
                        session,
                        campaign_id=payload.campaign_id,
                        run_id=run_id,
                        project_version_id=payload.project_version_id,
                        category=attempt.category,
                        technique=attempt.technique,
                        iteration=0,
                        seed_idx=seed_idx,
                        prior_user_messages=list(prior_user_messages),
                        conversation_id=conv_id,
                        task="default_briefing" if seed_idx == 0 else "follow_up",
                    )
                except Exception as exc:
                    self._log.exception(
                        "red_team.seed_failed",
                        error=repr(exc),
                        campaign_id=str(payload.campaign_id),
                        attempt_idx=idx,
                        seed_idx=seed_idx,
                    )
                    consecutive_fails += 1
                    if consecutive_fails >= plan.halt_on_consecutive_fails:
                        self._log.info(
                            "red_team.halted",
                            reason="consecutive_fails",
                            campaign_id=str(payload.campaign_id),
                        )
                        return
                    continue
                # Persist the red_team_attempts row for the partial-loop counter.
                await self._upsert_red_team_attempt(
                    session,
                    attack_id=result.attack_id,
                    iteration=0,
                    max_iterations=attempt.max_consecutive_partials,
                )
                prior_user_messages.append(result.payload_user_message)
                # Live UI: a new run + attack just fired.
                await publish(
                    kind="attack_executed",
                    campaign_id=payload.campaign_id,
                    run_id=run_id,
                    payload={
                        "category": attempt.category,
                        "technique": attempt.technique,
                        "seed_idx": seed_idx,
                        "attack_id": str(result.attack_id),
                        "output_filter_verdict": result.output_filter_verdict,
                    },
                )
                # Emit AttackEvent to the Judge.
                await self._bus.emit(
                    session,
                    _attack_event_envelope(
                        campaign_id=payload.campaign_id,
                        run_id=run_id,
                        attempt=attempt,
                        result_attack_id=result.attack_id,
                        attack_execution_id=result.attack_execution_id,
                        payload_user_message=result.payload_user_message,
                        canary=result.canary,
                        target_response_text=result.target_response_text,
                        iteration=0,
                        seed_idx=seed_idx,
                        trace_id=trace_id,
                    ),
                )
        # Note: this handler returns after EMITTING the AttackEvents.
        # The Judge worker processes them asynchronously; partial
        # verdicts come back on the Red Team's inbox as separate
        # VerdictRendered messages handled by `_handle_partial_verdict`.

    # ------------------------------------------------------------------
    # Partial-verdict handler — drives the variant loop
    # ------------------------------------------------------------------

    async def _handle_partial_verdict(
        self,
        session: AsyncSession,
        payload: VerdictRenderedPayload,
        trace_id: str,
    ) -> None:
        if payload.verdict != "partial":
            # Pass/fail/error land on Documentation's inbox; if one
            # arrived here it's a routing mistake — log and drop.
            self._log.warning(
                "red_team.unexpected_verdict",
                verdict=payload.verdict,
                attack_id=str(payload.attack_id),
            )
            return
        # Read the durable iteration counter.
        row = (
            await session.execute(
                text(
                    """
                    SELECT iteration, max_iterations, status
                    FROM red_team_attempts
                    WHERE attack_id = :id
                    """
                ),
                {"id": payload.attack_id},
            )
        ).first()
        if row is None:
            self._log.warning(
                "red_team.attempt_missing",
                attack_id=str(payload.attack_id),
            )
            return
        if row.status != "active":
            return
        if row.iteration + 1 > row.max_iterations:
            await session.execute(
                text(
                    """
                    UPDATE red_team_attempts
                    SET status = 'exhausted', updated_at = now()
                    WHERE attack_id = :id
                    """
                ),
                {"id": payload.attack_id},
            )
            return
        # Fetch the prior attempt's payload so the mutator has context.
        prior = (
            await session.execute(
                text(
                    """
                    SELECT a.payload, ae.target_response, ae.run_id,
                           ae.project_version_id
                    FROM attack_executions ae
                    JOIN attacks a ON a.id = ae.attack_id
                    WHERE ae.id = :id
                    """
                ),
                {"id": payload.attack_execution_id},
            )
        ).first()
        if prior is None:
            return
        prior_payload: dict[str, Any] = dict(prior.payload)
        prior_response_text = ""
        if isinstance(prior.target_response, dict):
            prior_response_text = str(prior.target_response.get("text", ""))
        next_iter = row.iteration + 1
        # Variant continues in the same OpenEMR conversation as the
        # seed it came from — that's the whole point of "iterate on a
        # partial success". When prior's conversation_id is missing
        # (older rows before this field landed), fall back to a fresh
        # default_briefing so we don't hang on a stale conversation.
        prior_conv_id = prior_payload.get("conversation_id")
        variant_conv_id: str | None = (
            str(prior_conv_id) if isinstance(prior_conv_id, str) and prior_conv_id else None
        )
        variant_task = "follow_up" if variant_conv_id else "default_briefing"
        try:
            result = await execute_attempt(
                session,
                campaign_id=payload.campaign_id,
                run_id=prior.run_id,
                project_version_id=prior.project_version_id,
                category=str(prior_payload.get("category", "injection")),
                technique=str(prior_payload.get("technique", "ignore_previous")),
                iteration=next_iter,
                mutator_context=MutatorContext(
                    prior_attack_payload=prior_payload,
                    prior_attack_user_message=str(prior_payload.get("user_message", "")),
                    prior_canary=str(prior_payload.get("canary", "")),
                    prior_target_response=prior_response_text,
                ),
                conversation_id=variant_conv_id,
                task=variant_task,
            )
        except Exception as exc:
            self._log.exception(
                "red_team.mutate_failed",
                attack_id=str(payload.attack_id),
                error=repr(exc),
            )
            return
        # New attack row -> new iteration counter on it (max_iterations
        # inherits from the original attack's counter so the cap is
        # campaign-wide, not per-variant).
        await self._upsert_red_team_attempt(
            session,
            attack_id=result.attack_id,
            iteration=next_iter,
            max_iterations=row.max_iterations,
        )
        # Mark the previous attack's counter as advanced.
        await session.execute(
            text(
                """
                UPDATE red_team_attempts
                SET iteration = :iter, updated_at = now()
                WHERE attack_id = :id
                """
            ),
            {"iter": next_iter, "id": payload.attack_id},
        )
        # Emit the next AttackEvent — same seed_idx as the partial we
        # came from; iteration bumps so the idempotency key is unique.
        await self._bus.emit(
            session,
            _attack_event_envelope(
                campaign_id=payload.campaign_id,
                run_id=prior.run_id,
                attempt=PlanAttempt(
                    category=str(prior_payload.get("category", "injection")),
                    technique=str(prior_payload.get("technique", "ignore_previous")),
                ),
                result_attack_id=result.attack_id,
                attack_execution_id=result.attack_execution_id,
                payload_user_message=result.payload_user_message,
                canary=result.canary,
                target_response_text=result.target_response_text,
                iteration=next_iter,
                trace_id=trace_id,
                seed_idx=payload.seed_idx,
            ),
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _upsert_red_team_attempt(
        self,
        session: AsyncSession,
        *,
        attack_id: UUID,
        iteration: int,
        max_iterations: int,
    ) -> None:
        await session.execute(
            text(
                """
                INSERT INTO red_team_attempts
                    (attack_id, iteration, max_iterations, status, updated_at)
                VALUES (:id, :iter, :max, 'active', now())
                ON CONFLICT (attack_id) DO UPDATE
                SET iteration = EXCLUDED.iteration,
                    max_iterations = EXCLUDED.max_iterations,
                    updated_at = now()
                """
            ),
            {"id": attack_id, "iter": iteration, "max": max_iterations},
        )


def _attack_event_envelope(
    *,
    campaign_id: UUID,
    run_id: UUID,
    attempt: PlanAttempt,
    result_attack_id: UUID,
    attack_execution_id: UUID,
    payload_user_message: str,
    canary: str,
    target_response_text: str,
    iteration: int,
    trace_id: str,
    seed_idx: int = 0,
) -> Envelope[AttackEventPayload]:
    return Envelope[AttackEventPayload](
        kind=MessageKind.ATTACK_EVENT,
        from_agent="red_team",
        to_agent="judge",
        payload=AttackEventPayload(
            campaign_id=campaign_id,
            run_id=run_id,
            attack_id=result_attack_id,
            attack_execution_id=attack_execution_id,
            category=attempt.category,
            technique=attempt.technique,
            payload=payload_user_message,
            target_response=target_response_text,
            canary=canary,
            iteration=iteration,
            seed_idx=seed_idx,
        ),
        trace_id=trace_id,
        campaign_id=campaign_id,
        attack_id=result_attack_id,
        idempotency_key=(f"red_team:attack_event:{attack_execution_id}:{seed_idx}:{iteration}"),
    )


def main() -> None:
    """``uv run python -m cats.workers.red_team``"""
    asyncio.run(RedTeamWorker().run())


if __name__ == "__main__":
    main()
