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

from cats.agents.red_team.escalation import ConversationTurn, decide_next_turn
from cats.agents.red_team.executor import (
    AttemptResult,
    MutatorContext,
    execute_attempt,
)
from cats.db.engine import session_scope
from cats.db.repositories.campaign_repo import create_run_in_campaign
from cats.db.repositories.run_repo import mark_run_running, sweep_orphaned_running_runs
from cats.graph.events import publish
from cats.llm.client import get_llm
from cats.messaging import (
    AttackEventPayload,
    CampaignPlanApprovedPayload,
    ClaimedMessage,
    ConversationTurnPayload,
    Envelope,
    MessageKind,
    VerdictRenderedPayload,
    Worker,
)
from cats.messaging.envelopes import PlanAttempt

# R10 — all four categories run multi-turn conversations now. The Red
# Team's escalation strategist (`cats.agents.red_team.escalation`)
# decides between turns whether to push, declare landed, or stop. For
# categories where the OpenEMR agent's follow_up path is finicky
# (historically exfil + indirect rejected as `invalid_envelope`), each
# turn falls back to a fresh `default_briefing` when the agent refuses
# the follow_up — the Red Team-side transcript still escalates, the
# wire-level conversation just doesn't share an agent-side context.
# This trades a smaller in-model context window for the broader
# coverage the user asked for in R10.
_CONVERSATION_SHARING_CATEGORIES: frozenset[str] = frozenset(
    {"injection", "exfil", "tool_abuse", "indirect_injection"}
)


class RedTeamWorker(Worker):
    """The Red Team agent's worker process. Plan-executor."""

    agent_name = "red_team"
    visibility_timeout_seconds = 300  # ARCHITECTURE.md §2.7

    async def run(self) -> None:
        # `_handle_plan_approved` walks the plan inside a single
        # message-handler invocation and isn't checkpointed, so a
        # container restart mid-walk leaves any runs it had already
        # marked `running` orphaned at that status forever. Sweep them
        # before entering the main loop. Safe because this worker is
        # the only writer of `runs.status='running'` and only one
        # replica is deployed.
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
        """Walk the plan. R10 — each PlanAttempt is one *conversation*,
        not K independent seeds. The Red Team's escalation strategist
        decides between turns whether to push (escalate), declare the
        vulnerability landed, or stop. ``seeds_per_attempt`` is the
        upper bound on conversation length; the Red Team can end
        earlier. After the conversation finishes, the worker emits ONE
        ``AttackEvent`` carrying the full transcript — the Judge rules
        over the whole conversation and names the decisive turn.

        One ``runs`` row per conversation; one ``attack_executions``
        row per turn (with ascending ``seed_idx``)."""
        plan = payload.plan
        consecutive_fails = 0
        for idx, attempt in enumerate(plan.attempts):
            try:
                conversation_ok = await self._run_conversation(
                    session,
                    payload=payload,
                    attempt=attempt,
                    trace_id=trace_id,
                )
            except Exception as exc:
                self._log.exception(
                    "red_team.conversation_failed",
                    error=repr(exc),
                    campaign_id=str(payload.campaign_id),
                    attempt_idx=idx,
                )
                conversation_ok = False

            if not conversation_ok:
                consecutive_fails += 1
                if consecutive_fails >= plan.halt_on_consecutive_fails:
                    self._log.info(
                        "red_team.halted",
                        reason="consecutive_fails",
                        campaign_id=str(payload.campaign_id),
                    )
                    return
            else:
                consecutive_fails = 0
        # Note: this handler returns after EMITTING one AttackEvent per
        # conversation. The Judge worker processes them asynchronously;
        # partial verdicts come back on the Red Team's inbox as
        # separate VerdictRendered messages handled by
        # `_handle_partial_verdict`.

    async def _run_conversation(
        self,
        session: AsyncSession,
        *,
        payload: CampaignPlanApprovedPayload,
        attempt: PlanAttempt,
        trace_id: str,
    ) -> bool:
        """One full multi-turn conversation for one PlanAttempt. Returns
        True on success (the AttackEvent was emitted), False on
        unrecoverable failure (transport error before any turn landed).

        The Red Team controls conversation length via the escalation
        strategist; ``attempt.seeds_per_attempt`` is the hard upper
        bound. All four categories now run multi-turn — see
        ``_CONVERSATION_SHARING_CATEGORIES`` for the wire-level
        sharing rule."""
        # One run per conversation. Every turn fires into the same
        # `runs` row so the run-detail UI shows the whole arc as a
        # single per-execution table.
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
                "category": attempt.category,
                "technique": attempt.technique,
                "multi_turn": True,
            },
        )

        shares_conversation = attempt.category in _CONVERSATION_SHARING_CATEGORIES
        # Until seed 0's response comes back the agent hasn't minted
        # the conversationId; ``conv_id`` is None and seed 0 fires as
        # ``default_briefing``. Subsequent seeds, if shares_conversation,
        # ride that id as ``follow_up``.
        conv_id: str | None = None
        prior_user_messages: list[str] = []
        prior_target_responses: list[str] = []
        transcript_turns: list[ConversationTurn] = []
        emitted_turns: list[ConversationTurnPayload] = []
        last_result: AttemptResult | None = None
        stop_reason = "cap_reached"

        for seed_idx in range(attempt.seeds_per_attempt):
            seed_task = "follow_up" if (shares_conversation and conv_id) else "default_briefing"
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
                    prior_target_responses=list(prior_target_responses),
                    conversation_id=conv_id if shares_conversation else None,
                    task=seed_task,
                )
            except Exception as exc:
                # First-turn failure → kill the conversation; later-turn
                # failure → stop where we are and ship what we have so
                # the Judge at least sees something.
                self._log.warning(
                    "red_team.turn_failed",
                    error=repr(exc),
                    campaign_id=str(payload.campaign_id),
                    seed_idx=seed_idx,
                )
                stop_reason = "error"
                if seed_idx == 0:
                    return False
                break

            # Persist the partial-loop counter on the first turn only —
            # the Mutator's variant loop fires another full conversation
            # rather than another turn within this one.
            if seed_idx == 0:
                await self._upsert_red_team_attempt(
                    session,
                    attack_id=result.attack_id,
                    iteration=0,
                    max_iterations=attempt.max_consecutive_partials,
                )
            last_result = result
            prior_user_messages.append(result.payload_user_message)
            prior_target_responses.append(result.target_response_text)
            transcript_turns.append(
                ConversationTurn(
                    seed_idx=seed_idx,
                    user_message=result.payload_user_message,
                    target_response=result.target_response_text,
                )
            )
            emitted_turns.append(
                ConversationTurnPayload(
                    seed_idx=seed_idx,
                    user_message=result.payload_user_message,
                    target_response=result.target_response_text,
                    attack_execution_id=result.attack_execution_id,
                    target_status_code=result.target_status_code,
                    target_error=result.target_error,
                    target_latency_ms=result.target_latency_ms,
                )
            )
            if conv_id is None and result.assigned_conversation_id:
                conv_id = result.assigned_conversation_id

            await publish(
                kind="attack_executed",
                campaign_id=payload.campaign_id,
                run_id=run_id,
                payload={
                    "category": attempt.category,
                    "technique": attempt.technique,
                    "seed_idx": seed_idx,
                    "attack_id": str(result.attack_id),
                    "status_code": result.target_status_code,
                    "latency_ms": result.target_latency_ms,
                    "filter_verdict": result.output_filter_verdict,
                    "multi_turn": True,
                },
            )

            # Escalation decision. The strategist sees the transcript so
            # far and chooses escalate / stop / declare_landed. A forced
            # stop fires when the conversation cap is reached, which is
            # the natural end-of-loop case (the loop would exit anyway,
            # but we record `stop_reason=cap_reached` explicitly).
            decision = await decide_next_turn(
                category=attempt.category,
                technique=attempt.technique,
                transcript=list(transcript_turns),
                llm=get_llm(),
                seeds_per_attempt=attempt.seeds_per_attempt,
            )
            if decision.decision == "escalate":
                continue
            stop_reason = decision.decision
            break

        if last_result is None:
            return False

        # Emit ONE AttackEvent for the whole conversation. The Judge
        # rules over the full transcript and returns a decisive turn.
        # The legacy single-turn fields mirror the LAST turn so older
        # consumers (legacy graph path, the Judge's evidence layer)
        # keep working without a transcript-aware code change.
        await self._bus.emit(
            session,
            _attack_event_envelope(
                campaign_id=payload.campaign_id,
                run_id=run_id,
                attempt=attempt,
                result_attack_id=last_result.attack_id,
                attack_execution_id=last_result.attack_execution_id,
                payload_user_message=last_result.payload_user_message,
                canary=last_result.canary,
                target_response_text=last_result.target_response_text,
                target_status_code=last_result.target_status_code,
                target_error=last_result.target_error,
                target_latency_ms=last_result.target_latency_ms,
                iteration=0,
                seed_idx=len(emitted_turns) - 1,
                trace_id=trace_id,
                transcript=emitted_turns,
                conversation_stop_reason=stop_reason,
            ),
        )
        return True

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
        prior_assigned_conv_id: str | None = None
        if isinstance(prior.target_response, dict):
            prior_response_text = str(prior.target_response.get("text", ""))
            raw_assigned = prior.target_response.get("assigned_conversation_id")
            if isinstance(raw_assigned, str) and raw_assigned:
                prior_assigned_conv_id = raw_assigned
        next_iter = row.iteration + 1
        # Variant continues in the same OpenEMR conversation as the
        # seed it came from — that's the whole point of "iterate on a
        # partial success". The agent-assigned id (parsed from the
        # kickoff's meta SSE frame and stored on the execution row's
        # target_response) is authoritative; the payload's
        # ``conversation_id`` is only the client-side placeholder the
        # agent discarded. Older rows without the assigned id fall back
        # to a fresh default_briefing so we don't hang on a phantom id.
        variant_conv_id: str | None = prior_assigned_conv_id
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
        # Live UI: the variant attack just fired.
        await publish(
            kind="attack_executed",
            campaign_id=payload.campaign_id,
            run_id=prior.run_id,
            payload={
                "category": str(prior_payload.get("category", "injection")),
                "technique": str(prior_payload.get("technique", "ignore_previous")),
                "seed_idx": payload.seed_idx,
                "iteration": next_iter,
                "attack_id": str(result.attack_id),
                "status_code": result.target_status_code,
                "latency_ms": result.target_latency_ms,
                "filter_verdict": result.output_filter_verdict,
            },
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
                target_status_code=result.target_status_code,
                target_error=result.target_error,
                target_latency_ms=result.target_latency_ms,
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
    target_status_code: int,
    target_error: str | None,
    target_latency_ms: int,
    iteration: int,
    trace_id: str,
    seed_idx: int = 0,
    transcript: list[ConversationTurnPayload] | None = None,
    conversation_stop_reason: str = "",
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
            target_status_code=target_status_code,
            target_error=target_error,
            target_latency_ms=target_latency_ms,
            canary=canary,
            iteration=iteration,
            seed_idx=seed_idx,
            transcript=transcript or [],
            conversation_stop_reason=conversation_stop_reason,
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
