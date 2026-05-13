"""Judge worker process.

Consumes ``AttackEvent`` envelopes from the Red Team. Runs the
deterministic post-condition first (cheap, mechanical); falls back to
the locked-version rubric LLM call when the deterministic check is
inconclusive. Persists a ``JudgeVerdict`` row, links it to the
``AttackExecution`` row, and emits ``VerdictRendered``:

- pass / fail → Documentation's inbox
- partial → Red Team's inbox (for the variant loop)

Idempotent on ``(attack_id, iteration, rubric_version_id)`` via the
producer-supplied envelope idempotency key.
"""

from __future__ import annotations

import asyncio
from typing import Literal
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from cats.agents.judge.verifier import judge_deterministic, judge_llm
from cats.db.repositories.rubric_repo import ensure_rubric_version
from cats.db.repositories.run_repo import record_verdict, set_execution_verdict
from cats.graph.events import publish
from cats.llm.client import get_llm
from cats.messaging import (
    AttackEventPayload,
    ClaimedMessage,
    Envelope,
    MessageKind,
    VerdictRenderedPayload,
    Worker,
)


class JudgeWorker(Worker):
    """The Judge agent's worker process."""

    agent_name = "judge"
    visibility_timeout_seconds = 60  # ARCHITECTURE.md §2.7

    async def handle(self, session: AsyncSession, message: ClaimedMessage) -> None:
        if message.kind is not MessageKind.ATTACK_EVENT:
            self._log.error(
                "judge.unexpected_kind",
                kind=message.kind.value,
                message_id=str(message.message_id),
            )
            return
        payload = AttackEventPayload.model_validate(message.payload_json)
        await self._render_verdict(session, payload, trace_id=message.trace_id)

    async def _render_verdict(
        self,
        session: AsyncSession,
        payload: AttackEventPayload,
        *,
        trace_id: str,
    ) -> None:
        # Deterministic short-circuit first.
        verdict, rationale, evidence = judge_deterministic(
            category=payload.category,
            attack_payload={
                "user_message": payload.payload,
                "canary": payload.canary,
                "technique": payload.technique,
            },
            target_response_text=payload.target_response,
        )
        is_deterministic = True
        judge_model = "deterministic"
        rubric_version_id: UUID | None = None

        if verdict == "inconclusive":
            (verdict, rationale, evidence), llm_result = await judge_llm(
                llm=get_llm(),
                category=payload.category,
                attack_user_message=payload.payload,
                target_response_text=payload.target_response,
                canary=payload.canary,
            )
            is_deterministic = False
            judge_model = llm_result.model
            rubric_version_id = await ensure_rubric_version(
                session, category=payload.category, version="v1"
            )

        verdict_id = await record_verdict(
            session,
            verdict=verdict,
            is_deterministic=is_deterministic,
            rationale=rationale,
            evidence=evidence,
            judge_model=judge_model,
            rubric_version_id=rubric_version_id,
        )
        await set_execution_verdict(
            session,
            attack_execution_id=payload.attack_execution_id,
            judge_verdict_id=verdict_id,
        )

        # Emit VerdictRendered.
        # Pass/fail → Documentation; partial → Red Team for variant loop.
        to_agent: Literal["documentation", "red_team"] = (
            "red_team" if verdict == "partial" else "documentation"
        )
        envelope = Envelope[VerdictRenderedPayload](
            kind=MessageKind.VERDICT_RENDERED,
            from_agent="judge",
            to_agent=to_agent,
            payload=VerdictRenderedPayload(
                campaign_id=payload.campaign_id,
                run_id=payload.run_id,
                attack_id=payload.attack_id,
                attack_execution_id=payload.attack_execution_id,
                judge_verdict_id=verdict_id,
                verdict=verdict,
                rationale=rationale,
                evidence=evidence,
                rubric_version_id=rubric_version_id,
                is_deterministic=is_deterministic,
                iteration=payload.iteration,
                seed_idx=payload.seed_idx,
            ),
            trace_id=trace_id,
            campaign_id=payload.campaign_id,
            attack_id=payload.attack_id,
            idempotency_key=(
                f"judge:verdict:{payload.attack_execution_id}:"
                f"{payload.seed_idx}:{payload.iteration}"
            ),
        )
        await self._bus.emit(session, envelope)
        # Live UI: verdict landed on a run.
        await publish(
            kind="judge_verdict_rendered",
            campaign_id=payload.campaign_id,
            run_id=payload.run_id,
            payload={
                "verdict": verdict,
                "is_deterministic": is_deterministic,
                "seed_idx": payload.seed_idx,
                "iteration": payload.iteration,
            },
        )


def main() -> None:
    """``uv run python -m cats.workers.judge``"""
    asyncio.run(JudgeWorker().run())


if __name__ == "__main__":
    main()
