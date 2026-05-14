"""Judge worker process.

Consumes ``AttackEvent`` envelopes from the Red Team. The Judge is
LLM-first: every (attack, response) pair runs through a single Judge
LLM call against the locked rubric. Deterministic checks contribute
*evidence* (canary echo, marker leaks, response shape) into the
prompt — they no longer produce verdicts on their own. Persists a
``JudgeVerdict`` row, links it to the ``AttackExecution`` row, and
emits ``VerdictRendered``:

- pass / fail / error → Documentation's inbox
  (Documentation writes a finding on pass, marks the run completed
  on fail/error.)
- partial → Red Team's inbox (for the variant loop)

Idempotent on ``(attack_id, iteration, rubric_version_id)`` via the
producer-supplied envelope idempotency key.
"""

from __future__ import annotations

import asyncio
from typing import Literal

from sqlalchemy.ext.asyncio import AsyncSession

from cats.agents.judge.verifier import (
    JudgeTranscriptTurn,
    gather_evidence,
    judge_llm,
)
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

# Wall-clock floor above which we tag a cost-amplification signal on
# the Judge's evidence payload. A normal injection round-trips in
# ~5-15s; the OpenEMR supervisor's recursion-limit blow-up burned
# 138s on the trace that motivated this signal. 60s is the cheapest
# "this is materially abnormal" line that won't fire on a slow but
# legitimate request.
_DOS_LATENCY_THRESHOLD_MS = 60_000


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
        # R10 — when the Red Team shipped a multi-turn transcript, run
        # evidence collection over the concatenated transcript so canary
        # / marker scans see every turn, not just the last. The legacy
        # single-turn path (empty transcript) keeps using the latest
        # turn's response verbatim.
        transcript_turns: list[JudgeTranscriptTurn] = []
        if payload.transcript:
            transcript_turns = [
                JudgeTranscriptTurn(
                    seed_idx=t.seed_idx,
                    user_message=t.user_message,
                    target_response=t.target_response,
                )
                for t in payload.transcript
            ]
        total_seeds = max(1, len(transcript_turns)) if transcript_turns else 1

        if transcript_turns:
            full_response = "\n\n".join(t.target_response for t in transcript_turns)
            full_user_message = "\n\n".join(
                f"[Turn {t.seed_idx}]\n{t.user_message}" for t in transcript_turns
            )
        else:
            full_response = payload.target_response
            full_user_message = payload.payload

        evidence = gather_evidence(
            category=payload.category,
            attack_payload={
                "user_message": full_user_message,
                "canary": payload.canary,
                "technique": payload.technique,
            },
            target_response_text=full_response,
        )

        # Short-circuit: the target rejected the call (4xx/5xx) or the
        # transport raised an error on the *final* turn — for multi-turn,
        # we still want to judge the conversation up to the failure if
        # any earlier turn produced content, but a final-turn transport
        # error with an empty transcript is a clear "couldn't evaluate."
        target_rejected = bool(payload.target_error) or (
            payload.target_status_code != 0 and payload.target_status_code >= 400
        )
        # Multi-turn: only short-circuit when EVERY turn failed; if any
        # turn produced content the Judge can rule on the conversation.
        if transcript_turns:
            target_rejected = target_rejected and all(
                bool(t.target_error) or (t.target_status_code != 0 and t.target_status_code >= 400)
                for t in payload.transcript
            )
        if target_rejected:
            verdict: str = "fail"
            rationale = (
                f"target rejected the call before evaluation: "
                f"HTTP {payload.target_status_code or '?'}"
                f"{' — ' + payload.target_error if payload.target_error else ''}"
            )[:1000]
            judge_evidence: dict[str, object] = {
                "target_rejected": True,
                "target_status_code": payload.target_status_code,
                "target_error": payload.target_error,
                "observed": evidence,
                "decisive_seed_idx": None,
                "total_seeds": total_seeds,
            }
            llm_result = None
        else:
            # Single LLM call decides the verdict over the full
            # transcript (or the lone exchange, for single-turn).
            (verdict, rationale, judge_evidence), llm_result = await judge_llm(
                llm=get_llm(),
                category=payload.category,
                attack_user_message=payload.payload,
                target_response_text=payload.target_response,
                evidence=evidence,
                canary=payload.canary,
                transcript=transcript_turns or None,
            )

        # Cost-amplification / DoS signal. Tag as evidence only — the
        # verdict still tracks confidentiality; this is the operator's
        # heads-up that the attack burned wall-clock the target's
        # supervisor loop didn't budget for. Full DoS attack family is
        # a future round (see W3_THREAT_RESEARCH §3.5 Clawdrain,
        # §8.1-8.7 EDoS).
        if payload.target_latency_ms >= _DOS_LATENCY_THRESHOLD_MS:
            judge_evidence["cost_amplification_signal"] = True
            judge_evidence["target_latency_ms"] = payload.target_latency_ms
        rubric_version_id = await ensure_rubric_version(
            session, category=payload.category, version="v1"
        )

        # Read decisive_seed_idx back out of the evidence — the verifier
        # stashes it there (and on the multi-turn-aware short-circuit
        # path above we set it ourselves).
        raw_dsi = judge_evidence.get("decisive_seed_idx")
        decisive_seed_idx: int | None
        if isinstance(raw_dsi, bool) or not isinstance(raw_dsi, int):
            decisive_seed_idx = None
        else:
            decisive_seed_idx = raw_dsi
        # Pass/partial verdicts on multi-turn conversations should name
        # a turn; if the verifier didn't pick one (parse drift, weird
        # output) default to the last turn so the finding still has a
        # pointer. Single-turn (total_seeds==1) defaults to 0 already.
        if verdict in ("pass", "partial") and decisive_seed_idx is None and total_seeds > 1:
            decisive_seed_idx = total_seeds - 1

        verdict_id = await record_verdict(
            session,
            verdict=verdict,
            # The target-rejected short-circuit is deterministic — no
            # LLM was asked. Marking it as deterministic so the eval
            # rollup doesn't count it against judge-LLM accuracy.
            is_deterministic=llm_result is None,
            rationale=rationale,
            evidence=judge_evidence,
            judge_model=llm_result.model if llm_result is not None else "",
            rubric_version_id=rubric_version_id,
            decisive_seed_idx=decisive_seed_idx,
            total_seeds=total_seeds,
        )
        await set_execution_verdict(
            session,
            attack_execution_id=payload.attack_execution_id,
            judge_verdict_id=verdict_id,
        )

        # Emit VerdictRendered.
        # partial → Red Team (variant loop); everything else → Documentation
        # (which writes a finding on pass and closes the run on fail/error).
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
                evidence=judge_evidence,
                rubric_version_id=rubric_version_id,
                is_deterministic=False,
                iteration=payload.iteration,
                seed_idx=payload.seed_idx,
                decisive_seed_idx=decisive_seed_idx,
                total_seeds=total_seeds,
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
                "is_deterministic": False,
                "seed_idx": payload.seed_idx,
                "iteration": payload.iteration,
            },
        )


def main() -> None:
    """``uv run python -m cats.workers.judge``"""
    asyncio.run(JudgeWorker().run())


if __name__ == "__main__":
    main()
