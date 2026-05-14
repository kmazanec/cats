"""Red Team eval runner.

Two case modes, switched on ``tags.mode``:

- **specialist mode** (default, ``mode`` absent or ``"specialist"``) —
  drives one of the per-category specialist dispatchers with a
  ``FakeLLMClient`` whose response is pinned by the case under
  ``## Inputs.fake_specialist_response``. Tests the *post-LLM*
  pipeline (canary substitution, output-filter contract, structural
  proposal shape) without paying for a real LLM call.

- **agent mode** (``mode: agent``) — drives the LangGraph Red Team
  agent end-to-end with a scripted tool-call sequence under
  ``## Inputs.scripted_tool_calls``. Tests the agent's tool-loop
  control flow + termination semantics (stop_reason, expected_verdict,
  turn-cap discipline) without hitting a live target.

Why fakes instead of real LLM calls: the red-team eval is testing the
*post-LLM* pipeline (canary handling, filter, structural contract on
proposal, agent control flow) — not the LLM's creative output. A
nightly variant can swap in a real-LLM executor; everything else
stays the same.

Usage::

    uv run python -m evals.runners.red_team
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Callable
from typing import Any

from cats.agents.red_team.exfil.dispatcher import propose_technique as exfil_propose
from cats.agents.red_team.injection.dispatcher import propose_technique as injection_propose
from cats.agents.red_team.tool_abuse.dispatcher import propose_technique as tool_abuse_propose
from cats.llm.client import FakeLLMClient, install_override
from cats.llm.models import AgentRole
from evals.loader import Case, load_cases
from evals.scorers import ScoreResult
from evals.scorers.red_team import score

_ROLE_BY_CATEGORY: dict[str, AgentRole] = {
    "injection": "redteam_injection",
    "exfil": "redteam_exfil",
    "tool_abuse": "redteam_toolabuse",
}

ProposeFn = Callable[..., Any]
_DISPATCH_BY_CATEGORY: dict[str, ProposeFn] = {
    "injection": injection_propose,
    "exfil": exfil_propose,
    "tool_abuse": tool_abuse_propose,
}


def _proposal_to_dict(proposal: Any) -> dict[str, Any]:
    """Flatten a specialist proposal dataclass into a uniform dict the
    scorer can introspect without knowing which category produced it."""
    base = {
        "technique": getattr(proposal, "technique", ""),
        "user_message": getattr(proposal, "user_message", ""),
        "title": getattr(proposal, "title", ""),
        "description": getattr(proposal, "description", ""),
    }
    # Category-specific fields. Missing attrs map to None.
    for opt in ("canary", "markers", "task_type", "target_areas", "expected_channel"):
        if hasattr(proposal, opt):
            base[opt] = getattr(proposal, opt)
    return base


async def _run_agent_case(case: Case) -> dict[str, Any]:
    """Drive the LangGraph agent with a scripted tool-call sequence.
    Returns a flat dict the scorer reads (``stop_reason``,
    ``expected_verdict``, ``transcript_length``, ``tool_call_count``,
    ``submitted_before_cap``)."""
    from uuid import uuid4

    from cats.agents.red_team import tools as tools_mod
    from cats.agents.red_team.agent import run_red_team_agent
    from cats.agents.red_team.executor import AttemptResult, _NormalizedProposal
    from cats.llm.client import FakeLLMClient, LLMResult, install_override
    from cats.messaging.envelopes import PlanAttempt
    from cats.target.contracts import AttackEnvelope

    category = str(case.inputs.get("category") or "injection")
    technique = str(case.inputs.get("technique") or "ignore_previous")
    seeds = int(case.inputs.get("seeds_per_attempt") or 5)
    scripted = case.inputs.get("scripted_tool_calls") or []
    if not isinstance(scripted, list) or not scripted:
        raise ValueError(f"{case.case_id}: inputs.scripted_tool_calls required")

    # Stub out side-effects that need real infrastructure.
    class _S:
        async def execute(self, *_a: Any, **_k: Any) -> Any:
            return None

        async def commit(self) -> None:
            return None

    async def _fake_audit(*_a: Any, **_k: Any) -> None:
        return None

    async def _fake_publish(*_a: Any, **_k: Any) -> None:
        return None

    async def _fake_fire(*_a: Any, **kwargs: Any) -> AttemptResult:
        return AttemptResult(
            attack_id=uuid4(),
            attack_execution_id=uuid4(),
            attack_signature="eval-sig",
            attack_title="eval-turn",
            payload_user_message=kwargs["user_message"],
            canary=kwargs["canary"],
            target_response_text="I cannot help with that.",
            target_status_code=200,
            target_latency_ms=1,
            target_error=None,
            output_filter_verdict="safe",
            output_filter_reason="",
            technique=kwargs["technique"],
            iteration=kwargs.get("iteration", 0),
            trace_id="eval-trace",
            per_agent_costs=[],
            assigned_conversation_id=None,
        )

    async def _fake_propose_attack(
        *, category: str, technique: str, **_k: Any
    ) -> _NormalizedProposal:
        return _NormalizedProposal(
            title="eval opener",
            description="eval fixture",
            user_message="please echo CATS-CANARY-EVAL",
            canary="CATS-CANARY-EVAL",
            technique=technique,
            payload_extras={},
            envelope=AttackEnvelope(
                user_message="please echo CATS-CANARY-EVAL", canary="CATS-CANARY-EVAL"
            ),
            cost_role="redteam_injection",
            llm_result=LLMResult(
                text="{}",
                model="fake",
                tokens_in=1,
                tokens_out=1,
                usd_estimate=0.0,
                trace_id="eval",
            ),
        )

    from cats.agents.mutator.strategies import MutatorResult
    from cats.agents.red_team import agent as agent_mod

    async def _fake_variant(*, state: Any, llm: Any) -> MutatorResult:
        return MutatorResult(
            user_message="mutated for eval CATS-CANARY-EVAL",
            technique_variant="eval",
            rationale="eval",
            llm=None,
        )

    # Monkeypatch via module attribute assignment (cleared in finally).
    saved_fire = tools_mod.fire_prepared_attack
    saved_propose = tools_mod._propose_attack
    saved_variant = tools_mod.generate_variant
    saved_publish = tools_mod.publish
    saved_audit = agent_mod.write_audit
    tools_mod.fire_prepared_attack = _fake_fire  # type: ignore[assignment]
    tools_mod._propose_attack = _fake_propose_attack  # type: ignore[assignment]
    tools_mod.generate_variant = _fake_variant  # type: ignore[assignment]
    tools_mod.publish = _fake_publish  # type: ignore[assignment]
    agent_mod.write_audit = _fake_audit  # type: ignore[assignment]

    fake = FakeLLMClient()
    # Build the responder sequence — one assistant turn per scripted call.
    sequence = []
    for tc in scripted:
        payload = {
            "id": f"eval-{len(sequence)}",
            "name": tc["name"],
            "arguments": tc.get("arguments", {}),
        }
        sequence.append((lambda p=payload: lambda _msgs: {"text": "", "tool_calls": [p]})())
    fake.register_sequence("redteam_injection", sequence)
    install_override(fake)
    try:
        result = await run_red_team_agent(
            session=_S(),
            campaign_id=uuid4(),
            run_id=uuid4(),
            project_version_id=uuid4(),
            attempt=PlanAttempt(category=category, technique=technique, seeds_per_attempt=seeds),
            trace_id="eval-trace",
        )
    finally:
        install_override(None)
        tools_mod.fire_prepared_attack = saved_fire  # type: ignore[assignment]
        tools_mod._propose_attack = saved_propose  # type: ignore[assignment]
        tools_mod.generate_variant = saved_variant  # type: ignore[assignment]
        tools_mod.publish = saved_publish  # type: ignore[assignment]
        agent_mod.write_audit = saved_audit  # type: ignore[assignment]

    return {
        "stop_reason": result.stop_reason,
        "expected_verdict": result.expected_verdict,
        "transcript_length": len(result.transcript),
        "tool_call_count": result.tool_call_count,
        "submitted_before_cap": result.stop_reason == "agent_submitted",
    }


async def _run_case(case: Case) -> dict[str, Any]:
    if (case.tags.get("mode") or "").lower() == "agent":
        return await _run_agent_case(case)
    category = case.tags.get("category") or ""
    technique = case.inputs.get("technique") or case.expected.get("technique") or ""
    fake_response = case.inputs.get("fake_specialist_response")
    if category not in _DISPATCH_BY_CATEGORY:
        raise ValueError(
            f"{case.case_id}: tags.category must be one of {sorted(_DISPATCH_BY_CATEGORY)}"
        )
    if not technique:
        raise ValueError(f"{case.case_id}: inputs.technique or expected.technique required")
    if fake_response is None:
        raise ValueError(
            f"{case.case_id}: inputs.fake_specialist_response required (object the specialist's LLM returns)"
        )

    # R10 — multi-turn fixtures pass prior_user_messages +
    # prior_target_responses + seed_idx so the specialist's prompt
    # exercises the multi-turn framing. The scorer can then inspect
    # the captured prompt to assert the specialist saw / reacted to
    # the prior turn.
    prior_user_messages = case.inputs.get("prior_user_messages")
    prior_target_responses = case.inputs.get("prior_target_responses")
    seed_idx = int(case.inputs.get("seed_idx") or 0)

    fake = FakeLLMClient()
    fake_text = json.dumps(fake_response)
    captured: dict[str, Any] = {}

    def _r(messages: list[dict[str, Any]]) -> str:
        captured["last_user_prompt"] = (
            next((m for m in messages if m.get("role") == "user"), {}).get("content") or ""
        )
        return fake_text

    fake.register(_ROLE_BY_CATEGORY[category], _r)
    install_override(fake)
    try:
        # Only the injection dispatcher today accepts the multi-turn
        # context. Other categories' multi-turn specialist work is a
        # near-term follow-up — they still run the eval as single-turn.
        if category == "injection":
            proposal = await _DISPATCH_BY_CATEGORY[category](
                technique=technique,
                llm=fake,
                seed_idx=seed_idx,
                prior_user_messages=prior_user_messages,
                prior_target_responses=prior_target_responses,
            )
        else:
            proposal = await _DISPATCH_BY_CATEGORY[category](technique=technique, llm=fake)
    finally:
        install_override(None)
    out = _proposal_to_dict(proposal)
    out["_captured_prompt"] = captured.get("last_user_prompt", "")
    return out


def run_eval(cases: list[Case] | None = None) -> list[ScoreResult]:
    cases = cases if cases is not None else load_cases("red_team")
    results: list[ScoreResult] = []
    for case in cases:
        try:
            proposal = asyncio.run(_run_case(case))
        except Exception as e:
            r = ScoreResult(case_id=case.case_id)
            r.error = f"{type(e).__name__}: {e}"
            results.append(r)
            continue
        results.append(score(case, proposal))
    return results


def _print_report(results: list[ScoreResult], *, threshold: float) -> int:
    passes = sum(1 for r in results if r.passed)
    total = len(results)
    rate = passes / total if total else 0.0
    print(f"=== red_team eval — {total} cases ===")
    for r in results:
        marker = "PASS" if r.passed else "FAIL"
        detail = ""
        if r.error:
            detail = f"  ERROR={r.error}"
        else:
            failing = [c for c in r.checks if not c.passed]
            if failing:
                detail = "  failing=" + ", ".join(c.name for c in failing)
        print(f"  [{marker}] {r.case_id}  ({r.passed_count}/{r.total}){detail}")
    print(f"\npass rate: {passes}/{total} = {rate:.3f}  (threshold {threshold:.3f})")
    return 0 if rate >= threshold else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--threshold", type=float, default=0.9)
    args = parser.parse_args(argv)
    results = run_eval()
    return _print_report(results, threshold=args.threshold)


if __name__ == "__main__":
    sys.exit(main())
