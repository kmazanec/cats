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
  control flow + termination semantics (stop_reason, self_assessment,
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


def _install_agent_fakes(monkeypatch_targets: dict[str, Any]) -> dict[str, Any]:
    """Stash the originals of every module attribute the agent path
    touches with infrastructure, then replace them with no-op fakes.
    Returns the originals dict the caller restores from in a finally
    block. Keeps the per-case setup terse."""
    from uuid import uuid4

    from cats.agents.mutator.strategies import MutatorResult
    from cats.agents.red_team import agent as agent_mod
    from cats.agents.red_team import tools as tools_mod
    from cats.agents.red_team.executor import AttemptResult, _NormalizedProposal
    from cats.llm.client import LLMResult
    from cats.target.contracts import AttackEnvelope

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

    async def _fake_variant(*, state: Any, llm: Any) -> MutatorResult:
        return MutatorResult(
            user_message="mutated for eval CATS-CANARY-EVAL",
            technique_variant="eval",
            rationale="eval",
            llm=None,
        )

    originals = {
        "fire": tools_mod.fire_prepared_attack,
        "propose": tools_mod._propose_attack,
        "variant": tools_mod.generate_variant,
        "publish": tools_mod.publish,
        "audit": agent_mod.write_audit,
    }
    monkeypatch_targets["tools"] = tools_mod
    monkeypatch_targets["agent"] = agent_mod
    tools_mod.fire_prepared_attack = _fake_fire  # type: ignore[assignment]
    tools_mod._propose_attack = _fake_propose_attack  # type: ignore[assignment]
    tools_mod.generate_variant = _fake_variant  # type: ignore[assignment]
    tools_mod.publish = _fake_publish  # type: ignore[assignment]
    agent_mod.write_audit = _fake_audit  # type: ignore[assignment]
    return originals


def _restore_agent_fakes(originals: dict[str, Any], modules: dict[str, Any]) -> None:
    tools_mod = modules["tools"]
    agent_mod = modules["agent"]
    tools_mod.fire_prepared_attack = originals["fire"]  # type: ignore[assignment]
    tools_mod._propose_attack = originals["propose"]  # type: ignore[assignment]
    tools_mod.generate_variant = originals["variant"]  # type: ignore[assignment]
    tools_mod.publish = originals["publish"]  # type: ignore[assignment]
    agent_mod.write_audit = originals["audit"]  # type: ignore[assignment]


def _fake_session() -> Any:
    class _S:
        async def execute(self, *_a: Any, **_k: Any) -> Any:
            return None

        async def commit(self) -> None:
            return None

    return _S()


def _build_attacker_sequence(scripted: list[dict[str, Any]]) -> list[Any]:
    sequence: list[Any] = []
    for tc in scripted:
        payload = {
            "id": f"eval-{len(sequence)}",
            "name": tc["name"],
            "arguments": tc.get("arguments", {}),
        }
        sequence.append((lambda p=payload: lambda _msgs: {"text": "", "tool_calls": [p]})())
    return sequence


async def _run_agent_case(case: Case) -> dict[str, Any]:
    """Drive the LangGraph agent with a scripted tool-call sequence.
    Returns a flat dict the scorer reads (``stop_reason``,
    ``self_assessment``, ``transcript_length``, ``tool_call_count``,
    ``submitted_before_cap``)."""
    from uuid import uuid4

    from cats.agents.red_team import agent as agent_mod
    from cats.agents.red_team.agent import run_red_team_agent
    from cats.llm.client import FakeLLMClient, install_override
    from cats.messaging.envelopes import PlanAttempt

    category = str(case.inputs.get("category") or "injection")
    technique = str(case.inputs.get("technique") or "ignore_previous")
    budget_usd_cap = float(case.inputs.get("budget_usd_cap") or 0.50)
    # Cases that exercise the soft turn cap can lower it via this override.
    max_turns_soft_override = case.inputs.get("max_turns_soft_override")
    scripted = case.inputs.get("scripted_tool_calls") or []
    if not isinstance(scripted, list) or not scripted:
        raise ValueError(f"{case.case_id}: inputs.scripted_tool_calls required")

    modules: dict[str, Any] = {}
    originals = _install_agent_fakes(modules)
    saved_max_turns_soft: int | None = None
    if max_turns_soft_override is not None:
        saved_max_turns_soft = agent_mod.MAX_TURNS_SOFT
        agent_mod.MAX_TURNS_SOFT = int(max_turns_soft_override)
    fake = FakeLLMClient()
    fake.register_sequence("redteam_injection", _build_attacker_sequence(scripted))
    install_override(fake)
    try:
        result = await run_red_team_agent(
            session=_fake_session(),
            campaign_id=uuid4(),
            run_id=uuid4(),
            project_version_id=uuid4(),
            attempt=PlanAttempt(
                category=category,
                technique=technique,
                per_attempt_budget_usd=budget_usd_cap,
            ),
            trace_id="eval-trace",
        )
    finally:
        install_override(None)
        _restore_agent_fakes(originals, modules)
        if saved_max_turns_soft is not None:
            agent_mod.MAX_TURNS_SOFT = saved_max_turns_soft

    return {
        "stop_reason": result.stop_reason,
        "self_assessment": result.self_assessment,
        "transcript_length": len(result.transcript),
        "tool_call_count": result.tool_call_count,
        "submitted_before_cap": result.stop_reason == "agent_submitted",
    }


async def _run_multi_attempt_case(case: Case) -> dict[str, Any]:
    """R10-follow-up — drive multiple PlanAttempts through one shared
    agent session (mirrors the worker's "one run, N attempts" shape).
    Each attempt has its own scripted_tool_calls; the runner walks them
    sequentially under one synthetic run_id. Returns aggregate stats
    the scorer reads (``attempt_count``, per-attempt ``stop_reasons``
    and ``self_assessments``, ``total_transcript_length``)."""
    from uuid import uuid4

    from cats.agents.red_team.agent import run_red_team_agent
    from cats.llm.client import FakeLLMClient, install_override
    from cats.messaging.envelopes import PlanAttempt

    attempts = case.inputs.get("attempts") or []
    if not isinstance(attempts, list) or not attempts:
        raise ValueError(f"{case.case_id}: inputs.attempts (list) required")

    modules: dict[str, Any] = {}
    originals = _install_agent_fakes(modules)

    # All attempts share one campaign_id, project_version_id, and run_id
    # to mirror the worker's actual shape under the R10-follow-up
    # refactor. Each attempt re-registers a fresh FakeLLMClient sequence
    # because the LangGraph compile is cached and re-uses the override
    # set at attacker-call time.
    campaign_id = uuid4()
    project_version_id = uuid4()
    run_id = uuid4()
    session = _fake_session()

    per_attempt_stops: list[str] = []
    per_attempt_verdicts: list[str] = []
    per_attempt_lengths: list[int] = []
    all_submitted = True
    try:
        for idx, attempt_dict in enumerate(attempts):
            scripted = attempt_dict.get("scripted_tool_calls") or []
            if not isinstance(scripted, list) or not scripted:
                raise ValueError(f"{case.case_id}: attempts[{idx}].scripted_tool_calls required")
            fake = FakeLLMClient()
            # Register the same scripted sequence under every Red Team
            # role — the agent picks its attacker role based on the
            # PlanAttempt's category (``redteam_injection`` /
            # ``redteam_exfil`` / etc.), so a single per-role registration
            # would miss cross-category multi-attempt sessions.
            attacker_seq = _build_attacker_sequence(scripted)
            for role in (
                "redteam_injection",
                "redteam_exfil",
                "redteam_toolabuse",
                "redteam_indirect_injection",
            ):
                fake.register_sequence(role, list(attacker_seq))
            install_override(fake)
            result = await run_red_team_agent(
                session=session,
                campaign_id=campaign_id,
                run_id=run_id,
                project_version_id=project_version_id,
                attempt=PlanAttempt(
                    category=str(attempt_dict.get("category") or "injection"),
                    technique=str(attempt_dict.get("technique") or "ignore_previous"),
                    seeds_per_attempt=int(attempt_dict.get("seeds_per_attempt") or 4),
                ),
                trace_id=f"eval-trace-{idx}",
            )
            install_override(None)
            per_attempt_stops.append(result.stop_reason)
            per_attempt_verdicts.append(result.self_assessment)
            per_attempt_lengths.append(len(result.transcript))
            if result.stop_reason != "agent_submitted":
                all_submitted = False
    finally:
        install_override(None)
        _restore_agent_fakes(originals, modules)

    return {
        "attempt_count": len(per_attempt_stops),
        "per_attempt_stop_reasons": per_attempt_stops,
        "per_attempt_self_assessments": per_attempt_verdicts,
        "per_attempt_transcript_lengths": per_attempt_lengths,
        "total_transcript_length": sum(per_attempt_lengths),
        "all_attempts_submitted": all_submitted,
    }


async def _run_case(case: Case) -> dict[str, Any]:
    mode = (case.tags.get("mode") or "").lower()
    if mode == "agent":
        return await _run_agent_case(case)
    if mode == "agent_multi_attempt":
        return await _run_multi_attempt_case(case)
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
