"""Red Team eval runner.

For each ``evals/cases/red_team/*.md`` case:

1. Build a ``CampaignState`` (or just pass technique directly).
2. Drive the specialist's ``propose_technique(technique=..., llm=fake)``
   with a ``FakeLLMClient`` that returns the JSON the case describes
   under ``## Inputs.fake_specialist_response``.
3. Normalize the resulting proposal to a plain dict.
4. Run the case's ``## Expected`` assertions through the scorer.

Why ``fake_specialist_response`` instead of letting the real LLM
produce one: the red-team eval is testing the *post-LLM* pipeline —
canary appending, output filter classification, structural
contract on the proposal — not the LLM's creative output. A
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


async def _run_case(case: Case) -> dict[str, Any]:
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
