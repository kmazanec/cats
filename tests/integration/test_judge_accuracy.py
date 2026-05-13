"""R3 — fast judge-accuracy subset.

Runs the answer-key cases that the deterministic judge can resolve
without any LLM (pass + fail; partials are LLM-only and exercised by
the full nightly ``evals.runner``). Fails the build if the deterministic
accuracy drops below 100% — every pass/fail case in the locked answer
key should resolve cleanly without the LLM, which is the whole point of
the deterministic short-circuit.

This keeps CI offline + fast (~3s) while still gating drift in the
canonical pass/fail cases.
"""

from __future__ import annotations

import pytest
from evals.runner import _judge_one, _load_cases

# This file talks to no external services. It's marked `integration`
# only because it imports langgraph via cats.agents.judge.
pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_deterministic_judge_matches_answer_key_for_pass_fail_cases() -> None:
    """Every pass/fail case in v1 must resolve correctly via the
    deterministic short-circuit. Partial cases are skipped here — those
    are the LLM judge's job and run in the full nightly eval."""
    cases = _load_cases("injection", "v1")
    pass_fail_cases = [c for c in cases if c.expected_verdict in ("pass", "fail")]

    assert len(pass_fail_cases) >= 20, (
        f"answer key v1 should have ≥20 deterministic cases (pass/fail); got {len(pass_fail_cases)}"
    )

    failures = []
    for case in pass_fail_cases:
        result = await _judge_one(
            case,
            category="injection",
            deterministic_only=True,
        )
        if result.actual_verdict != case.expected_verdict:
            failures.append((case.id, case.expected_verdict, result.actual_verdict))

    assert not failures, (
        f"deterministic judge disagreed with answer key on "
        f"{len(failures)}/{len(pass_fail_cases)} pass/fail cases: {failures}"
    )


@pytest.mark.asyncio
async def test_partial_cases_remain_inconclusive_under_deterministic_only() -> None:
    """The deterministic check has no concept of `partial` — it should
    rule `fail` (canary planted, not echoed). When --deterministic-only
    is set, those cases get an `inconclusive`-style outcome and the
    LLM judge handles them in the full nightly run.

    This is a smoke test for the answer-key labeling: every `partial`
    case should at least make it through the runner without erroring."""
    cases = _load_cases("injection", "v1")
    partials = [c for c in cases if c.expected_verdict == "partial"]
    assert len(partials) >= 1, "answer key v1 should include partial cases"

    for case in partials:
        result = await _judge_one(
            case,
            category="injection",
            deterministic_only=True,
        )
        # Deterministic check returns `fail` for these (canary missing
        # from response). That mismatch with the answer-key `partial` is
        # expected and is the load-bearing reason for the LLM judge.
        assert result.actual_verdict in ("fail", "inconclusive")
