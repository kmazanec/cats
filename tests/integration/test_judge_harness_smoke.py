"""Opt-in live smoke test for the Judge-accuracy harness.

Runs the real Judge LLM against one ``pass``-expected case from each
of the six fixture-bearing categories. Marked ``live_judge`` so it
doesn't run by default — it costs real money and needs an OpenRouter
key. Opt in with both an env flag AND a real key::

    CATS_RUN_LIVE_JUDGE_EVAL=1 OPENROUTER_API_KEY=sk-or-... \\
        pytest -m live_judge tests/integration/test_judge_harness_smoke.py

The env flag is the gate (not just the key) because
``tests/conftest.py`` sets a fake ``test-`` key for every test run,
so a bare key check would always pass.

The nightly GitLab job (``judge-accuracy-nightly``) covers the full
fixture set; this is the developer's "did I break the harness?"
smoke. ``max_cases=1`` keeps the total spend at ~$0.01 per run.

What this gives us that the unit tests don't: end-to-end exercise of
the real Judge LLM through the real ``judge_llm()`` code path. If the
prompt rendering, evidence-block serialization, or the per-category
rubric loading regresses, this test catches it before the nightly run.
"""

from __future__ import annotations

import os

import pytest
from evals.runner import (
    _CATEGORY_THRESHOLDS,
    ALL_CATEGORIES,
    _judge_one,
    _load_cases,
)

pytestmark = [pytest.mark.live_judge, pytest.mark.integration]


def _is_live_eval_enabled() -> bool:
    """Live-judge smoke runs only when the opt-in flag is set AND the
    OpenRouter key looks real (not the ``test-`` placeholder the
    global conftest injects)."""
    if os.environ.get("CATS_RUN_LIVE_JUDGE_EVAL") != "1":
        return False
    key = os.environ.get("OPENROUTER_API_KEY", "")
    return bool(key) and not key.startswith("test-")


@pytest.fixture(autouse=True)
def _require_live_eval_opt_in() -> None:
    if not _is_live_eval_enabled():
        pytest.skip(
            "Live judge smoke skipped. Opt in with CATS_RUN_LIVE_JUDGE_EVAL=1 "
            "+ a real OPENROUTER_API_KEY."
        )


@pytest.mark.parametrize("category", ALL_CATEGORIES)
@pytest.mark.asyncio
async def test_live_judge_can_rule_one_pass_case(category: str) -> None:
    """Pick the first ``pass``-expected fixture for the category and
    confirm the real Judge LLM rules ``pass`` on it.

    Why ``pass``-expected: it's the easiest verdict for the LLM to
    surface (the canary/marker/payload is right there), so a regression
    in the harness shows up as a verdict drift to ``fail``/``partial``
    /``error`` rather than a borderline disagreement. We don't smoke
    ``fail`` or ``partial`` cases here — those depend more on the
    model's hedging behavior and produce flakier results.
    """
    cases = _load_cases(category)
    pass_cases = [c for c in cases if c.expected_verdict == "pass"]
    assert pass_cases, f"{category} has no pass-expected fixtures to smoke"

    # Use the first pass case — fixture ordering is stable, so this
    # picks a deterministic case across CI runs.
    case = pass_cases[0]
    result = await _judge_one(case, deterministic_only=False)

    # We assert agreement, not perfection. A drift here means either
    # the harness regressed, the rubric needs updating, or the LLM
    # provider changed behavior — all worth a human look. The threshold
    # for this category is documented for the failure rationale.
    threshold = _CATEGORY_THRESHOLDS.get(category, 0.85)
    assert result.actual_verdict == "pass", (
        f"{case.id}: live Judge ruled {result.actual_verdict!r}, expected 'pass'. "
        f"(category threshold: {threshold:.2f}; "
        f"rubric/v1.md committed to this bar). "
        f"Judge rationale: {result.rationale[:200]}"
    )
