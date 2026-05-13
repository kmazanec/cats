"""R3 — fast offline judge-evidence subset.

The judge is now LLM-first: every verdict is rendered by ``judge_llm``.
That means a true accuracy bar needs an LLM and lives in the nightly
``evals.runner`` budget. What we can still gate offline in ~seconds is
that the *evidence* layer (``gather_evidence``) reports the cheap
deterministic observations the LLM needs to weigh — canary echo in
particular. If that signal regresses, every downstream LLM verdict
will be wrong by construction.

So: for every ``pass``-expected case in the answer key, the canary
must appear in the response text (the LLM needs to see this fact).
For every ``fail``-expected case where the answer rationale states
the canary was withheld, the canary must NOT appear. Partials are
inherently LLM-territory and aren't checked here.
"""

from __future__ import annotations

import pytest
from evals.runner import _load_cases

from cats.agents.judge.verifier import gather_evidence

# This file talks to no external services. It's marked `integration`
# only because it imports langgraph via cats.agents.judge.
pytestmark = pytest.mark.integration


def test_pass_cases_have_canary_in_response_evidence() -> None:
    """Every pass-expected case must show the canary verbatim in the
    response text — the LLM judge relies on this evidence to rule
    pass. If a pass case stops showing canary_in_response=True, the
    answer key drifted from the rubric or the deterministic helper
    regressed."""
    cases = _load_cases("injection", "v1")
    pass_cases = [c for c in cases if c.expected_verdict == "pass"]

    assert len(pass_cases) >= 1, "answer key v1 should include pass cases"

    failures = []
    for case in pass_cases:
        evidence = gather_evidence(
            category="injection",
            attack_payload={"canary": case.canary, "user_message": case.attack_user_message},
            target_response_text=case.target_response_text,
        )
        if not evidence.get("canary_in_response"):
            failures.append(case.id)

    assert not failures, (
        f"pass-expected cases without canary_in_response evidence "
        f"({len(failures)}/{len(pass_cases)}): {failures}"
    )


def test_fail_cases_load_and_collect_evidence_cleanly() -> None:
    """Every fail-expected case must pass through gather_evidence
    without raising and surface a usable response_shape — basic
    plumbing check so the LLM judge has something to read."""
    cases = _load_cases("injection", "v1")
    fail_cases = [c for c in cases if c.expected_verdict == "fail"]

    assert len(fail_cases) >= 10, (
        f"answer key v1 should have ≥10 fail cases for the offline gate; got {len(fail_cases)}"
    )

    for case in fail_cases:
        evidence = gather_evidence(
            category="injection",
            attack_payload={"canary": case.canary, "user_message": case.attack_user_message},
            target_response_text=case.target_response_text,
        )
        # response_shape is the universal-shape feature block; it must
        # exist on every evidence dict so the LLM has a consistent
        # schema to read.
        assert "response_shape" in evidence
        assert "char_count" in evidence["response_shape"]
