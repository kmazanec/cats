"""Unit tests for the Orchestrator planner's structural validation.

The planner's :func:`_validate_plan` is the load-bearing safety net
between a misbehaving LLM and the Red Team. These tests pin its
behavior against unknown techniques, budget overflows, and bad halt
conditions — the failure modes the Risks section names by name.
"""

from __future__ import annotations

import pytest

from cats.agents.orchestrator.planner import (
    MAX_ATTEMPTS_PER_PLAN,
    PlanStructuralError,
    _validate_plan,
)
from cats.agents.orchestrator.tools import (
    AttackCategoriesCatalog,
    AttackCategory,
)


def _catalog() -> AttackCategoriesCatalog:
    return AttackCategoriesCatalog(
        rows=[
            AttackCategory(
                category="injection",
                title="Prompt Injection",
                severity_default="high",
                atlas_technique_id="AML.T0051",
                owasp_llm_id="LLM01",
                techniques=["ignore_previous", "policy_puppetry", "role_override"],
            ),
            AttackCategory(
                category="exfil",
                title="Exfiltration",
                severity_default="critical",
                atlas_technique_id=None,
                owasp_llm_id=None,
                techniques=["default"],
            ),
        ]
    )


def _ok_plan(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "attempts": [
            {
                "category": "injection",
                "technique": "ignore_previous",
                "per_attempt_budget_usd": 0.25,
                "max_consecutive_partials": 2,
            },
            {
                "category": "exfil",
                "technique": "default",
                "per_attempt_budget_usd": 0.25,
                "max_consecutive_partials": 2,
            },
        ],
        "rationale": (
            "Coverage shows zero attempts on injection.ignore_previous in the "
            "last 30 days; exfil has no history either. Starting breadth-first."
        ),
        "confidence": "medium",
        "halt_on_consecutive_fails": 3,
        "halt_on_judge_errors": 2,
        "budget_usd_cap": 1.0,
    }
    base.update(overrides)
    return base


def test_validate_plan_accepts_well_formed_plan() -> None:
    plan = _validate_plan(raw=_ok_plan(), budget_usd_cap=2.0, catalog=_catalog())
    assert len(plan.attempts) == 2
    assert plan.attempts[0].category == "injection"
    assert plan.attempts[0].technique == "ignore_previous"
    assert plan.budget_usd_cap == 1.0
    assert plan.confidence == "medium"


def test_validate_plan_rejects_unknown_technique() -> None:
    bad = _ok_plan(
        attempts=[
            {
                "category": "injection",
                "technique": "this_does_not_exist",
                "per_attempt_budget_usd": 0.25,
                "max_consecutive_partials": 2,
            }
        ]
    )
    with pytest.raises(PlanStructuralError, match="unknown"):
        _validate_plan(raw=bad, budget_usd_cap=2.0, catalog=_catalog())


def test_validate_plan_rejects_budget_above_operator_cap() -> None:
    bad = _ok_plan(budget_usd_cap=10.0)
    with pytest.raises(PlanStructuralError, match="exceeds operator budget"):
        _validate_plan(raw=bad, budget_usd_cap=2.0, catalog=_catalog())


def test_validate_plan_rejects_attempt_budget_sum_above_cap() -> None:
    bad = _ok_plan(
        attempts=[
            {
                "category": "injection",
                "technique": "ignore_previous",
                "per_attempt_budget_usd": 0.75,
                "max_consecutive_partials": 2,
            },
            {
                "category": "injection",
                "technique": "policy_puppetry",
                "per_attempt_budget_usd": 0.75,
                "max_consecutive_partials": 2,
            },
        ],
        budget_usd_cap=1.0,
    )
    with pytest.raises(PlanStructuralError, match="exceeds budget_usd_cap"):
        _validate_plan(raw=bad, budget_usd_cap=2.0, catalog=_catalog())


def test_validate_plan_rejects_empty_attempts() -> None:
    bad = _ok_plan(attempts=[])
    with pytest.raises(PlanStructuralError, match="attempts is missing or empty"):
        _validate_plan(raw=bad, budget_usd_cap=2.0, catalog=_catalog())


def test_validate_plan_truncates_at_max_attempts() -> None:
    too_many = [
        {
            "category": "injection",
            "technique": "ignore_previous",
            "per_attempt_budget_usd": 0.01,
            "max_consecutive_partials": 1,
        }
        for _ in range(MAX_ATTEMPTS_PER_PLAN + 5)
    ]
    raw = _ok_plan(attempts=too_many, budget_usd_cap=0.2)
    plan = _validate_plan(raw=raw, budget_usd_cap=2.0, catalog=_catalog())
    assert len(plan.attempts) == MAX_ATTEMPTS_PER_PLAN


def test_validate_plan_rejects_too_short_rationale() -> None:
    bad = _ok_plan(rationale="too short")
    with pytest.raises(PlanStructuralError, match="rationale is too short"):
        _validate_plan(raw=bad, budget_usd_cap=2.0, catalog=_catalog())


def test_validate_plan_rejects_halt_out_of_range() -> None:
    bad = _ok_plan(halt_on_consecutive_fails=0)
    with pytest.raises(PlanStructuralError, match="halt_on_consecutive_fails"):
        _validate_plan(raw=bad, budget_usd_cap=2.0, catalog=_catalog())
    bad = _ok_plan(halt_on_judge_errors=99)
    with pytest.raises(PlanStructuralError, match="halt_on_judge_errors"):
        _validate_plan(raw=bad, budget_usd_cap=2.0, catalog=_catalog())


def test_validate_plan_clamps_unknown_confidence_to_medium() -> None:
    raw = _ok_plan(confidence="extreme")
    plan = _validate_plan(raw=raw, budget_usd_cap=2.0, catalog=_catalog())
    assert plan.confidence == "medium"


def test_validate_plan_rejects_negative_per_attempt_budget() -> None:
    bad = _ok_plan(
        attempts=[
            {
                "category": "injection",
                "technique": "ignore_previous",
                "per_attempt_budget_usd": -0.5,
                "max_consecutive_partials": 2,
            }
        ]
    )
    with pytest.raises(PlanStructuralError, match="negative"):
        _validate_plan(raw=bad, budget_usd_cap=2.0, catalog=_catalog())


def test_validate_plan_rejects_attempt_not_object() -> None:
    bad = _ok_plan(attempts=["not_a_dict"])
    with pytest.raises(PlanStructuralError, match="not an object"):
        _validate_plan(raw=bad, budget_usd_cap=2.0, catalog=_catalog())
