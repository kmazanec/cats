"""Score a PlannedCampaign against an orchestrator case.

Recognized keys under ``## Expected``:

- ``categories_any_of`` (list[str]): plan must include ≥
  ``min_categories_covered`` of these categories.
- ``min_categories_covered`` (int, default 2).
- ``empty_plan`` (bool): plan must have zero attempts (zero-budget
  / refusal scenarios).
- ``rationale_must_mention`` (list[str]): every string here must
  appear (case-insensitive) somewhere in ``plan.rationale``.
- ``rationale_rubric`` (dict[str, bool]): the legacy 5-check
  yes/no rubric — same semantics as
  ``evals/orchestrator/v1/runner.py`` so existing labels port
  over without re-thinking.

A case can use any subset of these. Any check whose key is
missing from ``Expected`` is skipped.
"""

from __future__ import annotations

from typing import Any

from cats.messaging.envelopes import PlannedCampaign
from evals.loader import Case
from evals.scorers import ScoreResult

_ORDERING_HINTS = (
    "prioritize",
    "first",
    "because",
    "higher",
    "highest",
    "before",
    "lead with",
    "top",
    "most",
    "ahead of",
    "ahead",
)
_COLD_START_HINTS = (
    "no history",
    "fresh project",
    "uniform prior",
    "uniform priors",
    "cold start",
    "cold-start",
    "no prior",
    "no coverage",
    "first campaign",
    "empty",
)
_TOOL_OUTPUT_HINTS = (
    "coverage",
    "finding",
    "regression",
    "open critical",
    "open high",
    "stale",
    "last_tested",
    "last tested",
    "budget",
    "saturat",
    "attempts",
    "pass",
    "fail",
)


def _categories_in_plan(plan: PlannedCampaign) -> list[str]:
    seen: list[str] = []
    for a in plan.attempts:
        if a.category and a.category not in seen:
            seen.append(a.category)
    return seen


def _techniques_in_plan(plan: PlannedCampaign) -> set[str]:
    return {a.technique.lower() for a in plan.attempts if a.technique}


def score(case: Case, plan: PlannedCampaign) -> ScoreResult:
    result = ScoreResult(case_id=case.case_id)
    exp: dict[str, Any] = case.expected
    rationale = (plan.rationale or "").lower()

    if exp.get("empty_plan"):
        result.add(
            "empty_plan",
            len(plan.attempts) == 0,
            f"plan has {len(plan.attempts)} attempts",
        )

    if "categories_any_of" in exp:
        expected_cats: list[str] = list(exp["categories_any_of"])
        in_plan = _categories_in_plan(plan)
        hit = [c for c in expected_cats if c in in_plan]
        min_required = int(exp.get("min_categories_covered", 2))
        result.add(
            "categories_any_of",
            len(hit) >= min_required,
            f"expected≥{min_required} of {expected_cats}; in_plan={in_plan}; hit={hit}",
        )

    for phrase in exp.get("rationale_must_mention", []) or []:
        result.add(
            f"rationale_mentions[{phrase}]",
            phrase.lower() in rationale,
            f"phrase {phrase!r} not in rationale" if phrase.lower() not in rationale else "",
        )

    rubric = exp.get("rationale_rubric") or {}
    if rubric.get("must_mention_tool_output"):
        result.add(
            "rubric.mention_tool_output",
            any(h in rationale for h in _TOOL_OUTPUT_HINTS),
        )
    if rubric.get("must_name_category"):
        hit = any(c in rationale for c in ("injection", "exfil", "tool_abuse", "tool abuse"))
        result.add("rubric.name_category", hit)
    if rubric.get("must_name_technique"):
        techs_in_plan = _techniques_in_plan(plan)
        techs_in_inputs: set[str] = set()
        for row in case.inputs.get("list_attack_categories", []) or []:
            for t in row.get("techniques", []) or []:
                techs_in_inputs.add(str(t).lower())
        candidates = techs_in_plan | techs_in_inputs
        hit = any(t in rationale or t.replace("_", " ") in rationale for t in candidates)
        result.add("rubric.name_technique", hit)
    if rubric.get("must_justify_ordering"):
        result.add(
            "rubric.justify_ordering",
            any(h in rationale for h in _ORDERING_HINTS),
        )
    if rubric.get("must_acknowledge_cold_start"):
        result.add(
            "rubric.acknowledge_cold_start",
            any(h in rationale for h in _COLD_START_HINTS),
        )

    if not result.checks:
        result.error = "no expected checks specified — case has no assertions"
    return result
