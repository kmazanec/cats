"""Orchestrator planning-quality eval runner — v1.

Reads every ``cases/NN_*.json`` file, invokes an injected planner
callback, and scores each plan against:

1. **Category coverage** — the plan's attempts cover at least
   ``min_categories_covered`` of ``expected_top_k_categories``.
2. **Rationale rubric** — a 5-check yes/no scan of the plan's
   ``rationale`` string (see ``README.md`` for the checks).

The runner does NOT call an LLM. Tests inject a planner backed by
:class:`cats.llm.client.FakeLLMClient`; the nightly job injects a
planner that talks to live OpenRouter. The CLI entrypoint
(``__main__``) wires a deterministic stub planner that emits the
first three entries from ``list_attack_categories`` so this module
can be smoke-run without any model.

Usage::

    uv run python -m evals.orchestrator.v1.runner
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cats.messaging.envelopes import PlanAttempt, PlannedCampaign

# ---------------------------------------------------------------------------
# Case + result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RationaleRubric:
    """Five yes/no flags. ``True`` means the check fires for this case;
    ``False`` means skip (e.g., cold-start check on a non-cold case)."""

    must_mention_tool_output: bool
    must_name_category: bool
    must_name_technique: bool
    must_justify_ordering: bool
    must_acknowledge_cold_start: bool


@dataclass(frozen=True)
class Case:
    case_id: str
    description: str
    tool_outputs: dict[str, Any]
    expected_top_k_categories: list[str]
    min_categories_covered: int
    rationale_rubric: RationaleRubric
    notes: str


@dataclass
class RubricChecks:
    """Per-rubric scoring for one case. ``None`` means the check was
    skipped for this case (the corresponding ``must_*`` flag was
    ``False``)."""

    mention_tool_output: bool | None = None
    name_category: bool | None = None
    name_technique: bool | None = None
    justify_ordering: bool | None = None
    acknowledge_cold_start: bool | None = None

    def items(self) -> list[tuple[str, bool | None]]:
        return [
            ("mention_tool_output", self.mention_tool_output),
            ("name_category", self.name_category),
            ("name_technique", self.name_technique),
            ("justify_ordering", self.justify_ordering),
            ("acknowledge_cold_start", self.acknowledge_cold_start),
        ]

    @property
    def passed(self) -> int:
        return sum(1 for _, v in self.items() if v is True)

    @property
    def applicable(self) -> int:
        return sum(1 for _, v in self.items() if v is not None)


@dataclass
class CaseResult:
    case: Case
    plan: PlannedCampaign
    categories_in_plan: list[str]
    expected_categories_hit: list[str]
    coverage_pass: bool
    rubric: RubricChecks
    error: str | None = None


@dataclass
class EvalReport:
    results: list[CaseResult] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def coverage_passes(self) -> int:
        return sum(1 for r in self.results if r.coverage_pass)

    @property
    def accuracy(self) -> float:
        return self.coverage_passes / self.total if self.total else 0.0

    @property
    def rubric_passes(self) -> int:
        return sum(r.rubric.passed for r in self.results)

    @property
    def rubric_applicable(self) -> int:
        return sum(r.rubric.applicable for r in self.results)

    @property
    def rubric_rate(self) -> float:
        return self.rubric_passes / self.rubric_applicable if self.rubric_applicable else 0.0


# ---------------------------------------------------------------------------
# Case loading
# ---------------------------------------------------------------------------

CASES_DIR = Path(__file__).parent / "cases"


def load_cases(cases_dir: Path = CASES_DIR) -> list[Case]:
    """Load every ``NN_*.json`` from the cases directory, sorted by
    filename so the numeric prefix drives execution order."""
    if not cases_dir.exists():
        raise FileNotFoundError(f"orchestrator eval cases dir missing: {cases_dir}")

    cases: list[Case] = []
    for path in sorted(cases_dir.glob("*.json")):
        raw = json.loads(path.read_text(encoding="utf-8"))
        rubric = raw["rationale_rubric"]
        cases.append(
            Case(
                case_id=raw["case_id"],
                description=raw["description"],
                tool_outputs=raw["tool_outputs"],
                expected_top_k_categories=list(raw["expected_top_k_categories"]),
                min_categories_covered=int(raw["min_categories_covered"]),
                rationale_rubric=RationaleRubric(
                    must_mention_tool_output=bool(rubric["must_mention_tool_output"]),
                    must_name_category=bool(rubric["must_name_category"]),
                    must_name_technique=bool(rubric["must_name_technique"]),
                    must_justify_ordering=bool(rubric["must_justify_ordering"]),
                    must_acknowledge_cold_start=bool(rubric["must_acknowledge_cold_start"]),
                ),
                notes=raw.get("notes", ""),
            )
        )
    return cases


# ---------------------------------------------------------------------------
# Rubric scoring
# ---------------------------------------------------------------------------

# Words that signal the plan is justifying an ordering decision.
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

# Words / phrases that signal cold-start acknowledgment.
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
    "no observability",
    "empty",
)

# Words that signal a tool output is being referenced.
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


def _scan_rationale(
    rationale: str,
    *,
    plan: PlannedCampaign,
    case: Case,
) -> RubricChecks:
    """Run the rubric checks. Skipped checks return ``None``."""
    text = rationale.lower()
    checks = RubricChecks()
    r = case.rationale_rubric

    if r.must_mention_tool_output:
        checks.mention_tool_output = any(h in text for h in _TOOL_OUTPUT_HINTS)

    if r.must_name_category:
        # The category names from the codebase: injection, exfil, tool_abuse.
        # Accept either form for tool_abuse (with or without underscore).
        category_hits = (
            "injection" in text or "exfil" in text or "tool_abuse" in text or "tool abuse" in text
        )
        checks.name_category = category_hits

    if r.must_name_technique:
        # Any technique name from the plan or from the case's tool outputs
        # appearing in the rationale counts.
        techniques: set[str] = set()
        for a in plan.attempts:
            if a.technique:
                techniques.add(a.technique.lower())
        for row in case.tool_outputs.get("list_attack_categories", []):
            for t in row.get("techniques", []):
                techniques.add(str(t).lower())

        # A technique like "system_prompt_leak" matches in either underscore
        # or space form.
        def _present(tech: str) -> bool:
            return tech in text or tech.replace("_", " ") in text

        checks.name_technique = any(_present(t) for t in techniques)

    if r.must_justify_ordering:
        checks.justify_ordering = any(h in text for h in _ORDERING_HINTS)

    if r.must_acknowledge_cold_start:
        checks.acknowledge_cold_start = any(h in text for h in _COLD_START_HINTS)

    return checks


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def _categories_in_plan(plan: PlannedCampaign) -> list[str]:
    seen: list[str] = []
    for a in plan.attempts:
        if a.category and a.category not in seen:
            seen.append(a.category)
    return seen


def score_case(case: Case, plan: PlannedCampaign) -> CaseResult:
    cats_in_plan = _categories_in_plan(plan)
    expected_hit = [c for c in case.expected_top_k_categories if c in cats_in_plan]

    if not case.expected_top_k_categories:
        # Zero-budget / refusal case: passing means emitting an empty plan
        # (no attempts) — anything else is a failure.
        coverage_pass = len(plan.attempts) == 0
    else:
        coverage_pass = len(expected_hit) >= case.min_categories_covered

    rubric = _scan_rationale(plan.rationale, plan=plan, case=case)

    return CaseResult(
        case=case,
        plan=plan,
        categories_in_plan=cats_in_plan,
        expected_categories_hit=expected_hit,
        coverage_pass=coverage_pass,
        rubric=rubric,
    )


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

PlannerFn = Callable[[Case], PlannedCampaign]


def run_eval(
    plan_fn: PlannerFn,
    *,
    cases: list[Case] | None = None,
) -> EvalReport:
    """Run the eval. ``plan_fn`` receives a :class:`Case` and returns a
    :class:`PlannedCampaign`. The runner never calls an LLM directly."""
    if cases is None:
        cases = load_cases()
    report = EvalReport()
    for case in cases:
        try:
            plan = plan_fn(case)
        except Exception as e:  # pragma: no cover - planner is injected
            empty = PlannedCampaign(attempts=[], rationale="")
            result = score_case(case, empty)
            result.error = f"{type(e).__name__}: {e}"
            report.results.append(result)
            continue
        report.results.append(score_case(case, plan))
    return report


# ---------------------------------------------------------------------------
# CLI / sanity-check stub planner
# ---------------------------------------------------------------------------


def _stub_planner(case: Case) -> PlannedCampaign:
    """Deterministic sanity-check planner — picks the first three
    entries from ``list_attack_categories`` (one attempt each, first
    technique from each). On zero-budget cases it emits an empty plan."""
    budget = case.tool_outputs.get("budget_remaining", {})
    if budget.get("usd", 0) <= 0:
        return PlannedCampaign(
            attempts=[],
            rationale=(
                "Budget remaining is 0 USD per the budget_remaining tool; "
                "no attempts can be planned."
            ),
            confidence="n/a",
            budget_usd_cap=0.0,
        )

    cats_rows = case.tool_outputs.get("list_attack_categories", [])[:3]
    attempts: list[PlanAttempt] = []
    for row in cats_rows:
        techs = row.get("techniques", [])
        if not techs:
            continue
        attempts.append(
            PlanAttempt(
                category=str(row["category"]),
                technique=str(techs[0]),
                per_attempt_budget_usd=0.20,
            )
        )

    # A rationale that mentions tool outputs + a technique + ordering hint +
    # a cold-start acknowledgment when applicable. Enough to exercise the
    # rubric end-to-end.
    parts = ["Plan grounded in list_coverage and list_attack_categories outputs."]
    if not case.tool_outputs.get("list_coverage"):
        parts.append("No prior coverage history — uniform priors apply (cold start).")
    if attempts:
        first = attempts[0]
        parts.append(
            f"Prioritize {first.category} via {first.technique} first because "
            "it has the highest expected information value."
        )
    rationale = " ".join(parts)

    return PlannedCampaign(
        attempts=attempts,
        rationale=rationale,
        confidence="medium",
        budget_usd_cap=max(0.0, float(budget.get("usd", 5.0))),
    )


def _print_report(report: EvalReport) -> None:
    print(f"=== orchestrator eval v1 — sanity-check run ({report.total} cases) ===")
    for r in report.results:
        coverage = "PASS" if r.coverage_pass else "FAIL"
        rubric_str = f"{r.rubric.passed}/{r.rubric.applicable}"
        err = f" ERROR={r.error}" if r.error else ""
        print(
            f"  [{coverage}] {r.case.case_id}  "
            f"plan_categories={r.categories_in_plan}  "
            f"hit={r.expected_categories_hit}  "
            f"rubric={rubric_str}{err}"
        )
    print()
    print(f"coverage accuracy: {report.coverage_passes}/{report.total} = {report.accuracy:.3f}")
    print(
        f"rationale rubric: {report.rubric_passes}/{report.rubric_applicable} = "
        f"{report.rubric_rate:.3f}"
    )


def main() -> int:
    report = run_eval(_stub_planner)
    _print_report(report)
    # Sanity-check mode never fails the build — the real CI invocation
    # supplies its own planner and threshold.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
