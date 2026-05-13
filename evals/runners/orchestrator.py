"""Orchestrator eval runner.

Loads every ``evals/cases/orchestrator/*.md`` case, invokes a
``plan_fn(case) -> PlannedCampaign`` callable, scores the plan, and
reports.

Default ``plan_fn`` is a deterministic stub planner — same shape as
``evals/orchestrator/v1/runner.py:_stub_planner`` — so the runner
needs no LLM, no DB, nothing. Nightly CI swaps in an LLM-backed
planner via ``run_eval(plan_fn=...)``.

Usage::

    uv run python -m evals.runners.orchestrator
    uv run python -m evals.runners.orchestrator --threshold 0.75
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable

from cats.messaging.envelopes import PlanAttempt, PlannedCampaign
from evals.loader import Case, load_cases
from evals.scorers import ScoreResult
from evals.scorers.orchestrator import score

PlanFn = Callable[[Case], PlannedCampaign]


def stub_planner(case: Case) -> PlannedCampaign:
    """Deterministic baseline planner — picks up to three categories
    from ``list_attack_categories``, names the first technique of
    each, and constructs a rationale that mentions the tool outputs,
    an ordering hint, and (if applicable) a cold-start note. Enough
    to validate every check in the scorer end-to-end."""
    inputs = case.inputs
    budget = inputs.get("budget_remaining", {}) or {}
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

    rows = inputs.get("list_attack_categories", []) or []
    coverage = inputs.get("list_coverage", []) or []
    findings = inputs.get("list_open_findings", []) or []
    regressions = inputs.get("list_recent_regressions", []) or []

    attempts: list[PlanAttempt] = []
    for row in rows[:3]:
        techs = row.get("techniques", []) or []
        if not techs:
            continue
        attempts.append(
            PlanAttempt(
                category=str(row["category"]),
                technique=str(techs[0]),
                per_attempt_budget_usd=0.20,
            )
        )

    parts: list[str] = []
    if not coverage and not findings and not regressions:
        parts.append("No prior coverage history or findings — uniform priors apply (cold start).")
    else:
        ref_bits: list[str] = []
        if findings:
            ref_bits.append(f"{len(findings)} open finding(s)")
        if regressions:
            ref_bits.append(f"{len(regressions)} recent regression(s)")
        if coverage:
            ref_bits.append("coverage history available")
        parts.append("Plan grounded in tool outputs: " + ", ".join(ref_bits) + ".")
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


def run_eval(
    plan_fn: PlanFn | None = None, *, cases: list[Case] | None = None
) -> list[ScoreResult]:
    plan_fn = plan_fn or stub_planner
    cases = cases if cases is not None else load_cases("orchestrator")
    results: list[ScoreResult] = []
    for case in cases:
        try:
            plan = plan_fn(case)
        except Exception as e:
            r = ScoreResult(case_id=case.case_id)
            r.error = f"{type(e).__name__}: {e}"
            results.append(r)
            continue
        results.append(score(case, plan))
    return results


def _print_report(results: list[ScoreResult], *, threshold: float) -> int:
    passes = sum(1 for r in results if r.passed)
    total = len(results)
    rate = passes / total if total else 0.0
    print(f"=== orchestrator eval — {total} cases ===")
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
    parser.add_argument("--threshold", type=float, default=0.75)
    args = parser.parse_args(argv)
    results = run_eval()
    return _print_report(results, threshold=args.threshold)


if __name__ == "__main__":
    sys.exit(main())
