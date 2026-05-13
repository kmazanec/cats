"""Documentation eval runner.

Loads ``evals/cases/documentation/*.md`` cases and drives
``cats.agents.documentation.writer.write_report`` with a
``FakeLLMClient`` whose response is taken verbatim from
``## Inputs.fake_documentation_response``. Scores the resulting
report Markdown against ``## Expected``.

The Documentation agent has the simplest contract: it transforms
``(category, technique, attack, response, verdict, rationale)``
into a structured Markdown report. The eval mostly checks that
critical context (technique, verdict, attack reproduction) shows
up in the report and that no PHI/canary contamination is
introduced.

Usage::

    uv run python -m evals.runners.documentation
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from cats.agents.documentation.writer import write_report
from cats.llm.client import FakeLLMClient
from evals.loader import Case, load_cases
from evals.scorers import ScoreResult
from evals.scorers.documentation import score


async def _run_case(case: Case) -> ScoreResult:
    inputs = case.inputs
    fake_response = case.inputs.get("fake_documentation_response")
    if fake_response is None:
        r = ScoreResult(case_id=case.case_id)
        r.error = "inputs.fake_documentation_response required"
        return r
    if not isinstance(fake_response, str):
        r = ScoreResult(case_id=case.case_id)
        r.error = "fake_documentation_response must be a string (the report markdown the LLM emits)"
        return r

    fake = FakeLLMClient()
    fake.register("documentation", lambda _msgs: fake_response)

    report, _llm = await write_report(
        llm=fake,
        category=str(inputs.get("category") or ""),
        technique=str(inputs.get("technique") or ""),
        attack_user_message=str(inputs.get("attack_user_message") or ""),
        target_response_text=str(inputs.get("target_response_text") or ""),
        verdict=str(inputs.get("verdict") or ""),
        rationale=str(inputs.get("rationale") or ""),
    )
    return score(case, report=report)


def run_eval(cases: list[Case] | None = None) -> list[ScoreResult]:
    cases = cases if cases is not None else load_cases("documentation")
    results: list[ScoreResult] = []
    for case in cases:
        try:
            results.append(asyncio.run(_run_case(case)))
        except Exception as e:
            r = ScoreResult(case_id=case.case_id)
            r.error = f"{type(e).__name__}: {e}"
            results.append(r)
    return results


def _print_report(results: list[ScoreResult], *, threshold: float) -> int:
    passes = sum(1 for r in results if r.passed)
    total = len(results)
    rate = passes / total if total else 0.0
    print(f"=== documentation eval — {total} cases ===")
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
