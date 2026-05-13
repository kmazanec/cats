"""Top-level eval suite — runs all four agent suites in one command.

Usage::

    uv run python -m evals.suite                # all four agents
    uv run python -m evals.suite orchestrator   # one suite only
    uv run python -m evals.suite judge --with-fake-llm
"""

from __future__ import annotations

import argparse
import sys

from evals.runners import documentation as documentation_runner
from evals.runners import judge as judge_runner
from evals.runners import orchestrator as orchestrator_runner
from evals.runners import red_team as red_team_runner
from evals.scorers import ScoreResult


def _run_all(*, with_fake_llm: bool) -> dict[str, list[ScoreResult]]:
    return {
        "orchestrator": orchestrator_runner.run_eval(),
        "red_team": red_team_runner.run_eval(),
        "judge": judge_runner.run_eval(with_fake_llm=with_fake_llm),
        "documentation": documentation_runner.run_eval(),
    }


def _summarize(label: str, results: list[ScoreResult]) -> tuple[int, int]:
    passes = sum(1 for r in results if r.passed)
    total = len(results)
    rate = passes / total if total else 0.0
    print(f"\n--- {label}: {passes}/{total} = {rate:.3f} ---")
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
    return passes, total


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "agent",
        nargs="?",
        choices=["orchestrator", "red_team", "judge", "documentation", "all"],
        default="all",
    )
    parser.add_argument("--threshold", type=float, default=0.9)
    parser.add_argument(
        "--with-fake-llm",
        action="store_true",
        help="Judge: drive judge_llm with a FakeLLMClient. Other agents ignore this.",
    )
    args = parser.parse_args(argv)

    if args.agent == "all":
        suites = _run_all(with_fake_llm=args.with_fake_llm)
    elif args.agent == "orchestrator":
        suites = {"orchestrator": orchestrator_runner.run_eval()}
    elif args.agent == "red_team":
        suites = {"red_team": red_team_runner.run_eval()}
    elif args.agent == "judge":
        suites = {"judge": judge_runner.run_eval(with_fake_llm=args.with_fake_llm)}
    elif args.agent == "documentation":
        suites = {"documentation": documentation_runner.run_eval()}
    else:  # pragma: no cover - argparse blocks this
        return 2

    total_pass = 0
    total = 0
    for label, results in suites.items():
        p, t = _summarize(label, results)
        total_pass += p
        total += t

    rate = total_pass / total if total else 0.0
    print(f"\n=== overall: {total_pass}/{total} = {rate:.3f}  (threshold {args.threshold:.3f}) ===")
    return 0 if rate >= args.threshold else 1


if __name__ == "__main__":
    sys.exit(main())
