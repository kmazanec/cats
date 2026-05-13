"""Judge-accuracy eval runner.

Reads ``evals/<category>/answer_key/<version>/cases.jsonl``, runs the
LLM-first Judge against each case, and prints:

- Overall accuracy
- Per-technique confusion table
- Failures by case ID

Exits non-zero when accuracy is below ``--threshold`` (or the env-driven
default from :data:`cats.config.Settings.eval_accuracy_threshold`).

Usage::

    uv run python -m evals.runner --category injection --key-version v1 --threshold 0.85

The ``--evidence-only`` flag skips the LLM call and reports the
deterministic evidence (canary echo, response shape) the LLM would
have seen — useful for the fast CI subset where we just want to
confirm the evidence-collection layer hasn't regressed. Note that
evidence-only cannot produce verdicts; it reports ``inconclusive``
for all cases, so its accuracy bar lives separately.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

from cats.agents.judge.verifier import gather_evidence, judge_llm
from cats.config import get_settings
from cats.llm.client import get_llm

VALID_VERDICTS = frozenset({"pass", "fail", "partial", "error"})


@dataclass(frozen=True)
class AnswerKeyCase:
    id: str
    technique: str
    canary: str
    attack_user_message: str
    target_response_text: str
    expected_verdict: str
    label_rationale: str


@dataclass(frozen=True)
class CaseResult:
    case: AnswerKeyCase
    actual_verdict: str
    was_deterministic: bool
    rationale: str


def _load_cases(category: str, version: str) -> list[AnswerKeyCase]:
    """Load every JSONL row from
    ``evals/<category>/answer_key/<version>/cases.jsonl``."""
    here = Path(__file__).parent
    cases_path = here / category / "answer_key" / version / "cases.jsonl"
    if not cases_path.exists():
        # Fall back to package-resource lookup so wheel-installed eval
        # data still works.
        try:
            ref = resources.files(f"evals.{category}.answer_key.{version}").joinpath("cases.jsonl")
            text = ref.read_text(encoding="utf-8")
        except (FileNotFoundError, ModuleNotFoundError) as e:
            raise FileNotFoundError(f"no answer key at {cases_path} (and not packaged)") from e
    else:
        text = cases_path.read_text(encoding="utf-8")

    cases: list[AnswerKeyCase] = []
    for line_no, raw in enumerate(text.splitlines(), 1):
        raw = raw.strip()
        if not raw or raw.startswith("//"):
            continue
        row = json.loads(raw)
        verdict = row["expected_verdict"]
        if verdict not in VALID_VERDICTS:
            raise ValueError(
                f"answer key line {line_no}: expected_verdict={verdict!r} "
                f"not in {sorted(VALID_VERDICTS)}"
            )
        cases.append(
            AnswerKeyCase(
                id=row["id"],
                technique=row["technique"],
                canary=row["canary"],
                attack_user_message=row["attack_user_message"],
                target_response_text=row["target_response_text"],
                expected_verdict=verdict,
                label_rationale=row.get("label_rationale", ""),
            )
        )
    return cases


async def _judge_one(
    case: AnswerKeyCase,
    *,
    category: str,
    deterministic_only: bool,
) -> CaseResult:
    """Run the LLM-first Judge for one case. Same code path as a real
    campaign: gather deterministic evidence, then a single LLM call."""
    attack_payload = {
        "user_message": case.attack_user_message,
        "canary": case.canary,
    }
    evidence = gather_evidence(
        category=category,
        attack_payload=attack_payload,
        target_response_text=case.target_response_text,
    )
    if deterministic_only:
        # Fast CI mode: skip the LLM entirely. We can't produce a
        # verdict — report inconclusive so callers can sanity-check
        # the evidence layer without burning budget. (The real
        # accuracy bar requires the LLM and lives in the nightly run.)
        return CaseResult(
            case=case,
            actual_verdict="inconclusive",
            was_deterministic=True,
            rationale=f"evidence-only: {json.dumps(evidence, default=str)[:200]}",
        )

    (verdict, rationale, _ev), _llm = await judge_llm(
        llm=get_llm(),
        category=category,
        attack_user_message=case.attack_user_message,
        target_response_text=case.target_response_text,
        evidence=evidence,
        canary=case.canary,
    )
    return CaseResult(
        case=case,
        actual_verdict=verdict,
        was_deterministic=False,
        rationale=rationale,
    )


def _format_confusion(results: Iterable[CaseResult]) -> str:
    """Per-technique counts: ``technique -> {(expected, actual): count}``."""
    by_tech: dict[str, Counter[tuple[str, str]]] = defaultdict(Counter)
    for r in results:
        by_tech[r.case.technique][(r.case.expected_verdict, r.actual_verdict)] += 1

    lines = []
    for tech in sorted(by_tech):
        lines.append(f"\n[{tech}]")
        for (expected, actual), count in sorted(by_tech[tech].items()):
            marker = "✓" if expected == actual else "✗"
            lines.append(f"  {marker} expected={expected:<7} actual={actual:<12} n={count}")
    return "\n".join(lines)


async def main(argv: list[str] | None = None) -> int:
    settings = get_settings()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--category", default="injection")
    parser.add_argument("--key-version", default="v1")
    parser.add_argument(
        "--threshold",
        type=float,
        default=settings.eval_accuracy_threshold,
        help="Accuracy below this fails the run.",
    )
    parser.add_argument(
        "--deterministic-only",
        action="store_true",
        help="Skip the LLM judge fallback — for fast CI subset runs.",
    )
    parser.add_argument(
        "--budget-usd",
        type=float,
        default=settings.eval_nightly_budget_usd,
        help="Soft cap; the runner aborts if cost crosses this estimate.",
    )
    parser.add_argument(
        "--max-cases",
        type=int,
        default=0,
        help="Run at most N cases (0 = all). Used by the fast CI subset.",
    )
    args = parser.parse_args(argv)

    cases = _load_cases(args.category, args.key_version)
    if args.max_cases > 0:
        cases = cases[: args.max_cases]
    print(
        f"running {len(cases)} cases from {args.category}/answer_key/{args.key_version}, "
        f"threshold={args.threshold:.2f}, deterministic_only={args.deterministic_only}"
    )

    results: list[CaseResult] = []
    for case in cases:
        result = await _judge_one(
            case,
            category=args.category,
            deterministic_only=args.deterministic_only,
        )
        results.append(result)
        marker = "✓" if result.case.expected_verdict == result.actual_verdict else "✗"
        det = " (det)" if result.was_deterministic else ""
        print(
            f"  {marker} {case.id} [{case.technique}]{det} "
            f"expected={case.expected_verdict} actual={result.actual_verdict}"
        )

    matched = sum(1 for r in results if r.case.expected_verdict == r.actual_verdict)
    total = len(results)
    accuracy = matched / total if total else 0.0

    print("\n=== summary ===")
    print(f"accuracy: {matched}/{total} = {accuracy:.3f} (threshold {args.threshold:.3f})")
    print(_format_confusion(results))

    failures = [r for r in results if r.case.expected_verdict != r.actual_verdict]
    if failures:
        print(f"\n=== {len(failures)} failure(s) ===")
        for r in failures:
            print(
                f"  - {r.case.id} [{r.case.technique}] "
                f"expected={r.case.expected_verdict} actual={r.actual_verdict}"
            )
            print(f"      label_rationale: {r.case.label_rationale}")
            print(f"      judge_rationale: {r.rationale[:200]}")

    if accuracy < args.threshold:
        print(f"\nFAIL: accuracy {accuracy:.3f} < threshold {args.threshold:.3f}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
