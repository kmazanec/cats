"""Judge eval runner.

Loads ``evals/cases/judge/*.md``, feeds each case through the Judge
verifier, and scores the verdict against the case's expectation.

Two modes:

- ``--evidence-only`` (default): no LLM call. The runner gathers
  deterministic evidence and asserts the *evidence-derived signals*
  (``canary_in_response``, ``markers_leaked``, response shape) match
  what the case's ``## Expected.evidence`` block claims. Catches
  drift in the evidence-collection layer without burning budget.
- ``--with-fake-llm`` (CI-safe): drive ``judge_llm`` with a
  ``FakeLLMClient`` that returns whatever verdict the case's
  ``## Inputs.fake_judge_response`` carries, then assert the
  verifier propagates / clamps it correctly. Exercises the JSON
  parsing + verdict-space clamping path without OpenRouter.

The live-LLM nightly invocation lives in ``evals/runner.py``
(unchanged) — that runner targets the JSONL answer key and uses
the real OpenRouter client. This markdown runner is the
human-writable CI bar.

Usage::

    uv run python -m evals.runners.judge                # evidence-only
    uv run python -m evals.runners.judge --with-fake-llm
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from cats.agents.judge.verifier import (
    JudgeTranscriptTurn,
    gather_evidence,
    judge_llm,
)
from cats.llm.client import FakeLLMClient
from evals.loader import Case, load_cases
from evals.scorers import ScoreResult
from evals.scorers.judge import score


def _evidence_only(case: Case) -> ScoreResult:
    """Score a case using only the deterministic evidence layer.

    Per-case ``## Expected.evidence`` is a dict of expected
    evidence fields (e.g. ``{"canary_in_response": true}``). Each
    key becomes one check.
    """
    inputs = case.inputs
    evidence = gather_evidence(
        category=str(inputs.get("category") or ""),
        attack_payload={
            "user_message": str(inputs.get("attack_user_message") or ""),
            "canary": str(inputs.get("canary") or ""),
        },
        target_response_text=str(inputs.get("target_response_text") or ""),
    )
    result = ScoreResult(case_id=case.case_id)
    expected_evidence = case.expected.get("evidence") or {}
    if not expected_evidence:
        # No evidence-layer assertions — silently skipped in this mode.
        # The fake-llm mode will exercise this case.
        result.add("skipped[no evidence asserted]", True, "")
        return result
    for key, expected_value in expected_evidence.items():
        actual = evidence.get(key)
        result.add(
            f"evidence[{key}]",
            actual == expected_value,
            f"got={actual!r} expected={expected_value!r}",
        )
    return result


async def _with_fake_llm(case: Case) -> ScoreResult:
    """Drive ``judge_llm`` with a FakeLLMClient and score the verdict."""
    inputs = case.inputs
    fake_judge_response = case.inputs.get("fake_judge_response")
    if fake_judge_response is None:
        r = ScoreResult(case_id=case.case_id)
        r.error = "fake-llm mode requires inputs.fake_judge_response"
        return r

    fake = FakeLLMClient()
    fake_text = json.dumps(fake_judge_response)
    fake.register("judge", lambda _msgs: fake_text)

    # R10 — when the case ships an explicit transcript, the Judge sees
    # it as a multi-turn conversation; evidence is gathered over the
    # concatenated turns (mirrors the Judge worker's behavior).
    transcript_raw = inputs.get("transcript")
    transcript: list[JudgeTranscriptTurn] | None = None
    if isinstance(transcript_raw, list) and transcript_raw:
        transcript = [
            JudgeTranscriptTurn(
                seed_idx=int(t.get("seed_idx", i)),
                user_message=str(t.get("user_message", "")),
                target_response=str(t.get("target_response", "")),
            )
            for i, t in enumerate(transcript_raw)
            if isinstance(t, dict)
        ]
        attack_user_message = "\n\n".join(
            f"[Turn {t.seed_idx}]\n{t.user_message}" for t in transcript
        )
        target_response_text = "\n\n".join(t.target_response for t in transcript)
    else:
        attack_user_message = str(inputs.get("attack_user_message") or "")
        target_response_text = str(inputs.get("target_response_text") or "")

    evidence = gather_evidence(
        category=str(inputs.get("category") or ""),
        attack_payload={
            "user_message": attack_user_message,
            "canary": str(inputs.get("canary") or ""),
        },
        target_response_text=target_response_text,
    )
    (verdict, rationale, ev), _llm = await judge_llm(
        llm=fake,
        category=str(inputs.get("category") or ""),
        attack_user_message=str(inputs.get("attack_user_message") or ""),
        target_response_text=str(inputs.get("target_response_text") or ""),
        evidence=evidence,
        canary=str(inputs.get("canary") or ""),
        transcript=transcript,
    )
    return score(
        case,
        actual_verdict=verdict,
        actual_rationale=rationale,
        actual_evidence=ev,
    )


def run_eval(*, with_fake_llm: bool = False, cases: list[Case] | None = None) -> list[ScoreResult]:
    cases = cases if cases is not None else load_cases("judge")
    results: list[ScoreResult] = []
    for case in cases:
        try:
            if with_fake_llm:
                results.append(asyncio.run(_with_fake_llm(case)))
            else:
                results.append(_evidence_only(case))
        except Exception as e:
            r = ScoreResult(case_id=case.case_id)
            r.error = f"{type(e).__name__}: {e}"
            results.append(r)
    return results


def _print_report(results: list[ScoreResult], *, threshold: float, mode: str) -> int:
    passes = sum(1 for r in results if r.passed)
    total = len(results)
    rate = passes / total if total else 0.0
    print(f"=== judge eval ({mode}) — {total} cases ===")
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
    parser.add_argument(
        "--with-fake-llm",
        action="store_true",
        help="Drive judge_llm with a FakeLLMClient instead of evidence-only.",
    )
    args = parser.parse_args(argv)
    mode = "fake-llm" if args.with_fake_llm else "evidence-only"
    results = run_eval(with_fake_llm=args.with_fake_llm)
    return _print_report(results, threshold=args.threshold, mode=mode)


if __name__ == "__main__":
    sys.exit(main())
