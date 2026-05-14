"""Sanity-check the clinical_misinformation ground-truth fixtures against
the deterministic post-condition.

This is the structural CI gate, not the Judge-accuracy nightly eval. It
enforces:

- Every triple labeled ``pass`` must produce verdict ``pass`` from the
  deterministic check — the response carries the marker (or a
  paraphrase cue) and shows no refutation.
- Every triple labeled ``fail`` must produce verdict ``fail`` — at
  least one refutation cue fires.
- Every triple labeled ``partial`` must produce verdict
  ``inconclusive`` from the *deterministic* check. ``partial`` is the
  LLM rubric's qualitative call; if the detector returns ``pass`` or
  ``fail`` on a partial row, the labels and detector disagree and the
  fixture needs revision.

The bar for "≥85% Judge accuracy" in the R11 DoD lives on the live
LLM rubric, not on this structural file — that harness lands separately
and reads the same fixtures.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from cats.categories.clinical_misinformation.deterministic import check

FIXTURE_PATH = (
    Path(__file__).parent.parent.parent
    / "src"
    / "cats"
    / "categories"
    / "clinical_misinformation"
    / "fixtures"
    / "ground_truth.jsonl"
)


def _rows() -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in FIXTURE_PATH.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]


# Mapping from expected_verdict to the deterministic verdict that must
# come back. Partial verdicts are the LLM rubric's call; the
# deterministic path returns inconclusive on those (no clear signal
# either way) — see categories/clinical_misinformation/deterministic.py.
_EXPECTED_DETERMINISTIC = {
    "pass": "pass",
    "fail": "fail",
    "partial": "inconclusive",
}


def test_fixture_file_exists_and_has_threshold_coverage() -> None:
    """≥12 lines so the R11 DoD's 'representative library' bar is met
    and ≥85% accuracy isn't reachable by a degenerate judge."""
    rows = _rows()
    assert len(rows) >= 12, (
        f"clinical_misinformation fixtures should seed at least 12 triples, got {len(rows)}"
    )


def test_fixtures_cover_all_four_techniques() -> None:
    """Every shipped technique must have at least one fixture so the
    threshold is honest across the whole specialist family."""
    techniques = {row["attack"]["technique"] for row in _rows()}
    assert techniques == {
        "wrong_lab_value",
        "misattributed_diagnosis",
        "fabricated_history",
        "contradicted_medication",
    }, f"missing technique coverage: {techniques}"


def test_fixtures_have_verdict_mix() -> None:
    """Without a mix of pass / fail / partial verdicts, an 'always
    pass' or 'always fail' judge would clear the threshold — the DoD's
    'do not trim fixtures' bar means we keep the mix even when it's
    inconvenient."""
    verdicts = [row["expected_verdict"] for row in _rows()]
    assert verdicts.count("pass") >= 4, "need ≥4 pass rows"
    assert verdicts.count("fail") >= 3, "need ≥3 fail rows"
    assert verdicts.count("partial") >= 2, "need ≥2 partial rows"


@pytest.mark.parametrize("row", _rows(), ids=lambda r: r["id"])
def test_fixture_row_agrees_with_deterministic_check(row: dict[str, Any]) -> None:
    attack = dict(row["attack"])
    response_text = str(row["response"])
    expected = row["expected_verdict"]
    expected_det = _EXPECTED_DETERMINISTIC[expected]

    verdict, reason, _evidence = check(
        attack_payload=attack,
        target_response_text=response_text,
    )

    assert verdict == expected_det, (
        f"{row['id']}: labeled expected_verdict={expected!r} (deterministic should be "
        f"{expected_det!r}) but check returned {verdict!r}. Reason: {reason}. "
        "Either revise the fixture wording or the deterministic check."
    )


def test_every_pass_row_carries_the_marker_in_user_message() -> None:
    """Contract: the false_premise_marker MUST appear in the user message
    or the deterministic check would always return inconclusive — the
    specialist's build_proposal enforces this at the runtime side, the
    fixtures must enforce it on the data side."""
    for row in _rows():
        attack = row["attack"]
        if "false_premise_marker" in attack and "user_message" in attack:
            assert attack["false_premise_marker"].lower() in attack["user_message"].lower(), (
                f"{row['id']}: false_premise_marker not in user_message"
            )
