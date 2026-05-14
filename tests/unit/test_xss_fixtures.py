"""Sanity-check the XSS ground-truth fixtures against the deterministic
post-condition.

Structural CI gate, not Judge-accuracy. Enforces:

- Every ``pass`` row makes the deterministic check return ``pass``
  (scanner fires + no refutation).
- Every ``fail`` row makes the deterministic check return ``fail``
  (refutation cue fires).
- Every ``partial`` row makes the deterministic check return
  ``inconclusive`` — ``partial`` is the LLM rubric's call; if the
  scanner returns ``pass`` or ``fail`` on a partial row, the fixture
  and detector disagree and the fixture needs revision.

The bar for "≥90% Judge accuracy" in the R12 rubric lives on the
live LLM rubric, not on this structural file.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from cats.categories.xss.deterministic import check

FIXTURE_PATH = (
    Path(__file__).parent.parent.parent
    / "src"
    / "cats"
    / "categories"
    / "xss"
    / "fixtures"
    / "ground_truth.jsonl"
)


def _rows() -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in FIXTURE_PATH.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]


_EXPECTED_DETERMINISTIC = {
    "pass": "pass",
    "fail": "fail",
    "partial": "inconclusive",
}


def test_fixture_file_has_coverage_floor() -> None:
    rows = _rows()
    assert len(rows) >= 15, f"xss fixtures should seed at least 15 triples, got {len(rows)}"


def test_fixtures_cover_all_six_techniques() -> None:
    """Every shipped technique must have at least one fixture."""
    techniques = {row["attack"]["technique"] for row in _rows()}
    assert techniques == {
        "script_tag",
        "img_onerror",
        "javascript_url",
        "event_handler",
        "markdown_parser_break",
        "html_entity_smuggling",
    }, f"technique coverage mismatch: {techniques}"


def test_fixtures_have_verdict_mix() -> None:
    """Without a verdict mix, a degenerate 'always pass' or 'always
    fail' judge would clear the threshold."""
    verdicts = [row["expected_verdict"] for row in _rows()]
    assert verdicts.count("pass") >= 6, "need ≥6 pass rows"
    assert verdicts.count("fail") >= 4, "need ≥4 fail rows"
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
        f"{row['id']}: labeled expected_verdict={expected!r} (deterministic should "
        f"be {expected_det!r}) but check returned {verdict!r}. Reason: {reason}."
    )


def test_every_pass_row_has_an_expected_family() -> None:
    """Pass rows must name the expected family so the finding signature
    is reproducible."""
    for row in _rows():
        if row["expected_verdict"] == "pass":
            assert row.get("expected_family"), (
                f"{row['id']}: pass row missing expected_family field"
            )
