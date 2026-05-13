"""Sanity-check that the tool_abuse ground-truth fixtures are consistent
with the deterministic post-condition.

This is not the Judge-accuracy nightly eval — that lives separately and
needs the live LLM judge. This is a structural contract:

- Every ``pass`` row must trigger the deterministic check (``pass``
  verdict), either because an explicit ``observed_*`` override flags
  out-of-baseline content or because the response text carries cues
  the scanner catches.
- ``fail`` rows must produce ``fail`` (observations present, all inside
  baseline).
- ``partial`` rows are the rubric's qualitative call; the deterministic
  check must NOT return ``pass`` on them.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from cats.categories.tool_abuse.deterministic import check

FIXTURE_PATH = (
    Path(__file__).parent.parent.parent
    / "src"
    / "cats"
    / "categories"
    / "tool_abuse"
    / "fixtures"
    / "ground_truth.jsonl"
)


def _rows() -> list[dict[str, Any]]:
    return [json.loads(line) for line in FIXTURE_PATH.read_text().splitlines() if line.strip()]


def test_fixture_file_exists_and_is_non_empty() -> None:
    rows = _rows()
    assert len(rows) >= 10, "tool_abuse fixtures should seed at least 10 triples"


@pytest.mark.parametrize("row", _rows(), ids=lambda r: r["id"])
def test_fixture_row_agrees_with_deterministic_check(row: dict[str, Any]) -> None:
    attack = dict(row["attack"])
    response_text = str(row["response"])
    expected = row["expected_verdict"]

    verdict, _reason, _ev = check(
        attack_payload=attack,
        target_response_text=response_text,
    )

    if expected == "pass":
        assert verdict == "pass", (
            f"{row['id']}: labeled pass but deterministic check returned "
            f"{verdict!r}. Either the response doesn't carry over-reach "
            "cues or the override is missing."
        )
    elif expected == "fail":
        assert verdict == "fail", (
            f"{row['id']}: labeled fail but deterministic check returned "
            f"{verdict!r}. Labels and check disagree."
        )
    else:  # partial
        assert verdict != "pass", (
            f"{row['id']}: labeled partial but deterministic check returned "
            "pass. Partial rows are the rubric's qualitative call — the "
            "check should NOT short-circuit them to pass."
        )


def test_every_pass_row_carries_clear_evidence() -> None:
    """Every pass row's evidence should name the specific tool or area
    that's outside the baseline — that's the finding's pointer."""
    for row in _rows():
        if row["expected_verdict"] != "pass":
            continue
        _v, _r, ev = check(
            attack_payload=dict(row["attack"]),
            target_response_text=str(row["response"]),
        )
        flagged = ev.get("tools_out_of_baseline", []) + ev.get("areas_out_of_baseline", [])
        assert flagged, (
            f"{row['id']}: pass verdict but evidence has no flagged "
            "tools/areas — finding wouldn't have a pointer."
        )


def test_fixture_techniques_are_all_known() -> None:
    """The fixture file should not test techniques the dispatcher
    doesn't ship — drift between the two is a tripwire we want to catch
    in the unit suite."""
    from cats.agents.red_team.tool_abuse.dispatcher import KNOWN_TECHNIQUES

    for row in _rows():
        technique = row["attack"]["technique"]
        assert technique in KNOWN_TECHNIQUES, (
            f"{row['id']}: technique {technique!r} not in dispatcher's "
            f"KNOWN_TECHNIQUES={sorted(KNOWN_TECHNIQUES)}"
        )
