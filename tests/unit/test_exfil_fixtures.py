"""Sanity-check that the exfil ground-truth fixtures are consistent with
the deterministic post-condition.

This is not the Judge-accuracy nightly eval (that lives separately and
needs the live LLM judge). This is a structural contract:

- Every triple labeled ``pass`` must surface a marker through the
  detector — otherwise the fixture is dishonest.
- Every triple labeled ``fail`` or ``partial`` must NOT surface a marker
  through the *deterministic* path — partial is the rubric's qualitative
  call, not the detector's. If the detector finds a marker on a
  fail/partial row, the labels are inconsistent.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cats.categories.exfil.deterministic import check

FIXTURE_PATH = (
    Path(__file__).parent.parent.parent
    / "src"
    / "cats"
    / "categories"
    / "exfil"
    / "fixtures"
    / "ground_truth.jsonl"
)


def _rows() -> list[dict[str, object]]:
    return [json.loads(line) for line in FIXTURE_PATH.read_text().splitlines() if line.strip()]


def test_fixture_file_exists_and_is_non_empty() -> None:
    rows = _rows()
    assert len(rows) >= 10, "exfil fixtures should seed at least 10 triples"


@pytest.mark.parametrize("row", _rows(), ids=lambda r: r["id"])
def test_fixture_row_agrees_with_deterministic_check(row: dict[str, object]) -> None:
    attack = dict(row["attack"])  # type: ignore[arg-type]
    response_text = str(row["response"])
    expected = row["expected_verdict"]

    verdict, _reason, evidence = check(
        attack_payload=attack,
        target_response_text=response_text,
    )

    if expected == "pass":
        assert verdict == "pass", (
            f"{row['id']}: labeled pass but deterministic check returned {verdict!r}; "
            "either the response doesn't actually carry the marker or the detector missed it"
        )
        expected_channel = row.get("expected_channel")
        if expected_channel:
            assert expected_channel in evidence["channels"], (
                f"{row['id']}: labeled channel={expected_channel} but detector "
                f"reported channels={evidence['channels']}"
            )
    else:
        assert verdict == "fail", (
            f"{row['id']}: labeled {expected!r} but deterministic check returned {verdict!r}; "
            "labels and detector disagree"
        )


def test_every_pass_row_has_an_expected_channel() -> None:
    """Every pass row must name the channel so the report can point at the
    exact defense that failed."""
    for row in _rows():
        if row["expected_verdict"] == "pass":
            assert row.get("expected_channel"), f"{row['id']}: pass row missing expected_channel"
