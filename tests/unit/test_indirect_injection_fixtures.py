"""Sanity-check that indirect-injection fixtures agree with the
deterministic post-condition.

Structural contract — labels and detector cannot drift apart without CI
breaking. Same pattern as tests/unit/test_exfil_fixtures.py.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cats.categories.indirect_injection.deterministic import check

FIXTURE_PATH = (
    Path(__file__).parent.parent.parent
    / "src"
    / "cats"
    / "categories"
    / "indirect_injection"
    / "fixtures"
    / "ground_truth.jsonl"
)


def _rows() -> list[dict[str, object]]:
    return [json.loads(line) for line in FIXTURE_PATH.read_text().splitlines() if line.strip()]


def test_fixture_file_exists_and_is_non_empty() -> None:
    rows = _rows()
    assert len(rows) >= 10, "indirect_injection fixtures should seed at least 10 triples"


@pytest.mark.parametrize("row", _rows(), ids=lambda r: r["id"])
def test_fixture_row_agrees_with_deterministic_check(row: dict[str, object]) -> None:
    attack = dict(row["attack"])  # type: ignore[arg-type]
    response = str(row["response"])
    expected = row["expected_verdict"]

    verdict, _reason, _evidence = check(
        attack_payload=attack,
        target_response_text=response,
    )

    if expected == "pass":
        assert verdict == "pass", (
            f"{row['id']}: labeled pass but deterministic check returned {verdict!r}"
        )
    elif expected == "fail":
        assert verdict == "fail", (
            f"{row['id']}: labeled fail but deterministic check returned {verdict!r}"
        )
    elif expected == "partial":
        # Partials are the rubric's qualitative call, not deterministic.
        # The deterministic check can rule either way:
        # - canary in refusal text → deterministic says pass; rubric demotes to partial.
        # - paraphrased instruction without canary → deterministic says fail; rubric promotes to partial.
        # Both are valid for a row labeled `partial`.
        assert verdict in {"pass", "fail"}, (
            f"{row['id']}: deterministic verdict={verdict!r} unexpected for partial row"
        )
    else:
        raise AssertionError(f"{row['id']}: unknown expected_verdict {expected!r}")


def test_every_row_carries_a_technique() -> None:
    """Every row must name the technique so taxonomy.lookup() can attach
    the right ATLAS / OWASP label to a finding."""
    for row in _rows():
        attack = row["attack"]
        assert isinstance(attack, dict)
        technique = attack.get("technique")
        assert technique, f"{row['id']}: missing technique"
