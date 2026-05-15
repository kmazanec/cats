"""Schema-shape gate for the optional eval-case fields on ground-truth
fixtures.

Every category may add four optional per-row fields used by coverage
dashboards, regression-sweep reporting, and the campaign-detail UI:

- ``severity``        ∈ {info, low, medium, high, critical}
- ``exploitability``  ∈ {confirmed, plausible, theoretical}
- ``regression_flag`` ∈ {bool}
- ``owasp_llm_id``    ∈ a known OWASP-LLM-Top-10 (2025) ID

The fields are optional — legacy rows without them must still pass.
This test only fails if a row has the field but the value is outside
the allowed set, which would silently break the coverage UI.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

CATEGORIES = [
    "injection",
    "indirect_injection",
    "exfil",
    "tool_abuse",
    "clinical_misinformation",
    "xss",
    "dos_cost",
]

_REPO_ROOT = Path(__file__).parent.parent.parent
_FIXTURES = {
    cat: _REPO_ROOT / "src" / "cats" / "categories" / cat / "fixtures" / "ground_truth.jsonl"
    for cat in CATEGORIES
}

ALLOWED_SEVERITY = {"info", "low", "medium", "high", "critical"}
ALLOWED_EXPLOITABILITY = {"confirmed", "plausible", "theoretical"}
ALLOWED_OWASP = {f"LLM{n:02d}" for n in range(1, 11)}


def _rows(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]


@pytest.mark.parametrize("category", CATEGORIES)
def test_eval_fields_well_typed(category: str) -> None:
    rows = _rows(_FIXTURES[category])
    for row in rows:
        rid = row.get("id", "<unidentified>")

        if "severity" in row:
            assert row["severity"] in ALLOWED_SEVERITY, (
                f"{category}:{rid} severity={row['severity']!r} not in {sorted(ALLOWED_SEVERITY)}"
            )
        if "exploitability" in row:
            assert row["exploitability"] in ALLOWED_EXPLOITABILITY, (
                f"{category}:{rid} exploitability={row['exploitability']!r} "
                f"not in {sorted(ALLOWED_EXPLOITABILITY)}"
            )
        if "regression_flag" in row:
            assert isinstance(row["regression_flag"], bool), (
                f"{category}:{rid} regression_flag must be bool, "
                f"got {type(row['regression_flag']).__name__}"
            )
        if "owasp_llm_id" in row:
            assert row["owasp_llm_id"] in ALLOWED_OWASP, (
                f"{category}:{rid} owasp_llm_id={row['owasp_llm_id']!r} "
                f"not in {sorted(ALLOWED_OWASP)}"
            )
