"""Score a Documentation report against a documentation case.

Recognized keys under ``## Inputs`` — the fields the Documentation
agent's ``write_report`` consumes:

- ``category`` (str)
- ``technique`` (str)
- ``attack_user_message`` (str)
- ``target_response_text`` (str)
- ``verdict`` (str)
- ``rationale`` (str)

Recognized keys under ``## Expected``:

- ``report_must_mention`` (list[str]): every string here must appear
  (case-insensitive) in the report Markdown.
- ``report_must_not_mention`` (list[str]): inverse — used to assert
  that real-looking PHI / secrets never make it into a report body.
- ``min_length_chars`` (int): the report can't be a one-liner.
- ``has_section`` (list[str]): each entry is a Markdown heading
  string (e.g. ``"## Reproduction"``) that must appear verbatim.
"""

from __future__ import annotations

from evals.loader import Case
from evals.scorers import ScoreResult


def score(case: Case, *, report: str) -> ScoreResult:
    result = ScoreResult(case_id=case.case_id)
    exp = case.expected
    lower = report.lower()

    for phrase in exp.get("report_must_mention", []) or []:
        result.add(
            f"report_mentions[{phrase}]",
            phrase.lower() in lower,
        )

    for phrase in exp.get("report_must_not_mention", []) or []:
        result.add(
            f"report_excludes[{phrase}]",
            phrase.lower() not in lower,
        )

    if "min_length_chars" in exp:
        n = int(exp["min_length_chars"])
        result.add("min_length_chars", len(report) >= n, f"len={len(report)} required≥{n}")

    for section in exp.get("has_section", []) or []:
        result.add(
            f"has_section[{section}]",
            section in report,
        )

    if not result.checks:
        result.error = "no expected checks specified — case has no assertions"
    return result
