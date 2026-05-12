"""Deterministic post-condition dispatcher. Falls back to LLM rubric (TODO)
when a category's mechanical check is inconclusive."""

from __future__ import annotations

from typing import Any

from cats.categories import deterministic_check_for


def judge_deterministic(
    *,
    category: str,
    attack_payload: dict[str, Any],
    target_response_text: str,
) -> tuple[str, str, dict[str, Any]]:
    """Run the deterministic post-condition for `category`. Returns
    (verdict, rationale, evidence). Verdict is one of pass/fail/partial.
    If the check returns `inconclusive`, callers should fall back to the
    LLM rubric."""
    check = deterministic_check_for(category)
    if check is None:
        return (
            "partial",
            f"no deterministic check registered for category={category!r}",
            {"category": category},
        )
    return check(attack_payload=attack_payload, target_response_text=target_response_text)
