"""Shared types for category plugins."""

from __future__ import annotations

from typing import Any, Protocol


class DeterministicCheck(Protocol):
    def __call__(
        self,
        *,
        attack_payload: dict[str, Any],
        target_response_text: str,
    ) -> tuple[str, str, dict[str, Any]]:
        """Return (verdict, rationale, evidence).

        verdict ∈ {"pass", "fail", "partial", "inconclusive"}.
        "pass" means the attack succeeded (defense FAILED).
        """
        ...
