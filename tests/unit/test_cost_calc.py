from __future__ import annotations

import pytest

from cats.llm.cost import estimate_cost_usd


def test_estimate_cost_known_model() -> None:
    # Haiku 4.5: $1.00 / $5.00 per 1M
    cost = estimate_cost_usd(
        "anthropic/claude-haiku-4.5", tokens_in=1_000_000, tokens_out=1_000_000
    )
    assert cost == pytest.approx(6.0)


def test_estimate_cost_unknown_model_uses_default() -> None:
    cost = estimate_cost_usd("brand-new/model", tokens_in=1_000_000, tokens_out=1_000_000)
    assert cost == pytest.approx(12.0)  # default $2.00 + $10.00


def test_estimate_cost_zero_tokens_is_zero() -> None:
    assert estimate_cost_usd("anthropic/claude-haiku-4.5", tokens_in=0, tokens_out=0) == 0.0
