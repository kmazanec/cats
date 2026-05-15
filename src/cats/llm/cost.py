"""Token-to-USD cost estimator. Prices from W3_ARCHITECTURE.md §1.5 (May 2026).

Prices are per 1M tokens (input / output). Costs are estimates; the truth
is whatever OpenRouter bills, which lands in the AttackExecution row when
the client returns a real usage object.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ModelPrice:
    input_per_1m: float
    output_per_1m: float


# Best-effort lookup. Unknown models default to a conservative mid-tier price.
# Prices verified against OpenRouter pricing pages on 2026-05-14; see
# docs/COST_ANALYSIS.md §3 for the verification table and provenance.
PRICE_TABLE: dict[str, ModelPrice] = {
    "anthropic/claude-haiku-4.5": ModelPrice(1.00, 5.00),
    "anthropic/claude-sonnet-4.5": ModelPrice(3.00, 15.00),
    "openai/gpt-5": ModelPrice(1.25, 10.00),
    "openai/gpt-5-mini": ModelPrice(0.25, 2.00),
    "google/gemini-2.5-flash": ModelPrice(0.30, 2.50),
    "deepseek/deepseek-chat": ModelPrice(0.32, 0.89),
    "deepseek/deepseek-chat-v3": ModelPrice(0.32, 0.89),
    "meta-llama/llama-3.3-70b-instruct": ModelPrice(0.10, 0.32),
    "nousresearch/hermes-4-405b": ModelPrice(1.00, 3.00),
    "cognitivecomputations/dolphin-mistral-24b-venice-edition": ModelPrice(0.0, 0.0),
    "cognitivecomputations/dolphin-mistral-24b-venice-edition:free": ModelPrice(0.0, 0.0),
    "qwen/qwen-2.5-72b-instruct": ModelPrice(0.36, 0.40),
}

_DEFAULT = ModelPrice(2.00, 10.00)


def estimate_cost_usd(model: str, *, tokens_in: int, tokens_out: int) -> float:
    price = PRICE_TABLE.get(model, _DEFAULT)
    return (tokens_in / 1_000_000) * price.input_per_1m + (
        tokens_out / 1_000_000
    ) * price.output_per_1m
