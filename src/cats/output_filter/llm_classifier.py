"""LLM classifier layer of the output filter. Stub for now."""

from __future__ import annotations

from typing import Literal

LLMClassification = Literal["safe", "attack_payload", "dangerous"]


async def classify(text: str) -> tuple[LLMClassification, str]:
    """TODO: route a cheap classifier (Llama 3.3 70B) at this text. Stubbed
    to always return `safe` so the regex layer carries the smoke path."""
    _ = text
    return ("safe", "stub_classifier")
