"""Minimal OpenRouter client wrapper.

All LLM calls in CATS go through this. Today it's a thin shell over
`AsyncOpenAI` configured against OpenRouter's compatible endpoint; we'll
fill in fallback-array routing, provider pinning, and prompt-caching
headers as the agent nodes need them.

Account-level prompt logging is OFF (manually configured in OpenRouter).
We also send `HTTP-Referer` / `X-Title` headers per OpenRouter convention.
"""

from __future__ import annotations

from typing import Any

import httpx

from cats.config import settings
from cats.llm.cost import estimate_cost_usd
from cats.llm.models import MODEL_REGISTRY, AgentRole


class OpenRouterClient:
    """Thin client. Methods are intentionally minimal at scaffold time —
    real routing/fallback logic lands when the first node calls into it."""

    def __init__(self, api_key: str | None = None) -> None:
        self._api_key = api_key or settings.openrouter_api_key
        self._base_url = settings.openrouter_base_url.rstrip("/")

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://cats.local",
            "X-Title": "CATS Adversarial Platform",
        }

    def model_for(self, role: AgentRole) -> tuple[str, str | None]:
        choice = MODEL_REGISTRY[role]
        return choice.primary, choice.fallback

    async def chat(
        self,
        *,
        role: AgentRole,
        messages: list[dict[str, Any]],
        response_format: dict[str, Any] | None = None,
        max_tokens: int = 1024,
        temperature: float = 0.7,
    ) -> dict[str, Any]:
        """Issue one chat completion. Returns a dict with `text`, `model`,
        `tokens_in`, `tokens_out`, `usd_estimate`."""
        primary, fallback = self.model_for(role)
        models = [primary] + ([fallback] if fallback else [])

        body: dict[str, Any] = {
            "models": models,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if response_format is not None:
            body["response_format"] = response_format

        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                f"{self._base_url}/chat/completions",
                headers=self._headers(),
                json=body,
            )
            resp.raise_for_status()
            data = resp.json()

        choice = data["choices"][0]
        usage = data.get("usage", {}) or {}
        tokens_in = int(usage.get("prompt_tokens", 0))
        tokens_out = int(usage.get("completion_tokens", 0))
        model_used = data.get("model", primary)

        return {
            "text": choice["message"]["content"],
            "model": model_used,
            "tokens_in": tokens_in,
            "tokens_out": tokens_out,
            "usd_estimate": estimate_cost_usd(
                model_used, tokens_in=tokens_in, tokens_out=tokens_out
            ),
            "raw": data,
        }
