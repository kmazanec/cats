"""LLM client protocol + factory.

All agent code depends on `LLMClient` (a Protocol), not the concrete
`OpenRouterClient`. Tests inject `FakeLLMClient`. Production wires the
real client.

`get_llm()` returns the FakeLLMClient when OPENROUTER_API_KEY is unset
or marked as a test stub — keeps `make test` fast and offline, and
makes `cats run-campaign` against the real Co-Pilot only work when keys
are actually configured.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from cats.config import settings
from cats.llm.cost import estimate_cost_usd
from cats.llm.models import MODEL_REGISTRY, AgentRole
from cats.llm.openrouter import OpenRouterClient


@dataclass(frozen=True)
class LLMResult:
    """Normalized response shape every client returns."""

    text: str
    model: str
    tokens_in: int
    tokens_out: int
    usd_estimate: float
    trace_id: str = ""


@runtime_checkable
class LLMClient(Protocol):
    """Common interface for real + fake LLM clients."""

    async def chat(
        self,
        *,
        role: AgentRole,
        messages: list[dict[str, Any]],
        response_format: dict[str, Any] | None = None,
        max_tokens: int = 1024,
        temperature: float = 0.7,
    ) -> LLMResult: ...


def _trace_id() -> str:
    """A per-call trace id. Real LangSmith ids are minted by LangSmith
    itself when tracing is on; otherwise we mint a synthetic one so the
    AttackExecution row always has *something* to point at."""
    if settings.langsmith_tracing and settings.langsmith_api_key:
        try:
            from langsmith.run_helpers import get_current_run_tree

            tree = get_current_run_tree()
            if tree is not None and tree.id:
                return str(tree.id)
        except Exception:
            pass
    return str(uuid.uuid4())


class RealLLMClient:
    """Production client. Thin shim that hands off to OpenRouterClient
    and normalizes the return into an `LLMResult`."""

    def __init__(self) -> None:
        self._under = OpenRouterClient()

    async def chat(
        self,
        *,
        role: AgentRole,
        messages: list[dict[str, Any]],
        response_format: dict[str, Any] | None = None,
        max_tokens: int = 1024,
        temperature: float = 0.7,
    ) -> LLMResult:
        raw = await self._under.chat(
            role=role,
            messages=messages,
            response_format=response_format,
            max_tokens=max_tokens,
            temperature=temperature,
        )
        return LLMResult(
            text=str(raw["text"]),
            model=str(raw["model"]),
            tokens_in=int(raw["tokens_in"]),
            tokens_out=int(raw["tokens_out"]),
            usd_estimate=float(raw["usd_estimate"]),
            trace_id=_trace_id(),
        )


@dataclass
class FakeLLMClient:
    """Deterministic client for tests. Returns canned responses keyed by
    role. Routes can register a per-role responder; the default emits a
    plausible-shape JSON for the role.

    Token counts are derived from string lengths so cost math still moves.
    """

    responders: dict[AgentRole, Callable[[list[dict[str, Any]]], str]] = field(default_factory=dict)
    call_log: list[dict[str, Any]] = field(default_factory=list)

    def register(self, role: AgentRole, fn: Callable[[list[dict[str, Any]]], str]) -> None:
        self.responders[role] = fn

    async def chat(
        self,
        *,
        role: AgentRole,
        messages: list[dict[str, Any]],
        response_format: dict[str, Any] | None = None,
        max_tokens: int = 1024,
        temperature: float = 0.7,
    ) -> LLMResult:
        _ = (response_format, max_tokens, temperature)
        responder = self.responders.get(role, _default_response_for)
        text = responder(messages)
        # Best-effort token estimate from prompt + response sizes.
        prompt_chars = sum(len(str(m.get("content", ""))) for m in messages)
        tokens_in = max(1, prompt_chars // 4)
        tokens_out = max(1, len(text) // 4)
        model = MODEL_REGISTRY[role].primary
        self.call_log.append(
            {
                "role": role,
                "messages": messages,
                "text": text,
                "model": model,
            }
        )
        return LLMResult(
            text=text,
            model=model,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            usd_estimate=estimate_cost_usd(model, tokens_in=tokens_in, tokens_out=tokens_out),
            trace_id=f"fake-trace-{uuid.uuid4()}",
        )


def _default_response_for(messages: list[dict[str, Any]]) -> str:
    """Best-guess plausible response per role. Specialist tests should
    register their own canned responders rather than relying on this."""
    _ = messages
    return json.dumps({"text": "FAKE-LLM-RESPONSE", "ok": True})


def get_llm() -> LLMClient:
    """Factory. Returns the real client when an OpenRouter key is set,
    fake otherwise. The test conftest force-installs a FakeLLMClient via
    monkeypatch on `cats.llm.client._OVERRIDE`."""
    if _OVERRIDE is not None:
        return _OVERRIDE
    if settings.openrouter_api_key and not settings.openrouter_api_key.startswith("test-"):
        return RealLLMClient()
    return FakeLLMClient()


_OVERRIDE: LLMClient | None = None


def install_override(client: LLMClient | None) -> None:
    """Test seam. Pass a FakeLLMClient (or any LLMClient) to make every
    `get_llm()` call return it; pass `None` to clear."""
    global _OVERRIDE
    _OVERRIDE = client
