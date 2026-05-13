"""LLM client protocol + factory.

All agent code depends on `LLMClient` (a Protocol), not the concrete
`OpenRouterClient`. Tests inject `FakeLLMClient`. Production wires the
real client.

`get_llm()` returns the FakeLLMClient when OPENROUTER_API_KEY is unset
or marked as a test stub — keeps `make test` fast and offline, and
makes `cats run-campaign` against the real Co-Pilot only work when keys
are actually configured.

## Tool use

The protocol supports OpenAI/OpenRouter-style function-calling. Pass
``tools=[ToolSpec(...)]`` to ``chat`` to advertise the catalog; the
returned ``LLMResult.tool_calls`` lists any function invocations the
model wants. The caller runs them, appends one ``{"role":"tool", ...}``
message per call to the conversation, and invokes ``chat`` again. Loop
until ``tool_calls`` is empty or a caller-imposed turn limit trips.
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
class ToolSpec:
    """One function the LLM may call. ``parameters`` is a JSON Schema
    describing the function's arguments. Keep it tight — sloppy schemas
    waste tokens and confuse the model."""

    name: str
    description: str
    parameters: dict[str, Any]

    def to_openai(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


@dataclass(frozen=True)
class ToolCall:
    """One function invocation the model emitted in its response."""

    id: str
    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class LLMResult:
    """Normalized response shape every client returns.

    ``tool_calls`` is non-empty when the model chose to call one or
    more functions instead of (or alongside) emitting text. ``text``
    is the assistant's plain-text content; it may be empty when the
    model emitted only tool calls."""

    text: str
    model: str
    tokens_in: int
    tokens_out: int
    usd_estimate: float
    trace_id: str = ""
    tool_calls: tuple[ToolCall, ...] = ()


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
        tools: list[ToolSpec] | None = None,
        tool_choice: str | None = None,
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
        tools: list[ToolSpec] | None = None,
        tool_choice: str | None = None,
    ) -> LLMResult:
        raw = await self._under.chat(
            role=role,
            messages=messages,
            response_format=response_format,
            max_tokens=max_tokens,
            temperature=temperature,
            tools=[t.to_openai() for t in tools] if tools else None,
            tool_choice=tool_choice,
        )
        return LLMResult(
            text=str(raw.get("text") or ""),
            model=str(raw["model"]),
            tokens_in=int(raw["tokens_in"]),
            tokens_out=int(raw["tokens_out"]),
            usd_estimate=float(raw["usd_estimate"]),
            trace_id=_trace_id(),
            tool_calls=_parse_tool_calls(raw.get("tool_calls") or []),
        )


def _parse_tool_calls(raw: list[dict[str, Any]]) -> tuple[ToolCall, ...]:
    """Convert OpenAI-shape tool_calls (each with ``function.arguments``
    as a JSON string) into our ``ToolCall`` triples. Malformed arguments
    surface as an empty dict — the caller decides whether to treat that
    as an error or a no-op."""
    out: list[ToolCall] = []
    for tc in raw:
        fn = tc.get("function") or {}
        name = str(fn.get("name") or "")
        if not name:
            continue
        raw_args = fn.get("arguments")
        args: dict[str, Any] = {}
        if isinstance(raw_args, str) and raw_args:
            try:
                parsed = json.loads(raw_args)
                if isinstance(parsed, dict):
                    args = parsed
            except json.JSONDecodeError:
                args = {}
        elif isinstance(raw_args, dict):
            args = raw_args
        out.append(
            ToolCall(
                id=str(tc.get("id") or uuid.uuid4()),
                name=name,
                arguments=args,
            )
        )
    return tuple(out)


# A FakeLLMClient responder is either a string (legacy plain-text response)
# or a dict carrying optional ``text`` + ``tool_calls`` keys (for tool-loop
# tests). Both shapes are mapped onto LLMResult.
FakeResponse = str | dict[str, Any]
FakeResponder = Callable[[list[dict[str, Any]]], FakeResponse]


@dataclass
class FakeLLMClient:
    """Deterministic client for tests. Returns canned responses keyed by
    role. Routes can register a per-role responder; the default emits a
    plausible-shape JSON for the role.

    A responder returns either:

    - A plain string (no tool calls; the string becomes ``text``).
    - A dict ``{"text": str, "tool_calls": [{"name", "arguments", "id"?}]}``
      to drive the tool-loop branches. Tests step through tool turns by
      registering a *sequence* of responders via ``register_sequence``.

    Token counts are derived from string lengths so cost math still moves.
    """

    responders: dict[AgentRole, FakeResponder] = field(default_factory=dict)
    sequences: dict[AgentRole, list[FakeResponder]] = field(default_factory=dict)
    call_log: list[dict[str, Any]] = field(default_factory=list)

    def register(self, role: AgentRole, fn: FakeResponder) -> None:
        self.responders[role] = fn

    def register_sequence(self, role: AgentRole, fns: list[FakeResponder]) -> None:
        """Register an ordered list of responders for ``role``. The Nth
        ``chat(role=...)`` call uses the Nth responder. Used to script
        tool-loop turns deterministically."""
        self.sequences[role] = list(fns)

    async def chat(
        self,
        *,
        role: AgentRole,
        messages: list[dict[str, Any]],
        response_format: dict[str, Any] | None = None,
        max_tokens: int = 1024,
        temperature: float = 0.7,
        tools: list[ToolSpec] | None = None,
        tool_choice: str | None = None,
    ) -> LLMResult:
        _ = (response_format, max_tokens, temperature, tool_choice)
        seq = self.sequences.get(role)
        responder = seq.pop(0) if seq else self.responders.get(role, _default_response_for)
        raw_response = responder(messages)

        text: str
        tool_calls: tuple[ToolCall, ...]
        if isinstance(raw_response, dict):
            text = str(raw_response.get("text") or "")
            tc_specs = raw_response.get("tool_calls") or []
            tool_calls = tuple(
                ToolCall(
                    id=str(tc.get("id") or f"call-{uuid.uuid4().hex[:8]}"),
                    name=str(tc["name"]),
                    arguments=tc.get("arguments") or {},
                )
                for tc in tc_specs
                if isinstance(tc, dict) and tc.get("name")
            )
        else:
            text = str(raw_response)
            tool_calls = ()

        # Best-effort token estimate from prompt + response sizes.
        prompt_chars = sum(len(str(m.get("content", ""))) for m in messages)
        # Tool spec characters count toward prompt budget so the test
        # accounting reflects the real cost shape.
        if tools:
            prompt_chars += sum(len(t.name) + len(t.description) for t in tools)
        tokens_in = max(1, prompt_chars // 4)
        out_chars = len(text) + sum(len(json.dumps(tc.arguments)) for tc in tool_calls)
        tokens_out = max(1, out_chars // 4)
        model = MODEL_REGISTRY[role].primary
        self.call_log.append(
            {
                "role": role,
                "messages": messages,
                "tools": [t.name for t in tools] if tools else [],
                "text": text,
                "tool_calls": [
                    {"id": tc.id, "name": tc.name, "arguments": tc.arguments} for tc in tool_calls
                ],
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
            tool_calls=tool_calls,
        )


def _default_response_for(messages: list[dict[str, Any]]) -> FakeResponse:
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
