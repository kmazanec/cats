"""Unit tests for the FakeLLMClient tool-call protocol.

Covers the non-breaking extension to LLMClient.chat: optional ``tools``
parameter, ``tool_calls`` field on LLMResult, the dict-shape responder
contract used to drive multi-turn tool loops in tests, and the
``register_sequence`` helper for stepping through scripted turns.
"""

from __future__ import annotations

from typing import Any

import pytest

from cats.llm.client import FakeLLMClient, ToolCall, ToolSpec

TOOL = ToolSpec(
    name="echo",
    description="Echo the argument back.",
    parameters={
        "type": "object",
        "properties": {"value": {"type": "string"}},
        "required": ["value"],
    },
)


def test_tool_spec_serializes_to_openai_shape() -> None:
    payload = TOOL.to_openai()
    assert payload["type"] == "function"
    assert payload["function"]["name"] == "echo"
    assert payload["function"]["parameters"]["required"] == ["value"]


@pytest.mark.asyncio
async def test_string_responder_back_compat() -> None:
    """Existing callers that register a string-returning responder
    still get an LLMResult with empty tool_calls. No regression."""
    fake = FakeLLMClient()
    fake.register("documentation", lambda _m: "plain text response")
    result = await fake.chat(role="documentation", messages=[{"role": "user", "content": "hi"}])
    assert result.text == "plain text response"
    assert result.tool_calls == ()


@pytest.mark.asyncio
async def test_dict_responder_returns_tool_calls() -> None:
    fake = FakeLLMClient()
    fake.register(
        "documentation",
        lambda _m: {
            "text": "",
            "tool_calls": [{"name": "echo", "arguments": {"value": "hello"}}],
        },
    )
    result = await fake.chat(
        role="documentation",
        messages=[{"role": "user", "content": "x"}],
        tools=[TOOL],
    )
    assert result.text == ""
    assert len(result.tool_calls) == 1
    tc = result.tool_calls[0]
    assert isinstance(tc, ToolCall)
    assert tc.name == "echo"
    assert tc.arguments == {"value": "hello"}
    assert tc.id  # FakeLLMClient mints one when the responder omits it


@pytest.mark.asyncio
async def test_register_sequence_drives_multi_turn_loop() -> None:
    """Tests script tool-loop turns by registering an ordered sequence;
    the Nth chat() call uses the Nth responder."""
    fake = FakeLLMClient()
    turns: list[dict[str, Any]] = [
        {
            "text": "",
            "tool_calls": [{"name": "echo", "arguments": {"value": "first"}, "id": "call-1"}],
        },
        {
            "text": "all done",
            "tool_calls": [],
        },
    ]
    fake.register_sequence("documentation", [lambda _m, t=t: t for t in turns])

    r1 = await fake.chat(
        role="documentation",
        messages=[{"role": "user", "content": "go"}],
        tools=[TOOL],
    )
    assert r1.tool_calls[0].name == "echo"
    assert r1.tool_calls[0].id == "call-1"

    r2 = await fake.chat(
        role="documentation",
        messages=[
            {"role": "user", "content": "go"},
            {"role": "tool", "tool_call_id": "call-1", "content": "first"},
        ],
        tools=[TOOL],
    )
    assert r2.tool_calls == ()
    assert r2.text == "all done"


@pytest.mark.asyncio
async def test_tools_appear_in_call_log() -> None:
    """call_log should record which tools were advertised so tests
    can assert the catalog reached the LLM."""
    fake = FakeLLMClient()
    fake.register("documentation", lambda _m: "ok")
    await fake.chat(
        role="documentation",
        messages=[{"role": "user", "content": "x"}],
        tools=[TOOL],
    )
    last = fake.call_log[-1]
    assert "echo" in last["tools"]


@pytest.mark.asyncio
async def test_chat_costs_account_for_tool_call_output() -> None:
    """Tool-call arguments contribute to tokens_out (otherwise a
    multi-turn loop's cost accounting would massively undershoot
    reality)."""
    fake = FakeLLMClient()
    fake.register(
        "documentation",
        lambda _m: {
            "text": "",
            "tool_calls": [{"name": "echo", "arguments": {"value": "x" * 200}}],
        },
    )
    result = await fake.chat(
        role="documentation",
        messages=[{"role": "user", "content": "x"}],
        tools=[TOOL],
    )
    # The argument has 200 chars; tokens_out should reflect that.
    assert result.tokens_out > 50
