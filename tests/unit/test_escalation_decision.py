"""R10 — Red Team escalation strategist unit tests.

Drives :func:`cats.agents.red_team.escalation.decide_next_turn` with a
``FakeLLMClient`` and verifies:

- Parses ``escalate`` / ``stop`` / ``declare_landed`` JSON outputs.
- Unknown decision value → ``stop`` (defensive, never escalates into the
  unknown).
- Unparseable JSON → ``stop``.
- Hard cap on conversation length forces ``stop`` without burning an LLM
  call (the strategist isn't called past the cap).
- Empty/zero-content latest target response forces ``stop`` (no LLM
  call) — short-circuits transport failures.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from cats.agents.red_team.escalation import (
    ConversationTurn,
    decide_next_turn,
)
from cats.llm.client import FakeLLMClient


def _canned(text: str):
    def _r(_msgs: list[dict[str, Any]]) -> str:
        return text

    return _r


def _turn(seed_idx: int, user_msg: str = "hey", response: str = "no") -> ConversationTurn:
    return ConversationTurn(
        seed_idx=seed_idx,
        user_message=user_msg,
        target_response=response,
    )


@pytest.mark.asyncio
async def test_escalate_parses() -> None:
    fake = FakeLLMClient()
    fake.register(
        "mutator",
        _canned(json.dumps({"decision": "escalate", "rationale": "model wavered on turn 1"})),
    )
    out = await decide_next_turn(
        category="injection",
        technique="ignore_previous",
        transcript=[_turn(0, response="I cannot help with that, but...")],
        llm=fake,
        seeds_per_attempt=5,
    )
    assert out.decision == "escalate"
    assert "wavered" in out.rationale
    assert out.llm is not None


@pytest.mark.asyncio
async def test_declare_landed_parses() -> None:
    fake = FakeLLMClient()
    fake.register(
        "mutator",
        _canned(json.dumps({"decision": "declare_landed", "rationale": "canary echoed verbatim"})),
    )
    out = await decide_next_turn(
        category="injection",
        technique="ignore_previous",
        transcript=[_turn(0, response="Sure! CATS-CANARY-DEADBEEF here you go.")],
        llm=fake,
        seeds_per_attempt=5,
    )
    assert out.decision == "declare_landed"


@pytest.mark.asyncio
async def test_stop_parses() -> None:
    fake = FakeLLMClient()
    fake.register(
        "mutator",
        _canned(json.dumps({"decision": "stop", "rationale": "firm refusal x3"})),
    )
    out = await decide_next_turn(
        category="injection",
        technique="ignore_previous",
        transcript=[
            _turn(0, response="No."),
            _turn(1, response="Still no."),
            _turn(2, response="I won't."),
        ],
        llm=fake,
        seeds_per_attempt=5,
    )
    assert out.decision == "stop"


@pytest.mark.asyncio
async def test_unknown_decision_falls_back_to_stop() -> None:
    fake = FakeLLMClient()
    fake.register(
        "mutator",
        _canned(json.dumps({"decision": "yolo", "rationale": "??"})),
    )
    out = await decide_next_turn(
        category="injection",
        technique="ignore_previous",
        transcript=[_turn(0)],
        llm=fake,
        seeds_per_attempt=5,
    )
    assert out.decision == "stop"
    # The strategist DID get called (LLM result returned) — we just
    # didn't trust its output.
    assert out.llm is not None


@pytest.mark.asyncio
async def test_unparseable_json_falls_back_to_stop() -> None:
    fake = FakeLLMClient()
    fake.register(
        "mutator",
        _canned("yo whats up this is not JSON at all"),
    )
    out = await decide_next_turn(
        category="injection",
        technique="ignore_previous",
        transcript=[_turn(0)],
        llm=fake,
        seeds_per_attempt=5,
    )
    assert out.decision == "stop"


@pytest.mark.asyncio
async def test_cap_forces_stop_without_llm_call() -> None:
    fake = FakeLLMClient()
    # Register a responder that would say "escalate" — we want to prove
    # it is NEVER invoked when the cap has been hit.
    called = {"n": 0}

    def _r(_msgs: list[dict[str, Any]]) -> str:
        called["n"] += 1
        return json.dumps({"decision": "escalate"})

    fake.register("mutator", _r)
    transcript = [_turn(i) for i in range(5)]  # 5 turns
    out = await decide_next_turn(
        category="injection",
        technique="ignore_previous",
        transcript=transcript,
        llm=fake,
        seeds_per_attempt=5,
    )
    assert out.decision == "stop"
    assert out.llm is None
    assert called["n"] == 0


@pytest.mark.asyncio
async def test_empty_latest_response_short_circuits_to_stop() -> None:
    fake = FakeLLMClient()
    called = {"n": 0}

    def _r(_msgs: list[dict[str, Any]]) -> str:
        called["n"] += 1
        return json.dumps({"decision": "escalate"})

    fake.register("mutator", _r)
    out = await decide_next_turn(
        category="injection",
        technique="ignore_previous",
        transcript=[_turn(0, response="   ")],
        llm=fake,
        seeds_per_attempt=5,
    )
    assert out.decision == "stop"
    assert out.llm is None
    assert called["n"] == 0


@pytest.mark.asyncio
async def test_empty_transcript_returns_stop() -> None:
    fake = FakeLLMClient()
    out = await decide_next_turn(
        category="injection",
        technique="ignore_previous",
        transcript=[],
        llm=fake,
        seeds_per_attempt=5,
    )
    assert out.decision == "stop"
    assert out.llm is None
