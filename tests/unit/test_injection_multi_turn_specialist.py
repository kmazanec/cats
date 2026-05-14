"""R10 — injection specialist sees prior target responses on follow-up turns.

When the worker passes ``prior_target_responses`` alongside
``prior_user_messages``, the specialist's user-prompt switches to the
multi-turn framing: it shows the attacker / assistant transcript and
asks the model to REACT to the latest target response rather than just
"produce a different angle."

These tests stub the LLM and inspect the prompt the specialist sends.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from cats.agents.red_team.injection import propose_technique
from cats.llm.client import FakeLLMClient


def _capture_and_canned(captured: dict[str, Any], parsed: dict[str, Any]):
    def _r(msgs: list[dict[str, Any]]) -> str:
        captured["user"] = msgs[-1]["content"]
        return json.dumps(parsed)

    return _r


_PARSED = {
    "title": "T",
    "description": "D",
    "technique": "ignore_previous",
    "user_message": "next turn references the prior response, plus {{CANARY}}.",
}


@pytest.mark.asyncio
async def test_multi_turn_prompt_includes_transcript_block() -> None:
    fake = FakeLLMClient()
    captured: dict[str, Any] = {}
    fake.register("redteam_injection", _capture_and_canned(captured, _PARSED))
    await propose_technique(
        technique="ignore_previous",
        llm=fake,
        seed_idx=1,
        prior_user_messages=["turn 0 attacker prompt"],
        prior_target_responses=["turn 0 assistant: I cannot help with that, but..."],
    )
    user_prompt = captured["user"]
    assert "multi-turn conversation" in user_prompt
    assert "Turn 0 attacker:" in user_prompt
    assert "Turn 0 assistant:" in user_prompt
    assert "REACT" in user_prompt


@pytest.mark.asyncio
async def test_single_turn_prompt_uses_diversity_framing() -> None:
    """Without prior_target_responses the specialist falls back to the
    R3-era "produce a materially different angle" framing — that path
    must still work for single-turn callers."""
    fake = FakeLLMClient()
    captured: dict[str, Any] = {}
    fake.register("redteam_injection", _capture_and_canned(captured, _PARSED))
    await propose_technique(
        technique="ignore_previous",
        llm=fake,
        seed_idx=1,
        prior_user_messages=["turn 0 attacker prompt"],
        prior_target_responses=None,
    )
    user_prompt = captured["user"]
    assert "MATERIALLY DIFFERENT" in user_prompt
    assert "multi-turn conversation" not in user_prompt


@pytest.mark.asyncio
async def test_no_prior_no_directive() -> None:
    fake = FakeLLMClient()
    captured: dict[str, Any] = {}
    fake.register("redteam_injection", _capture_and_canned(captured, _PARSED))
    await propose_technique(technique="ignore_previous", llm=fake, seed_idx=0)
    user_prompt = captured["user"]
    assert "multi-turn conversation" not in user_prompt
    assert "MATERIALLY DIFFERENT" not in user_prompt
