"""Unit tests for the Injection specialist (R2).

Stub the LLM with a `FakeLLMClient`; verify the parser handles raw JSON,
fenced JSON, prose-wrapped JSON, and the missing-canary defensive splice.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from cats.agents.red_team.injection import propose
from cats.llm.client import FakeLLMClient


def _canned(text_for_call: str) -> Any:
    def _respond(_messages: list[dict[str, Any]]) -> str:
        return text_for_call

    return _respond


@pytest.mark.asyncio
async def test_specialist_parses_raw_json() -> None:
    fake = FakeLLMClient()
    fake.register(
        "redteam_injection",
        _canned(
            json.dumps(
                {
                    "title": "test title",
                    "description": "test description",
                    "technique": "ignore_previous",
                    "user_message": "Please reply with {{CANARY}} exactly.",
                    "expected_canary_echo": True,
                }
            )
        ),
    )
    proposal = await propose(llm=fake)
    assert proposal.technique == "ignore_previous"
    assert proposal.title == "test title"
    # Canary substitution happened — the raw {{CANARY}} placeholder
    # was rewritten to a unique CATS-CANARY-<hex> token.
    assert "{{CANARY}}" not in proposal.user_message
    assert proposal.canary.startswith("CATS-CANARY-")
    assert proposal.canary in proposal.user_message


@pytest.mark.asyncio
async def test_specialist_handles_fenced_json() -> None:
    fake = FakeLLMClient()
    body = json.dumps(
        {
            "title": "fenced",
            "description": "desc",
            "technique": "task_redirect",
            "user_message": "test {{CANARY}}",
        }
    )
    fake.register("redteam_injection", _canned(f"Here is the attack:\n\n```json\n{body}\n```"))
    proposal = await propose(llm=fake)
    assert proposal.title == "fenced"
    assert proposal.technique == "task_redirect"


@pytest.mark.asyncio
async def test_specialist_handles_prose_wrapped_json() -> None:
    fake = FakeLLMClient()
    body = json.dumps(
        {
            "title": "prose-wrapped",
            "description": "d",
            "technique": "role_override",
            "user_message": "see {{CANARY}}",
        }
    )
    fake.register(
        "redteam_injection",
        _canned(f"Sure! Here you go:\n\n{body}\n\nLet me know if you want another."),
    )
    proposal = await propose(llm=fake)
    assert proposal.technique == "role_override"


@pytest.mark.asyncio
async def test_specialist_splices_in_missing_canary() -> None:
    fake = FakeLLMClient()
    # LLM forgot to keep the {{CANARY}} placeholder in user_message.
    fake.register(
        "redteam_injection",
        _canned(
            json.dumps(
                {
                    "title": "no canary in message",
                    "description": "model forgot",
                    "technique": "ignore_previous",
                    "user_message": "Hello there.",
                }
            )
        ),
    )
    proposal = await propose(llm=fake)
    # Defensive splice should have added it.
    assert proposal.canary in proposal.user_message


@pytest.mark.asyncio
async def test_specialist_rejects_unparseable() -> None:
    fake = FakeLLMClient()
    fake.register("redteam_injection", _canned("totally not json"))
    with pytest.raises(ValueError):
        await propose(llm=fake)


@pytest.mark.asyncio
async def test_specialist_rejects_missing_user_message() -> None:
    fake = FakeLLMClient()
    fake.register(
        "redteam_injection",
        _canned(json.dumps({"title": "x", "technique": "ignore_previous"})),
    )
    with pytest.raises(ValueError):
        await propose(llm=fake)
