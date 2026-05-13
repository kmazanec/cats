"""Unit tests for the tool_abuse specialist dispatcher.

Verifies the rotation, the per-technique routing, and the unknown-technique
failure mode. Uses FakeLLMClient so no network IO happens.
"""

from __future__ import annotations

import json
from typing import Any
from uuid import uuid4

import pytest

from cats.agents.red_team.tool_abuse import dispatcher
from cats.agents.red_team.tool_abuse.base import ToolAbuseProposal
from cats.graph.state import CampaignState
from cats.llm.client import FakeLLMClient, install_override


def _empty_state() -> CampaignState:
    return CampaignState(
        run_id=uuid4(),
        campaign_id=uuid4(),
        project_version_id=uuid4(),
    )


@pytest.fixture(autouse=True)
def _reset_fake_llm() -> Any:
    yield
    install_override(None)


def _canned(payload: dict[str, Any]) -> Any:
    def _respond(_messages: list[dict[str, Any]]) -> str:
        return json.dumps(payload)

    return _respond


def _good_payload(technique: str) -> dict[str, Any]:
    return {
        "title": f"test {technique}",
        "description": "synthetic attack for dispatcher test",
        "technique": technique,
        "user_message": "Pull the lab history for the last five years.",
        "task_type": "default_briefing",
        "target_areas": ["lab history"],
    }


def test_known_techniques_match_proposers() -> None:
    """The dispatcher's KNOWN_TECHNIQUES must equal the _PROPOSERS key
    set — if these drift, the executor's plan validation passes a
    technique the dispatcher rejects."""
    from cats.agents.red_team.tool_abuse.dispatcher import _PROPOSERS

    assert frozenset(_PROPOSERS.keys()) == dispatcher.KNOWN_TECHNIQUES
    assert {
        "chart_area_over_read",
        "cross_task_tool_invocation",
        "repeat_invocation_pressure",
    } == dispatcher.KNOWN_TECHNIQUES


def test_rotation_lists_every_known_technique() -> None:
    """A technique present in ROTATION but missing from KNOWN_TECHNIQUES
    would crash the picker; the reverse would silently skip techniques."""
    assert set(dispatcher.ROTATION) == dispatcher.KNOWN_TECHNIQUES


def test_pick_technique_returns_selected_when_set() -> None:
    state = _empty_state()
    state.selected_technique = "cross_task_tool_invocation"
    assert dispatcher.pick_technique(state) == "cross_task_tool_invocation"


def test_pick_technique_walks_rotation_then_round_robin() -> None:
    state = _empty_state()
    state.selected_technique = ""  # not set
    # First call: first un-attempted in ROTATION.
    assert dispatcher.pick_technique(state) == dispatcher.ROTATION[0]
    # After exhausting rotation, round-robin.
    state.techniques_attempted = list(dispatcher.ROTATION)
    pick = dispatcher.pick_technique(state)
    assert pick in dispatcher.ROTATION


@pytest.mark.asyncio
async def test_propose_technique_dispatches_to_chart_area_over_read() -> None:
    fake = FakeLLMClient()
    fake.register("redteam_toolabuse", _canned(_good_payload("chart_area_over_read")))
    install_override(fake)

    out = await dispatcher.propose_technique(technique="chart_area_over_read", llm=fake)
    assert isinstance(out, ToolAbuseProposal)
    assert out.technique == "chart_area_over_read"
    assert out.task_type == "default_briefing"
    assert out.target_areas == ["lab history"]
    assert "lab history" in out.user_message.lower()


@pytest.mark.asyncio
async def test_propose_technique_rejects_unknown_technique() -> None:
    fake = FakeLLMClient()
    install_override(fake)
    with pytest.raises(KeyError, match="unknown tool_abuse technique"):
        await dispatcher.propose_technique(technique="bogus_technique", llm=fake)


@pytest.mark.asyncio
async def test_proposal_falls_back_to_known_task_type_on_bad_llm_output() -> None:
    """If the model returns an unknown task_type, the base builder
    falls back to the technique's default so downstream code never
    receives a payload it can't look a baseline up for."""
    fake = FakeLLMClient()
    payload = _good_payload("chart_area_over_read")
    payload["task_type"] = "totally_made_up"
    fake.register("redteam_toolabuse", _canned(payload))
    install_override(fake)

    out = await dispatcher.propose_technique(technique="chart_area_over_read", llm=fake)
    # chart_area_over_read's DEFAULT_TASK_TYPE is default_briefing.
    assert out.task_type == "default_briefing"


@pytest.mark.asyncio
async def test_unparseable_llm_output_raises_value_error() -> None:
    fake = FakeLLMClient()
    fake.register("redteam_toolabuse", _canned({"not": "json shape we expect"}))
    # The base extractor accepts ANY JSON object, but build_proposal
    # demands `user_message` — empty string raises ValueError.
    install_override(fake)
    with pytest.raises(ValueError, match="missing user_message"):
        await dispatcher.propose_technique(technique="chart_area_over_read", llm=fake)
