"""Unit tests for the campaign-report tool-loop writer.

These tests do not hit the DB; they replace the data tools with
in-memory stubs by monkeypatching the campaign_tools module so the
loop's structural behavior (turn budget, tool dispatch, fallback)
gets exercised without standing up postgres.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from cats.agents.documentation import campaign_tools, campaign_writer
from cats.config import set_settings_for_test
from cats.llm.client import FakeLLMClient


def _stub_data(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace the data tools with deterministic stubs so the writer
    doesn't need a real session/DB to drive its tool dispatch."""
    summary = {
        "campaign_name": "T",
        "project_name": "P",
        "target_base_url": "http://t",
        "totals": {"runs": 3, "attacks_fired": 5, "usd_estimate": 0.12},
        "verdicts": {"pass": 1, "fail": 3, "error": 1},
    }
    breakdown = {
        "by_category": {
            "injection": {"ignore_previous": {"pass": 1, "fail": 2}},
        }
    }
    findings = {"findings": [], "count": 0}
    failures = {"errors": [], "count": 0}
    cost = {
        "by_role": [
            {
                "agent_role": "judge",
                "tokens_in": 100,
                "tokens_out": 50,
                "usd_estimate": 0.01,
                "calls": 3,
            }
        ],
        "totals": {"usd_estimate": 0.01, "tokens_in": 100, "tokens_out": 50},
    }
    timeline = {"timeline": [], "count": 0}

    async def _s(*a: Any, **k: Any) -> dict[str, Any]:
        return summary

    async def _b(*a: Any, **k: Any) -> dict[str, Any]:
        return breakdown

    async def _f(*a: Any, **k: Any) -> dict[str, Any]:
        return findings

    async def _rf(*a: Any, **k: Any) -> dict[str, Any]:
        return failures

    async def _c(*a: Any, **k: Any) -> dict[str, Any]:
        return cost

    async def _t(*a: Any, **k: Any) -> dict[str, Any]:
        return timeline

    monkeypatch.setattr(campaign_tools, "data_campaign_summary", _s)
    monkeypatch.setattr(campaign_tools, "data_verdict_breakdown", _b)
    monkeypatch.setattr(campaign_tools, "data_findings", _f)
    monkeypatch.setattr(campaign_tools, "data_recent_failures", _rf)
    monkeypatch.setattr(campaign_tools, "data_cost_breakdown", _c)
    monkeypatch.setattr(campaign_tools, "data_timeline", _t)


@pytest.fixture
def isolated_reports_dir(tmp_path: Path) -> Path:
    """Point campaign_reports_dir at a per-test tmp_path so artifacts
    don't bleed between tests or pollute /tmp."""
    set_settings_for_test(campaign_reports_dir=str(tmp_path))
    return tmp_path


@pytest.mark.asyncio
async def test_writer_emits_report_when_llm_calls_finish(
    monkeypatch: pytest.MonkeyPatch, isolated_reports_dir: Path
) -> None:
    _stub_data(monkeypatch)
    fake = FakeLLMClient()
    fake.register_sequence(
        "documentation",
        [
            # Turn 0: gather summary.
            lambda _m: {
                "text": "",
                "tool_calls": [{"name": "data_campaign_summary", "arguments": {}}],
            },
            # Turn 1: render a histogram.
            lambda _m: {
                "text": "",
                "tool_calls": [
                    {
                        "name": "render_verdict_histogram",
                        "arguments": {
                            "verdict_breakdown": {"by_category": {"injection": {"x": {"pass": 1}}}}
                        },
                    }
                ],
            },
            # Turn 2: finish.
            lambda _m: {
                "text": "",
                "tool_calls": [
                    {
                        "name": "finish_report",
                        "arguments": {
                            "body_markdown": "# Report\n\n![hist](verdict-histogram.svg)\n"
                        },
                    }
                ],
            },
        ],
    )

    cid = uuid4()
    result = await campaign_writer.write_campaign_report(
        llm=fake,
        session=None,
        campaign_id=cid,  # type: ignore[arg-type]
    )
    assert "# Report" in result.body_markdown
    assert result.used_fallback is False
    # One render call → one persisted artifact.
    assert len(result.artifacts) == 1
    assert result.artifacts[0]["path"].endswith(".svg")
    # And the SVG actually wrote to disk under our isolated tmp dir.
    svg_path = isolated_reports_dir / str(cid) / "artifacts" / result.artifacts[0]["path"]
    assert svg_path.is_file()
    assert "<svg" in svg_path.read_text()


@pytest.mark.asyncio
async def test_writer_falls_back_when_loop_budget_exhausted(
    monkeypatch: pytest.MonkeyPatch, isolated_reports_dir: Path
) -> None:
    """If the LLM never calls finish_report, the writer hits the turn
    budget and emits a deterministic minimal report so the operator
    isn't left with nothing."""
    _stub_data(monkeypatch)
    set_settings_for_test(campaign_report_max_turns=3)

    fake = FakeLLMClient()
    # Every turn, the LLM keeps calling data_findings (busy work) and
    # never finishes.
    fake.register(
        "documentation",
        lambda _m: {
            "text": "",
            "tool_calls": [{"name": "data_findings", "arguments": {}}],
        },
    )

    result = await campaign_writer.write_campaign_report(
        llm=fake,
        session=None,
        campaign_id=uuid4(),  # type: ignore[arg-type]
    )
    assert result.used_fallback is True
    assert "fallback" in result.body_markdown.lower()
    # Deterministic fallback re-queries summary; should still mention the project.
    assert "Project" in result.body_markdown or "Campaign" in result.body_markdown


@pytest.mark.asyncio
async def test_writer_persists_tool_transcript(
    monkeypatch: pytest.MonkeyPatch, isolated_reports_dir: Path
) -> None:
    _stub_data(monkeypatch)
    fake = FakeLLMClient()
    fake.register_sequence(
        "documentation",
        [
            lambda _m: {
                "text": "",
                "tool_calls": [{"name": "data_campaign_summary", "arguments": {}}],
            },
            lambda _m: {
                "text": "",
                "tool_calls": [{"name": "finish_report", "arguments": {"body_markdown": "# x"}}],
            },
        ],
    )

    result = await campaign_writer.write_campaign_report(
        llm=fake,
        session=None,
        campaign_id=uuid4(),  # type: ignore[arg-type]
    )
    # Transcript records the data call AND the finish_report call.
    tool_names = [entry["tool"] for entry in result.tool_transcript]
    assert "data_campaign_summary" in tool_names
    assert "finish_report" in tool_names


@pytest.mark.asyncio
async def test_writer_costs_accumulate_across_turns(
    monkeypatch: pytest.MonkeyPatch, isolated_reports_dir: Path
) -> None:
    _stub_data(monkeypatch)
    fake = FakeLLMClient()
    fake.register_sequence(
        "documentation",
        [
            lambda _m: {
                "text": "",
                "tool_calls": [{"name": "data_campaign_summary", "arguments": {}}],
            },
            lambda _m: {
                "text": "",
                "tool_calls": [{"name": "data_findings", "arguments": {}}],
            },
            lambda _m: {
                "text": "",
                "tool_calls": [{"name": "finish_report", "arguments": {"body_markdown": "# x"}}],
            },
        ],
    )
    result = await campaign_writer.write_campaign_report(
        llm=fake,
        session=None,
        campaign_id=uuid4(),  # type: ignore[arg-type]
    )
    # Three turns → three LLM calls → strictly positive tokens.
    assert result.tokens_in > 0
    assert result.usd_estimate >= 0  # Haiku in fake mode might round to ~0.
    assert result.model


@pytest.mark.asyncio
async def test_writer_calls_on_turn_start_each_turn(
    monkeypatch: pytest.MonkeyPatch, isolated_reports_dir: Path
) -> None:
    """The keep-alive hook fires at the top of every turn so the
    worker can refresh its bus claim before burning more tokens."""
    _stub_data(monkeypatch)
    fake = FakeLLMClient()
    fake.register_sequence(
        "documentation",
        [
            lambda _m: {
                "text": "",
                "tool_calls": [{"name": "data_campaign_summary", "arguments": {}}],
            },
            lambda _m: {
                "text": "",
                "tool_calls": [{"name": "data_findings", "arguments": {}}],
            },
            lambda _m: {
                "text": "",
                "tool_calls": [{"name": "finish_report", "arguments": {"body_markdown": "# x"}}],
            },
        ],
    )

    seen_turns: list[int] = []

    async def hook(turn: int) -> bool:
        seen_turns.append(turn)
        return True

    await campaign_writer.write_campaign_report(
        llm=fake,
        session=None,  # type: ignore[arg-type]
        campaign_id=uuid4(),
        on_turn_start=hook,
    )
    # Hook fires once per LLM turn, in order, starting at 0.
    assert seen_turns == [0, 1, 2]


@pytest.mark.asyncio
async def test_writer_aborts_when_keep_alive_returns_false(
    monkeypatch: pytest.MonkeyPatch, isolated_reports_dir: Path
) -> None:
    """If the hook returns False (claim lost / cancelled) the writer
    aborts before burning more LLM cost and the result carries the
    fallback flag with the abort reason."""
    _stub_data(monkeypatch)
    fake = FakeLLMClient()
    fake.register(
        "documentation",
        lambda _m: {
            "text": "",
            "tool_calls": [{"name": "data_campaign_summary", "arguments": {}}],
        },
    )

    calls = 0

    async def hook(turn: int) -> bool:
        nonlocal calls
        calls += 1
        # Allow turn 0, abort turn 1.
        return turn == 0

    result = await campaign_writer.write_campaign_report(
        llm=fake,
        session=None,  # type: ignore[arg-type]
        campaign_id=uuid4(),
        on_turn_start=hook,
    )
    assert result.used_fallback is True
    assert "claim" in result.fallback_reason.lower()
    # Two hook invocations: one allowed (turn 0), one rejected (turn 1).
    assert calls == 2
