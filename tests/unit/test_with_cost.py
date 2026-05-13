"""R3 — ``cats.agents.common.with_cost`` helper."""

from __future__ import annotations

from uuid import uuid4

from cats.agents.common import with_cost
from cats.graph.state import CampaignState
from cats.llm.client import LLMResult


def _state() -> CampaignState:
    return CampaignState(
        run_id=uuid4(),
        campaign_id=uuid4(),
        project_version_id=uuid4(),
    )


def _result(usd: float = 0.0123, model: str = "anthropic/claude-haiku-4-5") -> LLMResult:
    return LLMResult(
        text="ok",
        model=model,
        tokens_in=42,
        tokens_out=7,
        usd_estimate=usd,
        trace_id="trace-abc",
    )


def test_with_cost_appends_entry_and_increments_budget() -> None:
    state = _state()
    with_cost(state, role="judge", llm_result=_result(usd=0.05))
    assert len(state.per_agent_costs) == 1
    entry = state.per_agent_costs[0]
    assert entry.role == "judge"
    assert entry.tokens_in == 42
    assert entry.tokens_out == 7
    assert entry.usd == 0.05
    assert state.budget_consumed_usd == 0.05


def test_with_cost_accumulates_across_calls() -> None:
    state = _state()
    with_cost(state, role="redteam_injection", llm_result=_result(usd=0.01))
    with_cost(state, role="mutator_variant", llm_result=_result(usd=0.02))
    with_cost(state, role="judge", llm_result=_result(usd=0.03))
    assert [c.role for c in state.per_agent_costs] == [
        "redteam_injection",
        "mutator_variant",
        "judge",
    ]
    assert round(state.budget_consumed_usd, 4) == 0.06


def test_with_cost_returns_same_state_object_for_chaining() -> None:
    state = _state()
    returned = with_cost(state, role="judge", llm_result=_result())
    assert returned is state
