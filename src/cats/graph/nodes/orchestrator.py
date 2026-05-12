"""Orchestrator node. Picks the next category for the inner loop using the
deterministic epsilon-greedy bandit in `cats.agents.orchestrator.policy`.
Stub: hardcodes injection for the smoke path."""

from __future__ import annotations

from cats.graph.state import CampaignState


async def run(state: CampaignState) -> CampaignState:
    if state.selected_category is None:
        state.selected_category = "injection"
    return state
