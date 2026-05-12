"""Orchestrator node.

R2 scope: the user names the category; the Orchestrator records the
plan and emits a `campaign_started` event. Real bandit-based selection
across multiple categories is Round 6 work.
"""

from __future__ import annotations

from cats.graph.events import publish
from cats.graph.state import CampaignState


async def run(state: CampaignState) -> CampaignState:
    if not state.selected_category:
        state.selected_category = "injection"
    await publish(
        kind="campaign_started",
        campaign_id=state.campaign_id,
        run_id=state.run_id,
        payload={
            "selected_category": state.selected_category,
            "target_kind": state.target_kind,
        },
    )
    return state
