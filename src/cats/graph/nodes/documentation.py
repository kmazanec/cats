"""Documentation node. Real impl: structured vulnerability report; pauses
on critical-severity for human approval. Stub: no-op."""

from __future__ import annotations

from cats.graph.state import CampaignState


async def run(state: CampaignState) -> CampaignState:
    return state
