"""Mutator node. Real impl: takes a partially-successful attack and emits
N variants tagged `source=mutator` with `parent_attack_id` pointing back at
the seed.

Stub: passthrough."""

from __future__ import annotations

from cats.graph.state import CampaignState


async def run(state: CampaignState) -> CampaignState:
    return state
