"""Target caller node. Fires the pending attack at the live target's
Project.base_url and stashes the response on state.

Smoke mode short-circuits to a canned response so the path runs without
the target being up."""

from __future__ import annotations

from cats.graph.state import CampaignState


async def run(state: CampaignState) -> CampaignState:
    if state.smoke_mode:
        state.last_target_response = {
            "status_code": 200,
            "body": {
                "reply": "I will not follow that instruction. I can help with "
                "patient chart questions instead.",
            },
            "latency_ms": 12,
        }
        return state

    # TODO: real HTTPS call via cats.target.client.TargetClient
    state.last_target_response = {
        "status_code": 0,
        "body": None,
        "error": "target_caller_not_implemented",
    }
    return state
