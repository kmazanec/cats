"""Target Caller node.

Fires the pending attack at the live target via `TargetClient.attack`.
Smoke mode short-circuits to a canned response. State must carry the
target config (base_url, kind, credentials) — the worker populates
these at run start so this node doesn't have to touch the DB.
"""

from __future__ import annotations

from cats.graph.events import publish
from cats.graph.state import CampaignState
from cats.target.client import TargetClient
from cats.target.contracts import AttackEnvelope


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
        state.last_target_text = state.last_target_response["body"]["reply"]
        state.last_target_status_code = 200
        state.last_target_latency_ms = 12
        return state

    if not state.target_base_url:
        state.last_target_response = {"error": "target_base_url not set on state"}
        state.last_target_text = ""
        state.last_target_status_code = 0
        return state

    client = TargetClient(
        base_url=state.target_base_url,
        target_kind=state.target_kind,
        username=state.target_username,
        password=state.target_password,
        bearer_token=state.target_bearer_token,
    )
    envelope = AttackEnvelope(
        user_message=str(state.pending_attack_payload.get("user_message", "")),
        canary=state.pending_canary,
    )
    result = await client.attack(envelope)

    state.last_target_text = result.text
    state.last_target_status_code = result.status_code
    state.last_target_latency_ms = result.latency_ms
    state.last_target_response = {
        "status_code": result.status_code,
        "latency_ms": result.latency_ms,
        "text": result.text[:5000],
        "error": result.error,
    }
    state.attacks_fired += 1

    await publish(
        kind="attack_executed",
        campaign_id=state.campaign_id,
        run_id=state.run_id,
        payload={
            "status_code": result.status_code,
            "latency_ms": result.latency_ms,
            "error": result.error,
        },
    )
    return state
