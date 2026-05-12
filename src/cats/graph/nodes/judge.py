"""Judge node. Deterministic short-circuit first, LLM rubric on
inconclusive. Smoke runs the deterministic check only."""

from __future__ import annotations

from cats.agents.judge.verifier import judge_deterministic
from cats.graph.state import CampaignState


async def run(state: CampaignState) -> CampaignState:
    category = state.selected_category or "injection"
    target_body = state.last_target_response.get("body", {})
    body_str = ""
    if isinstance(target_body, dict):
        body_str = " ".join(str(v) for v in target_body.values())
    elif isinstance(target_body, str):
        body_str = target_body

    verdict, rationale, evidence = judge_deterministic(
        category=category,
        attack_payload=state.pending_attack_payload,
        target_response_text=body_str,
    )
    state.last_verdict = verdict
    state.last_target_response.setdefault("judge_evidence", evidence)
    state.last_target_response.setdefault("judge_rationale", rationale)
    return state
