"""Judge node.

Two stages:
1. Deterministic post-condition (canary echo for injection).
2. If `inconclusive`, fall back to the locked rubric v1 LLM call.

Records cost on the per-agent breakdown when the LLM stage runs.
"""

from __future__ import annotations

from cats.agents.common import with_cost
from cats.agents.judge.verifier import judge_deterministic, judge_llm
from cats.graph.events import publish
from cats.graph.state import CampaignState
from cats.llm.client import get_llm


async def run(state: CampaignState) -> CampaignState:
    category = state.selected_category or "injection"

    # The response text the target_caller assembled is the canonical
    # surface to judge against. Fall back to flattening the dict shape
    # for the smoke path which doesn't go through target_caller.attack().
    body_text = state.last_target_text
    if not body_text:
        body = state.last_target_response.get("body", {})
        if isinstance(body, dict):
            body_text = " ".join(str(v) for v in body.values())
        elif isinstance(body, str):
            body_text = body

    verdict, rationale, evidence = judge_deterministic(
        category=category,
        attack_payload=state.pending_attack_payload,
        target_response_text=body_text,
    )
    state.last_verdict_is_deterministic = True
    state.last_verdict_model = "deterministic"

    if verdict == "inconclusive":
        # Fall back to the LLM rubric.
        (verdict, rationale, evidence), llm_result = await judge_llm(
            llm=get_llm(),
            category=category,
            attack_user_message=str(state.pending_attack_payload.get("user_message", "")),
            target_response_text=body_text,
            canary=state.pending_canary,
        )
        state.last_verdict_is_deterministic = False
        state.last_verdict_model = llm_result.model
        with_cost(state, role="judge", llm_result=llm_result)

    state.last_verdict = verdict
    state.last_verdict_rationale = rationale
    state.last_verdict_evidence = evidence
    state.last_target_response.setdefault("judge_evidence", evidence)
    state.last_target_response.setdefault("judge_rationale", rationale)

    await publish(
        kind="judge_verdict_rendered",
        campaign_id=state.campaign_id,
        run_id=state.run_id,
        payload={
            "verdict": verdict,
            "is_deterministic": state.last_verdict_is_deterministic,
            "rationale": rationale[:300],
        },
    )
    return state
