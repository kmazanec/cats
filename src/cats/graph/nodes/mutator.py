"""Mutator node.

R3: variant generation on partial-success feedback. The node runs in two
modes:

1. **Fresh attack mode** (no prior verdict): pass the attack through
   unchanged. The dashboard still sees a ``mutator_passthrough`` event
   so the seven-role topology is visible.
2. **Variant mode** (``state.last_verdict == "partial"`` and the loop
   has not exhausted ``MAX_CONSECUTIVE_PARTIALS``): call the variant
   generator, splice the rewritten user_message back into the pending
   attack payload, and record cost. The judge then re-evaluates the
   variant.

The loop is bounded by ``MAX_CONSECUTIVE_PARTIALS``; the
``judge → mutator`` conditional edge in :mod:`cats.graph.build` checks
``state.consecutive_partial_count`` and routes to ``documentation``
when the cap is reached.
"""

from __future__ import annotations

from cats.agents.common import with_cost
from cats.agents.mutator import MAX_CONSECUTIVE_PARTIALS, generate_variant
from cats.graph.events import publish
from cats.graph.state import CampaignState
from cats.llm.client import get_llm


async def run(state: CampaignState) -> CampaignState:
    is_variant_pass = (
        state.last_verdict == "partial"
        and state.consecutive_partial_count < MAX_CONSECUTIVE_PARTIALS
    )

    if not is_variant_pass:
        await publish(
            kind="attack_proposed",
            campaign_id=state.campaign_id,
            run_id=state.run_id,
            payload={
                "stage": "mutator_passthrough",
                "note": "Fresh attack — Mutator passes through.",
            },
        )
        return state

    # Variant mode. Increment the partial counter *before* generating the
    # variant so a same-loop replay sees the bump (idempotency under
    # checkpoint resume).
    state.consecutive_partial_count += 1

    result = await generate_variant(state=state, llm=get_llm())

    # Splice the variant back into the pending attack so output_filter +
    # target_caller see the new payload.
    state.pending_attack_payload = {
        **state.pending_attack_payload,
        "user_message": result.user_message,
        "variant_of_technique": state.selected_technique,
        "variant_strategy": result.technique_variant,
    }
    state.pending_attack_title = (
        f"{state.pending_attack_title} · variant {state.consecutive_partial_count}"
    )

    if result.llm is not None:
        with_cost(state, role="mutator", llm_result=result.llm)

    await publish(
        kind="attack_proposed",
        campaign_id=state.campaign_id,
        run_id=state.run_id,
        payload={
            "stage": "mutator_variant",
            "consecutive_partial": state.consecutive_partial_count,
            "variant_strategy": result.technique_variant,
            "rationale": result.rationale[:200],
        },
    )

    # Clear the verdict so downstream nodes (output_filter, target_caller,
    # judge) treat this as a fresh attack rather than re-reading the
    # previous partial.
    state.last_verdict = None
    state.last_verdict_rationale = ""
    state.last_verdict_evidence = {}

    return state
