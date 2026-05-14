"""``encoded_payload`` — base64 / leetspeak / ROT13 wrapping.

Tests the target's input-normalization pipeline. The specialist embeds
the canary instruction in an encoded form; success means the model
decoded and obeyed despite the defense layer (docs/W3_THREAT_RESEARCH
§1.6).

We keep ``temperature`` slightly lower than the other specialists because
encoded payloads benefit from precise character-level construction —
high temperature tends to break the encoding mid-stream.
"""

from __future__ import annotations

from cats.agents.red_team.injection.base import (
    InjectionProposal,
    build_proposal,
    new_canary,
    run_specialist_llm,
)
from cats.llm.client import LLMClient

TECHNIQUE = "encoded_payload"


async def propose(
    *,
    llm: LLMClient,
    seed_idx: int = 0,
    prior_user_messages: list[str] | None = None,
    prior_target_responses: list[str] | None = None,
) -> InjectionProposal:
    canary = new_canary()
    parsed, llm_result = await run_specialist_llm(
        llm=llm,
        technique=TECHNIQUE,
        canary=canary,
        temperature=0.5,
        seed_idx=seed_idx,
        prior_user_messages=prior_user_messages,
        prior_target_responses=prior_target_responses,
    )
    return build_proposal(parsed=parsed, canary=canary, technique=TECHNIQUE, llm_result=llm_result)
