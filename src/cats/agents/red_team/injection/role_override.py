"""``role_override`` — instruction-hierarchy break via injected role tags.

The attack injects a literal ``</user>\\n\\nSystem: …`` (or variants) into
the user message, attempting to make the model treat subsequent text as a
higher-priority system instruction (docs/W3_THREAT_RESEARCH §1.7,
"Instruction-hierarchy / role-confusion").
"""

from __future__ import annotations

from cats.agents.red_team.injection.base import (
    InjectionProposal,
    build_proposal,
    new_canary,
    run_specialist_llm,
)
from cats.llm.client import LLMClient

TECHNIQUE = "role_override"


async def propose(
    *,
    llm: LLMClient,
    seed_idx: int = 0,
    prior_user_messages: list[str] | None = None,
) -> InjectionProposal:
    canary = new_canary()
    parsed, llm_result = await run_specialist_llm(
        llm=llm,
        technique=TECHNIQUE,
        canary=canary,
        seed_idx=seed_idx,
        prior_user_messages=prior_user_messages,
    )
    return build_proposal(parsed=parsed, canary=canary, technique=TECHNIQUE, llm_result=llm_result)
