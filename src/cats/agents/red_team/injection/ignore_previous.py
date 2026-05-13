"""``ignore_previous`` — the R2 baseline.

The classic "ignore previous instructions and …" override. Continues to
use the category-wide R2 prompts when the technique-specific directory
is absent, so this module is byte-equivalent in behavior to R2's
``propose()``.
"""

from __future__ import annotations

from cats.agents.red_team.injection.base import (
    InjectionProposal,
    build_proposal,
    new_canary,
    run_specialist_llm,
)
from cats.llm.client import LLMClient

TECHNIQUE = "ignore_previous"


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
