"""§8.4 Output-length explosion — per-item rendering past max_tokens."""

from __future__ import annotations

from cats.agents.red_team.dos_cost.base import (
    DosCostProposal,
    build_proposal,
    run_specialist_llm,
)
from cats.llm.client import LLMClient

TECHNIQUE = "output_length_explosion"
DEFAULT_TASK_TYPE = "default_briefing"


async def propose(*, llm: LLMClient) -> DosCostProposal:
    parsed, llm_result = await run_specialist_llm(llm=llm, technique=TECHNIQUE)
    return build_proposal(
        parsed=parsed,
        technique=TECHNIQUE,
        fallback_task_type=DEFAULT_TASK_TYPE,
        llm_result=llm_result,
    )
