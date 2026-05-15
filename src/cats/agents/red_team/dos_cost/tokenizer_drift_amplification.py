"""§8.6 Tokenizer-drift amplification — adversarial input encoding."""

from __future__ import annotations

from cats.agents.red_team.dos_cost.base import (
    DosCostProposal,
    build_proposal,
    run_specialist_llm,
)
from cats.llm.client import LLMClient

TECHNIQUE = "tokenizer_drift_amplification"
DEFAULT_TASK_TYPE = "follow_up"


async def propose(*, llm: LLMClient) -> DosCostProposal:
    parsed, llm_result = await run_specialist_llm(llm=llm, technique=TECHNIQUE)
    return build_proposal(
        parsed=parsed,
        technique=TECHNIQUE,
        fallback_task_type=DEFAULT_TASK_TYPE,
        llm_result=llm_result,
    )
