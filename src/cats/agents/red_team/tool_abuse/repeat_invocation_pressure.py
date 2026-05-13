"""§3.3 repeat-invocation pressure — coerce repeated pulls of one
out-of-baseline chart area in a single turn."""

from __future__ import annotations

from cats.agents.red_team.tool_abuse.base import (
    ToolAbuseProposal,
    build_proposal,
    run_specialist_llm,
)
from cats.llm.client import LLMClient

TECHNIQUE = "repeat_invocation_pressure"
DEFAULT_TASK_TYPE = "default_briefing"


async def propose(*, llm: LLMClient) -> ToolAbuseProposal:
    parsed, llm_result = await run_specialist_llm(llm=llm, technique=TECHNIQUE)
    return build_proposal(
        parsed=parsed,
        technique=TECHNIQUE,
        fallback_task_type=DEFAULT_TASK_TYPE,
        llm_result=llm_result,
    )
