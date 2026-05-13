"""§3.2 cross-task tool invocation — surface-narrow follow-up whose
phrasing nudges the supervisor into an out-of-baseline tool family."""

from __future__ import annotations

from cats.agents.red_team.tool_abuse.base import (
    ToolAbuseProposal,
    build_proposal,
    run_specialist_llm,
)
from cats.llm.client import LLMClient

TECHNIQUE = "cross_task_tool_invocation"
DEFAULT_TASK_TYPE = "follow_up"


async def propose(*, llm: LLMClient) -> ToolAbuseProposal:
    parsed, llm_result = await run_specialist_llm(llm=llm, technique=TECHNIQUE)
    return build_proposal(
        parsed=parsed,
        technique=TECHNIQUE,
        fallback_task_type=DEFAULT_TASK_TYPE,
        llm_result=llm_result,
    )
