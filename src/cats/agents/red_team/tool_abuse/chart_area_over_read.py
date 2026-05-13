"""§3.1 chart-area over-read — coerce surfacing of one specific
out-of-baseline chart area (e.g. lab history during a fresh briefing)."""

from __future__ import annotations

from cats.agents.red_team.tool_abuse.base import (
    ToolAbuseProposal,
    build_proposal,
    run_specialist_llm,
)
from cats.llm.client import LLMClient

TECHNIQUE = "chart_area_over_read"
DEFAULT_TASK_TYPE = "default_briefing"


async def propose(*, llm: LLMClient) -> ToolAbuseProposal:
    parsed, llm_result = await run_specialist_llm(llm=llm, technique=TECHNIQUE)
    return build_proposal(
        parsed=parsed,
        technique=TECHNIQUE,
        fallback_task_type=DEFAULT_TASK_TYPE,
        llm_result=llm_result,
    )
