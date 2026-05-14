"""Campaign-report writer — backwards-compatible facade over the
LangGraph documenter agent.

The real implementation lives in :mod:`cats.agents.documentation.agent`
(a proper LangGraph graph with `author` + `tool_executor` nodes). This
module preserves the pre-agent public surface — ``write_campaign_report``,
``CampaignReportResult``, ``KeepAliveHook`` — so the documentation
worker, tests, and any external callers don't need to change.

To wire new behavior, edit ``agent.py``. To change the prompt, edit
``campaign_system_prompt.md``. To change the tool catalog or the
underlying queries, edit ``campaign_tools.py``.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from cats.agents.documentation.agent import (
    CampaignReportResult,
    KeepAliveHook,
    run_documenter_agent,
)
from cats.llm.client import LLMClient


async def write_campaign_report(
    *,
    llm: LLMClient,
    session: AsyncSession,
    campaign_id: UUID,
    on_turn_start: KeepAliveHook | None = None,
) -> CampaignReportResult:
    """Run the documenter graph and return the rendered report.

    ``on_turn_start`` keeps the pre-agent parameter name so the
    documentation worker doesn't need to change. It's the keep-alive
    hook: workers pass one that calls ``self.touch_claim`` so a long
    LLM tool loop doesn't trip the bus visibility timeout. Returning
    ``False`` aborts cleanly and the writer emits the deterministic
    fallback report."""
    return await run_documenter_agent(
        llm=llm,
        session=session,
        campaign_id=campaign_id,
        keep_alive_hook=on_turn_start,
    )


__all__ = ["CampaignReportResult", "KeepAliveHook", "write_campaign_report"]
