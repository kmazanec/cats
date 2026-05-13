"""Tool-abuse category dispatcher.

Picks among the shipped tool_abuse techniques and runs that technique's
specialist. R7 foundations ships three; the executor refuses any
technique not in :data:`KNOWN_TECHNIQUES`.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from cats.agents.red_team.tool_abuse import (
    chart_area_over_read,
    cross_task_tool_invocation,
    repeat_invocation_pressure,
)
from cats.agents.red_team.tool_abuse.base import ToolAbuseProposal
from cats.graph.state import CampaignState
from cats.llm.client import LLMClient

# Order matters: the dispatcher walks this list, preferring techniques
# the campaign hasn't attempted yet.
ROTATION: tuple[str, ...] = (
    "chart_area_over_read",
    "cross_task_tool_invocation",
    "repeat_invocation_pressure",
)

_PROPOSERS: dict[str, Callable[..., Awaitable[ToolAbuseProposal]]] = {
    "chart_area_over_read": chart_area_over_read.propose,
    "cross_task_tool_invocation": cross_task_tool_invocation.propose,
    "repeat_invocation_pressure": repeat_invocation_pressure.propose,
}

KNOWN_TECHNIQUES: frozenset[str] = frozenset(_PROPOSERS.keys())


def pick_technique(state: CampaignState) -> str:
    """Choose the next technique to run for this state.

    Priority order:

    1. If ``state.selected_technique`` is in :data:`KNOWN_TECHNIQUES`, use it.
    2. Walk :data:`ROTATION` and return the first one not in
       ``state.techniques_attempted``.
    3. Round-robin once everything has been attempted at least once.
    """
    if state.selected_technique and state.selected_technique in KNOWN_TECHNIQUES:
        return state.selected_technique
    attempted = set(state.techniques_attempted)
    for technique in ROTATION:
        if technique not in attempted:
            return technique
    return ROTATION[len(state.techniques_attempted) % len(ROTATION)]


async def propose_technique(*, technique: str, llm: LLMClient) -> ToolAbuseProposal:
    """Run one specific specialist. Fails loud on unknown technique."""
    if technique not in _PROPOSERS:
        raise KeyError(
            f"unknown tool_abuse technique {technique!r}; known: {sorted(KNOWN_TECHNIQUES)}"
        )
    return await _PROPOSERS[technique](llm=llm)


async def propose(*, llm: LLMClient, state: CampaignState | None = None) -> ToolAbuseProposal:
    """Pick a technique from ``state`` (or default to the first
    ROTATION entry when no state is provided) and run its specialist."""
    technique = pick_technique(state) if state is not None else ROTATION[0]
    return await propose_technique(technique=technique, llm=llm)
