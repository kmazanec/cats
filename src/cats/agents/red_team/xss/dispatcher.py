"""XSS dispatcher (R12).

Picks among the six shipped techniques and runs that technique's
specialist. The shape mirrors :mod:`cats.agents.red_team.exfil.dispatcher`
so the executor's per-category branch in
:func:`cats.agents.red_team.executor._propose_attack` reads uniformly
across categories.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from cats.agents.red_team.xss import (
    event_handler,
    html_entity_smuggling,
    img_onerror,
    javascript_url,
    markdown_parser_break,
    script_tag,
)
from cats.agents.red_team.xss.base import XssProposal
from cats.graph.state import CampaignState
from cats.llm.client import LLMClient

# Order matters: the dispatcher walks this list, preferring techniques
# the campaign hasn't attempted yet. Ordered by directness — the
# loudest payloads first so a single-turn campaign exercises the
# strongest signal early.
ROTATION: tuple[str, ...] = (
    "script_tag",
    "img_onerror",
    "event_handler",
    "javascript_url",
    "markdown_parser_break",
    "html_entity_smuggling",
)

_PROPOSERS: dict[str, Callable[..., Awaitable[XssProposal]]] = {
    "script_tag": script_tag.propose,
    "img_onerror": img_onerror.propose,
    "javascript_url": javascript_url.propose,
    "event_handler": event_handler.propose,
    "markdown_parser_break": markdown_parser_break.propose,
    "html_entity_smuggling": html_entity_smuggling.propose,
}

KNOWN_TECHNIQUES: frozenset[str] = frozenset(_PROPOSERS.keys())


def pick_technique(state: CampaignState) -> str:
    """Choose the next technique to run for this state."""
    if state.selected_technique and state.selected_technique in KNOWN_TECHNIQUES:
        return state.selected_technique
    attempted = set(state.techniques_attempted)
    for technique in ROTATION:
        if technique not in attempted:
            return technique
    return ROTATION[len(state.techniques_attempted) % len(ROTATION)]


async def propose_technique(
    *,
    technique: str,
    llm: LLMClient,
    prior_target_response: str = "",
) -> XssProposal:
    """Run one specific specialist. Fails loud on unknown techniques."""
    if technique not in _PROPOSERS:
        raise KeyError(f"unknown xss technique {technique!r}; known: {sorted(KNOWN_TECHNIQUES)}")
    return await _PROPOSERS[technique](llm=llm, prior_target_response=prior_target_response)


async def propose(
    *,
    llm: LLMClient,
    state: CampaignState | None = None,
    prior_target_response: str = "",
) -> XssProposal:
    """Pick a technique from ``state`` (or default to the first
    ROTATION entry) and run its specialist."""
    technique = pick_technique(state) if state is not None else ROTATION[0]
    return await propose_technique(
        technique=technique, llm=llm, prior_target_response=prior_target_response
    )
