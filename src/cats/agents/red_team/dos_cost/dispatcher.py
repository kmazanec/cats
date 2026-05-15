"""dos_cost category dispatcher.

Picks among the shipped dos_cost techniques and runs that technique's
specialist. The executor refuses any technique not in
:data:`KNOWN_TECHNIQUES`.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from cats.agents.red_team.dos_cost import (
    clawdrain_segmented_verification,
    output_length_explosion,
    recursive_task_expansion,
    tokenizer_drift_amplification,
)
from cats.agents.red_team.dos_cost.base import DosCostProposal
from cats.graph.state import CampaignState
from cats.llm.client import LLMClient

# Order matters: the dispatcher walks this list, preferring techniques
# the campaign hasn't attempted yet. Clawdrain leads because it's the
# documented baseline; tokenizer-drift trails because it's the cheapest
# (no per-step fan-out) and lowest-impact of the four.
ROTATION: tuple[str, ...] = (
    "clawdrain_segmented_verification",
    "output_length_explosion",
    "recursive_task_expansion",
    "tokenizer_drift_amplification",
)

_PROPOSERS: dict[str, Callable[..., Awaitable[DosCostProposal]]] = {
    "clawdrain_segmented_verification": clawdrain_segmented_verification.propose,
    "output_length_explosion": output_length_explosion.propose,
    "recursive_task_expansion": recursive_task_expansion.propose,
    "tokenizer_drift_amplification": tokenizer_drift_amplification.propose,
}

KNOWN_TECHNIQUES: frozenset[str] = frozenset(_PROPOSERS.keys())


def pick_technique(state: CampaignState) -> str:
    """Choose the next technique to run for this state. Same priority
    order as the other dispatchers (selected → unattempted → round-robin)."""
    if state.selected_technique and state.selected_technique in KNOWN_TECHNIQUES:
        return state.selected_technique
    attempted = set(state.techniques_attempted)
    for technique in ROTATION:
        if technique not in attempted:
            return technique
    return ROTATION[len(state.techniques_attempted) % len(ROTATION)]


async def propose_technique(*, technique: str, llm: LLMClient) -> DosCostProposal:
    """Run one specific specialist. Fails loud on unknown technique."""
    if technique not in _PROPOSERS:
        raise KeyError(
            f"unknown dos_cost technique {technique!r}; known: {sorted(KNOWN_TECHNIQUES)}"
        )
    return await _PROPOSERS[technique](llm=llm)


async def propose(*, llm: LLMClient, state: CampaignState | None = None) -> DosCostProposal:
    """Pick a technique from ``state`` (or default to the first ROTATION
    entry when no state is provided) and run its specialist."""
    technique = pick_technique(state) if state is not None else ROTATION[0]
    return await propose_technique(technique=technique, llm=llm)
