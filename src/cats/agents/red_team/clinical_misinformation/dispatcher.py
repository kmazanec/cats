"""Clinical-misinformation dispatcher (R11).

Picks among the four shipped techniques and runs that technique's
specialist. The shape mirrors :mod:`cats.agents.red_team.exfil.dispatcher`
so the executor's per-category branch in
:func:`cats.agents.red_team.executor._propose_attack` reads uniformly
across categories.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from cats.agents.red_team.clinical_misinformation import (
    contradicted_medication,
    fabricated_history,
    misattributed_diagnosis,
    wrong_lab_value,
)
from cats.agents.red_team.clinical_misinformation.base import ClinicalMisinfoProposal
from cats.graph.state import CampaignState
from cats.llm.client import LLMClient

# Order matters: the dispatcher walks this list, preferring techniques
# the campaign hasn't attempted yet.
ROTATION: tuple[str, ...] = (
    "wrong_lab_value",
    "misattributed_diagnosis",
    "fabricated_history",
    "contradicted_medication",
)

_PROPOSERS: dict[str, Callable[..., Awaitable[ClinicalMisinfoProposal]]] = {
    "wrong_lab_value": wrong_lab_value.propose,
    "misattributed_diagnosis": misattributed_diagnosis.propose,
    "fabricated_history": fabricated_history.propose,
    "contradicted_medication": contradicted_medication.propose,
}

KNOWN_TECHNIQUES: frozenset[str] = frozenset(_PROPOSERS.keys())


def pick_technique(state: CampaignState) -> str:
    """Choose the next technique to run for this state. Priority:
    1. ``state.selected_technique`` if known.
    2. First entry in :data:`ROTATION` not in ``techniques_attempted``.
    3. Round-robin once everything has been attempted at least once.
    """
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
    kickoff_briefing: str = "",
) -> ClinicalMisinfoProposal:
    """Run one specific specialist. Fails loud on unknown techniques —
    silent fallback would mask Orchestrator plan bugs."""
    if technique not in _PROPOSERS:
        raise KeyError(
            f"unknown clinical_misinformation technique {technique!r}; "
            f"known: {sorted(KNOWN_TECHNIQUES)}"
        )
    return await _PROPOSERS[technique](llm=llm, kickoff_briefing=kickoff_briefing)


async def propose(
    *,
    llm: LLMClient,
    state: CampaignState | None = None,
    kickoff_briefing: str = "",
) -> ClinicalMisinfoProposal:
    """Pick a technique from ``state`` (or default to the first
    ROTATION entry when no state is provided) and run its specialist."""
    technique = pick_technique(state) if state is not None else ROTATION[0]
    return await propose_technique(technique=technique, llm=llm, kickoff_briefing=kickoff_briefing)
