"""Exfil-category dispatcher.

Picks among the *shipped* exfil techniques and runs that technique's
specialist. R6's foundations report catalogues five techniques; this
slice ships the two highest-leverage ones (``cross_patient_scope_bypass``
and ``markdown_image_exfil``) and registers the other three as
NotImplementedError stubs in :data:`_DEFERRED_TECHNIQUES`. Adding the
remaining specialists is a small follow-up — author the per-technique
prompts and a 25-line module mirroring the two shipped here.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from cats.agents.red_team.exfil import cross_patient_scope_bypass, markdown_image_exfil
from cats.agents.red_team.exfil.base import ExfilProposal
from cats.graph.state import CampaignState
from cats.llm.client import LLMClient

# Order matters: the dispatcher walks this list, preferring techniques
# the campaign hasn't attempted yet.
ROTATION: tuple[str, ...] = (
    "cross_patient_scope_bypass",
    "markdown_image_exfil",
)

_PROPOSERS: dict[str, Callable[..., Awaitable[ExfilProposal]]] = {
    "cross_patient_scope_bypass": cross_patient_scope_bypass.propose,
    "markdown_image_exfil": markdown_image_exfil.propose,
}

KNOWN_TECHNIQUES: frozenset[str] = frozenset(_PROPOSERS.keys())

# Techniques the R6 foundations report catalogued but this slice doesn't
# yet ship. The dispatcher raises a descriptive NotImplementedError if
# the Orchestrator (or a fixture) names one — pointing at the report so
# the operator knows the path to fill them in.
_DEFERRED_TECHNIQUES: frozenset[str] = frozenset(
    {
        "reference_link_exfil",
        "tool_param_exfil",
        "clarifying_question_echo",
    }
)


def pick_technique(state: CampaignState) -> str:
    """Choose the next technique to run for this state.

    Priority order:

    1. If ``state.selected_technique`` is in ``KNOWN_TECHNIQUES``, use it.
    2. Walk ``ROTATION`` and return the first one not in
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


async def propose_technique(*, technique: str, llm: LLMClient) -> ExfilProposal:
    """Run one specific specialist. Fails loud on unknown or deferred
    technique names — silent fallback would mask Orchestrator plan bugs."""
    if technique in _DEFERRED_TECHNIQUES:
        raise NotImplementedError(
            f"exfil technique {technique!r} is catalogued in "
            "reports/exfil/R6_foundations.md but the specialist module "
            "is not yet implemented. The dispatcher accepts only "
            f"{sorted(KNOWN_TECHNIQUES)} for now."
        )
    if technique not in _PROPOSERS:
        raise KeyError(
            f"unknown exfil technique {technique!r}; known: "
            f"{sorted(KNOWN_TECHNIQUES)}; deferred: {sorted(_DEFERRED_TECHNIQUES)}"
        )
    return await _PROPOSERS[technique](llm=llm)


async def propose(*, llm: LLMClient, state: CampaignState | None = None) -> ExfilProposal:
    """Pick a technique from ``state`` (or default to the first
    ROTATION entry when no state is provided) and run its specialist."""
    technique = pick_technique(state) if state is not None else ROTATION[0]
    return await propose_technique(technique=technique, llm=llm)
