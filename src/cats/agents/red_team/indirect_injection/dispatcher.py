"""Indirect-injection dispatcher.

Picks among the *shipped* indirect_injection techniques and runs that
technique's specialist. R5's foundations report catalogues 13 W3 §5
techniques; this slice ships two (``white_text`` and ``comment_hide``)
to prove the executor pattern end-to-end against the live target, and
catalogues the rest as NotImplementedError stubs. Each deferred
technique becomes a ~30-line module + per-technique prompts to add.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from cats.agents.red_team.indirect_injection import comment_hide, white_text
from cats.agents.red_team.indirect_injection.base import IndirectInjectionProposal
from cats.docx_attacks import Technique
from cats.graph.state import CampaignState
from cats.llm.client import LLMClient

# Order matters: the dispatcher walks this list, preferring techniques
# the campaign hasn't attempted yet. White-text first because it's the
# simplest defense check — if the extractor's color filter is missing
# it surfaces immediately.
ROTATION: tuple[str, ...] = (
    "white_text",
    "comment_hide",
)

_PROPOSERS: dict[str, Callable[..., Awaitable[IndirectInjectionProposal]]] = {
    "white_text": white_text.propose,
    "comment_hide": comment_hide.propose,
}

KNOWN_TECHNIQUES: frozenset[str] = frozenset(_PROPOSERS.keys())

# Techniques the docx synthesis library implements (and R5's foundations
# report catalogues) but this slice doesn't yet ship a specialist for.
# The set comes straight from the Technique enum minus what's in ROTATION.
_DEFERRED_TECHNIQUES: frozenset[str] = frozenset(
    {t.value for t in Technique if t.value not in set(ROTATION)}
)


def pick_technique(state: CampaignState) -> str:
    """Choose the next technique to run for this state.

    Priority:
    1. ``state.selected_technique`` if it is in ``KNOWN_TECHNIQUES``.
    2. First entry in ``ROTATION`` not in ``state.techniques_attempted``.
    3. Round-robin once everything has been attempted at least once.
    """
    if state.selected_technique and state.selected_technique in KNOWN_TECHNIQUES:
        return state.selected_technique
    attempted = set(state.techniques_attempted)
    for technique in ROTATION:
        if technique not in attempted:
            return technique
    return ROTATION[len(state.techniques_attempted) % len(ROTATION)]


async def propose_technique(*, technique: str, llm: LLMClient) -> IndirectInjectionProposal:
    """Run one specific specialist. Fails loud on deferred/unknown names."""
    if technique in _DEFERRED_TECHNIQUES:
        raise NotImplementedError(
            f"indirect_injection technique {technique!r} is catalogued in "
            "reports/indirect_injection/R5_foundations.md and implemented in "
            "cats.docx_attacks, but the Red Team specialist module is not yet "
            f"shipped. The dispatcher accepts only {sorted(KNOWN_TECHNIQUES)} "
            "for now; adding a specialist is a ~30-line module + per-technique "
            "prompts mirroring white_text.py / comment_hide.py."
        )
    if technique not in _PROPOSERS:
        raise KeyError(
            f"unknown indirect_injection technique {technique!r}; known: "
            f"{sorted(KNOWN_TECHNIQUES)}; deferred: {sorted(_DEFERRED_TECHNIQUES)}"
        )
    return await _PROPOSERS[technique](llm=llm)


async def propose(
    *, llm: LLMClient, state: CampaignState | None = None
) -> IndirectInjectionProposal:
    """Pick a technique from ``state`` (or default to the first ROTATION
    entry when no state is provided) and run its specialist."""
    technique = pick_technique(state) if state is not None else ROTATION[0]
    return await propose_technique(technique=technique, llm=llm)
