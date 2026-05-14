"""Direct-injection dispatcher.

R2's red-team router called one specialist per campaign. R3 introduces a
*family* of techniques so the platform can attempt several distinct
attacks per campaign. The dispatcher picks which technique runs next
based on what the campaign has already attempted, then calls that
technique's specialist.

Selection policy (R3): walk through ``ROTATION`` in order, skipping any
technique already in ``techniques_attempted``. If every technique has
been attempted once, rotate from the start again — repeats with fresh
canaries are still informative. ``selected_technique`` on the state can
override the rotation for fixture-driven tests.

This stays deliberately simple. R6 introduces the orchestrator's
attack-planning loop and may replace this with something adaptive.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from cats.agents.red_team.injection import (
    encoded_payload,
    ignore_previous,
    policy_puppetry,
    role_override,
    system_prompt_leak,
)
from cats.agents.red_team.injection.base import InjectionProposal
from cats.graph.state import CampaignState
from cats.llm.client import LLMClient

# Order matters: the dispatcher walks this list. Place earlier the
# techniques that exercise the most-load-bearing R3 DoD items (the
# multi-technique-per-campaign assertion picks the first three).
ROTATION: tuple[str, ...] = (
    "ignore_previous",
    "policy_puppetry",
    "role_override",
    "system_prompt_leak",
    "encoded_payload",
)

_PROPOSERS: dict[str, Callable[..., Awaitable[InjectionProposal]]] = {
    "ignore_previous": ignore_previous.propose,
    "policy_puppetry": policy_puppetry.propose,
    "role_override": role_override.propose,
    "system_prompt_leak": system_prompt_leak.propose,
    "encoded_payload": encoded_payload.propose,
}

KNOWN_TECHNIQUES: frozenset[str] = frozenset(_PROPOSERS.keys())


def pick_technique(state: CampaignState) -> str:
    """Choose the next technique to run for this state.

    Priority order:

    1. If ``state.selected_technique`` is in ``KNOWN_TECHNIQUES``, use it.
       This lets a fixture-driven test pin a specific technique.
    2. Walk ``ROTATION`` and return the first one not in
       ``state.techniques_attempted``.
    3. If all five have been attempted at least once, return the next in
       round-robin order based on ``len(techniques_attempted) % len(ROTATION)``.
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
    seed_idx: int = 0,
    prior_user_messages: list[str] | None = None,
    prior_target_responses: list[str] | None = None,
) -> InjectionProposal:
    """Run one specific specialist. Raises ``KeyError`` if the technique
    is not registered — fail loud so a typo in fixtures surfaces
    immediately rather than silently degrading to a default.

    ``seed_idx`` + ``prior_user_messages`` let the Red Team probe a
    single technique from K distinct angles per plan attempt; see
    :func:`cats.agents.red_team.injection.base.run_specialist_llm`.

    R10 — ``prior_target_responses`` upgrades the prior-message
    threading to a true multi-turn conversation: when supplied, the
    specialist sees what the target said in response to each prior
    turn and crafts a follow-up that reacts to that response."""
    if technique not in _PROPOSERS:
        raise KeyError(
            f"unknown injection technique {technique!r}; known: {sorted(KNOWN_TECHNIQUES)}"
        )
    return await _PROPOSERS[technique](
        llm=llm,
        seed_idx=seed_idx,
        prior_user_messages=prior_user_messages,
        prior_target_responses=prior_target_responses,
    )


async def propose(*, llm: LLMClient, state: CampaignState | None = None) -> InjectionProposal:
    """Pick a technique from ``state`` (or default to ``ignore_previous``
    when no state is provided — preserves R2 callers that don't yet pass
    state) and run its specialist.

    R2 callers used ``propose(llm=...)`` with no state and got the
    monolithic specialist back. The default here mirrors that behavior
    for backward compatibility with the integration test fixtures.
    """
    technique = pick_technique(state) if state is not None else "ignore_previous"
    return await propose_technique(technique=technique, llm=llm)
