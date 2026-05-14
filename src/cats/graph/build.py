"""Build the LangGraph state machine.

Topology (matches ARCHITECTURE.md §2.2; R3 wires the partial→mutate loop)::

    orchestrator → red_team_router → mutator → output_filter
                                                    │
                                          ┌─────────┴─────────┐
                                          │                   │
                                          ▼                   ▼
                                     target_caller       documentation  (filter quarantined)
                                          │
                                          ▼
                                        judge
                                          │
                                ┌─────────┴─────────┐
                                │                   │
                          (partial &&         (else: pass/fail or
                           cap not hit)        partial cap hit)
                                │                   │
                                ▼                   ▼
                             mutator           documentation → END

Two conditional edges:

1. ``output_filter → {target_caller, documentation}`` (R2): a quarantined
   payload never reaches the live target.
2. ``judge → {mutator, documentation}`` (R3): a ``partial`` verdict
   loops back through the Mutator for variant generation, bounded by
   ``MAX_CONSECUTIVE_PARTIALS``.
"""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, START, StateGraph

from cats.agents.mutator import MAX_CONSECUTIVE_PARTIALS
from cats.graph.checkpointer import get_inmemory_checkpointer
from cats.graph.nodes import (
    briefing_kickoff,
    documentation,
    judge,
    mutator,
    orchestrator,
    output_filter,
    red_team_router,
    target_caller,
)
from cats.graph.state import CampaignState


def _route_after_filter(state: CampaignState) -> str:
    """If the output filter quarantined the payload, skip the live-target
    call and go straight to documentation. Otherwise fire the attack."""
    if state.output_filter_verdict in ("dangerous", "attack_payload"):
        return "documentation"
    return "target_caller"


def _route_after_judge(state: CampaignState) -> str:
    """R3: loop back through the Mutator on ``partial`` verdicts, bounded
    by ``MAX_CONSECUTIVE_PARTIALS``. On ``pass``, ``fail``, or when the
    cap is reached, advance to documentation as before."""
    if (
        state.last_verdict == "partial"
        and state.consecutive_partial_count < MAX_CONSECUTIVE_PARTIALS
    ):
        return "mutator"
    return "documentation"


def build_graph(*, checkpointer: Any | None = None) -> Any:
    """Compile the graph. Callers pass in a checkpointer (PostgresSaver
    for real runs, InMemorySaver for tests/smoke). When omitted, falls
    back to the in-memory saver."""
    g: StateGraph[CampaignState] = StateGraph(CampaignState)

    g.add_node("orchestrator", orchestrator.run)
    g.add_node("briefing_kickoff", briefing_kickoff.run)
    g.add_node("red_team_router", red_team_router.run)
    g.add_node("mutator", mutator.run)
    g.add_node("output_filter", output_filter.run)
    g.add_node("target_caller", target_caller.run)
    g.add_node("judge", judge.run)
    g.add_node("documentation", documentation.run)

    g.add_edge(START, "orchestrator")
    # Kickoff runs once per Run, after the orchestrator has selected a
    # technique but before the specialist drafts an attack. The captured
    # conversationId rides into every subsequent target_caller invocation
    # (mutate-loop variants too) as task=follow_up.
    g.add_edge("orchestrator", "briefing_kickoff")
    g.add_edge("briefing_kickoff", "red_team_router")
    g.add_edge("red_team_router", "mutator")
    g.add_edge("mutator", "output_filter")
    g.add_conditional_edges("output_filter", _route_after_filter)
    g.add_edge("target_caller", "judge")
    g.add_conditional_edges("judge", _route_after_judge)
    g.add_edge("documentation", END)

    return g.compile(checkpointer=checkpointer or get_inmemory_checkpointer())
