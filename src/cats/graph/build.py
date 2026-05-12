"""Build the LangGraph state machine.

Topology (matches ARCHITECTURE.md §2.2):
    orchestrator → red_team_router → mutator → output_filter →
    target_caller → judge → documentation → END

The output_filter -> target_caller edge is conditional: when the filter
quarantines the payload, the graph short-circuits to documentation
without firing at the live target.
"""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, START, StateGraph

from cats.graph.checkpointer import get_inmemory_checkpointer
from cats.graph.nodes import (
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


def build_graph(*, checkpointer: Any | None = None) -> Any:
    """Compile the graph. Callers pass in a checkpointer (PostgresSaver
    for real runs, InMemorySaver for tests/smoke). When omitted, falls
    back to the in-memory saver."""
    g: StateGraph[CampaignState] = StateGraph(CampaignState)

    g.add_node("orchestrator", orchestrator.run)
    g.add_node("red_team_router", red_team_router.run)
    g.add_node("mutator", mutator.run)
    g.add_node("output_filter", output_filter.run)
    g.add_node("target_caller", target_caller.run)
    g.add_node("judge", judge.run)
    g.add_node("documentation", documentation.run)

    g.add_edge(START, "orchestrator")
    g.add_edge("orchestrator", "red_team_router")
    g.add_edge("red_team_router", "mutator")
    g.add_edge("mutator", "output_filter")
    g.add_conditional_edges("output_filter", _route_after_filter)
    g.add_edge("target_caller", "judge")
    g.add_edge("judge", "documentation")
    g.add_edge("documentation", END)

    return g.compile(checkpointer=checkpointer or get_inmemory_checkpointer())
