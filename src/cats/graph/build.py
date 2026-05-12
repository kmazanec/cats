"""Build the LangGraph state machine.

Topology (matches W3_ARCHITECTURE.md §7):
    orchestrator → red_team_router → mutator (optional) → output_filter →
    target_caller → judge → documentation → END

Scaffold version uses stub nodes that thread state correctly but don't
call real LLMs. Each node will get a real implementation in its own
focused task.
"""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, START, StateGraph

from cats.graph.checkpointer import get_checkpointer
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


def build_graph() -> Any:
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
    g.add_edge("output_filter", "target_caller")
    g.add_edge("target_caller", "judge")
    g.add_edge("judge", "documentation")
    g.add_edge("documentation", END)

    return g.compile(checkpointer=get_checkpointer())
