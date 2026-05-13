"""Cost accounting for LLM-using graph nodes.

R2 retro flagged three copies of identical AgentCostEntry-append +
``budget_consumed_usd`` increment boilerplate in the judge, red-team router,
and documentation nodes. R3's new mutator would have been a fourth. This
helper centralizes it.

Usage::

    from cats.agents.common import with_cost

    llm_result = await some_call(...)
    with_cost(state, role="mutator_variant", llm_result=llm_result)
"""

from __future__ import annotations

from cats.graph.state import AgentCostEntry, CampaignState
from cats.llm.client import LLMResult


def with_cost(
    state: CampaignState,
    *,
    role: str,
    llm_result: LLMResult,
) -> CampaignState:
    """Record one LLM call's cost against ``state``.

    Appends an :class:`AgentCostEntry` to ``state.per_agent_costs`` and adds
    the call's ``usd_estimate`` to ``state.budget_consumed_usd``. Returns
    the same state object for chaining.
    """
    state.per_agent_costs.append(
        AgentCostEntry(
            role=role,
            model=llm_result.model,
            tokens_in=llm_result.tokens_in,
            tokens_out=llm_result.tokens_out,
            usd=llm_result.usd_estimate,
        )
    )
    state.budget_consumed_usd += llm_result.usd_estimate
    return state
