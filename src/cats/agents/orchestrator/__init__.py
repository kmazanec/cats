"""Orchestrator agent — campaign planner.

The Orchestrator is a LangGraph tool-using agent that calls the
observability tool surface (coverage, findings, regressions, prior
campaigns, drill-downs) and emits a validated ``PlannedCampaign`` via
the terminal ``submit_plan`` tool. The bus worker invokes
:func:`propose_plan` (a thin shim over :func:`run_orchestrator_agent`)
so the message-pipeline call site stays unchanged across the refactor.

Public surface:

- :func:`propose_plan` — bus-worker entry point. Returns a
  :class:`PlanProposal` or raises :class:`PlanStructuralError`.
- :func:`run_orchestrator_agent` — direct LangGraph entrypoint for
  tests, the CLI, and any future caller that already owns its own
  ``AsyncSession``.
- :class:`PlanProposal`, :class:`PlanStructuralError` — the dataclass
  + exception the worker reads.
"""

from cats.agents.orchestrator.agent import run_orchestrator_agent
from cats.agents.orchestrator.planner import (
    MAX_ATTEMPTS_PER_PLAN,
    ORCHESTRATOR_MODEL_ROLE,
    PlanProposal,
    PlanStructuralError,
    propose_plan,
)

__all__ = [
    "MAX_ATTEMPTS_PER_PLAN",
    "ORCHESTRATOR_MODEL_ROLE",
    "PlanProposal",
    "PlanStructuralError",
    "propose_plan",
    "run_orchestrator_agent",
]
