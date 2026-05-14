"""Orchestrator planner — thin shim over the LangGraph agent.

Historical note: in R4, ``propose_plan`` did the planning itself —
pre-fetch five tool outputs, build a strict-JSON prompt, single LLM
call, validate, retry once. The R10-second-followup refactor moved
the planning loop into a LangGraph agent (:mod:`cats.agents.orchestrator.agent`)
that picks its own tools, drills into the signals that matter, and
self-corrects on validator errors. ``propose_plan`` is now a function-
shaped facade so the bus worker (``cats.workers.orchestrator``) keeps
its existing call site, exception path, and audit keys unchanged.

This module retains the load-bearing pieces the rest of the codebase
imports:

- :class:`PlanProposal` — the dataclass the worker reads.
- :class:`PlanStructuralError` — raised when the agent can't produce a
  validated plan; the worker maps it to a ``failed`` ``campaign_plans``
  row + a ``plan_failed`` UI event.
- :func:`_validate_plan` — the structural validator. The agent's
  ``submit_plan`` tool calls it directly so the
  ``tests/unit/test_orchestrator_planner_validation.py`` pins still
  hold. **Do not duplicate this logic elsewhere.**
- :data:`MAX_ATTEMPTS_PER_PLAN` and :data:`ORCHESTRATOR_MODEL_ROLE` —
  constants other modules reference.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import UUID

from cats.llm.client import LLMClient
from cats.llm.models import AgentRole
from cats.logging import get_logger
from cats.messaging.envelopes import PlanAttempt, PlannedCampaign

log = get_logger(__name__)

# Per ARCHITECTURE.md §4.1. The model registry resolves the family;
# the OpenRouter wrapper handles fallbacks.
ORCHESTRATOR_MODEL_ROLE: AgentRole = "orchestrator"

# The maximum number of attempts the planner is allowed to emit per
# campaign. Bounds blast radius regardless of what the LLM proposes;
# the structural-validation step truncates at this cap.
MAX_ATTEMPTS_PER_PLAN: int = 8


@dataclass(frozen=True)
class PlanProposal:
    """The result of one planning session.

    ``plan`` is the validated, structurally-sound plan ready to emit on
    the bus as ``CampaignPlanProposed``. ``tool_transcript`` is the
    list of ``(tool, args, output)`` triples captured during planning
    — the audit trail an operator sees on the plan-approval page.
    ``cost_usd`` and ``model`` are recorded against the campaign for
    the per-agent cost rollup. ``cold_start`` is True when all three
    observability tools returned empty rows."""

    plan: PlannedCampaign
    tool_transcript: list[dict[str, Any]]
    cost_usd: float
    model: str
    trace_id: str
    cold_start: bool


class PlanStructuralError(ValueError):
    """The agent could not produce a structurally valid plan — unknown
    technique key, budget overflow, cap hit before submit, etc. The
    worker maps this to a ``failed`` ``campaign_plans`` row and a
    ``plan_failed`` UI event."""


async def propose_plan(
    *,
    project_id: UUID,
    project_version_id: UUID,
    budget_usd: float,
    campaign_id: UUID | None = None,
    llm: LLMClient | None = None,
) -> PlanProposal:
    """Produce one validated campaign plan for ``project_id``.

    Thin shim around :func:`cats.agents.orchestrator.agent.run_orchestrator_agent`.
    Signature + exception contract preserved verbatim so the
    ``OrchestratorWorker`` is unchanged.

    Opens its own ``AsyncSession`` for the agent's audit-write side
    effects. The worker also holds a session for the inbound message;
    using a fresh scope here keeps the agent's audit rows + tool
    queries on their own short-lived transaction rather than coupling
    them to the worker's message-claim transaction.
    """
    from cats.agents.orchestrator.agent import run_orchestrator_agent
    from cats.db.engine import session_scope
    from cats.llm.client import get_llm

    if llm is None:
        llm = get_llm()

    async with session_scope() as session:
        return await run_orchestrator_agent(
            llm=llm,
            session=session,
            project_id=project_id,
            project_version_id=project_version_id,
            budget_usd=budget_usd,
            campaign_id=campaign_id,
        )


# ---------------------------------------------------------------------------
# Structural validation (called by the submit_plan tool)
# ---------------------------------------------------------------------------


def _validate_plan(
    *,
    raw: dict[str, Any],
    budget_usd_cap: float,
    catalog: Any,
) -> PlannedCampaign:
    """Structurally validate the agent's candidate plan dict. Raises
    :class:`PlanStructuralError` on any violation rather than silently
    coercing — the operator needs to see the failure.

    Called from the ``submit_plan`` tool
    (``cats.agents.orchestrator.tools.run_submit_plan``). Also pinned
    directly by ``tests/unit/test_orchestrator_planner_validation.py``."""
    # Build a set of valid (category, technique) pairs from the catalog.
    valid_pairs: set[tuple[str, str]] = set()
    for cat in catalog.rows:
        for tech in cat.techniques:
            valid_pairs.add((cat.category, tech))
    if not valid_pairs:  # pragma: no cover - defensive; catalog always populated
        raise PlanStructuralError("attack-category catalog is empty")

    attempts_raw = raw.get("attempts", [])
    if not isinstance(attempts_raw, list) or len(attempts_raw) == 0:
        raise PlanStructuralError("plan.attempts is missing or empty")
    if len(attempts_raw) > MAX_ATTEMPTS_PER_PLAN:
        # Truncate rather than fail — over-eager planners shouldn't
        # block the operator entirely, but we record the trim.
        attempts_raw = attempts_raw[:MAX_ATTEMPTS_PER_PLAN]

    attempts: list[PlanAttempt] = []
    total_budget = 0.0
    for i, a in enumerate(attempts_raw):
        if not isinstance(a, dict):
            raise PlanStructuralError(f"attempts[{i}] is not an object: {a!r}")
        category = str(a.get("category", "")).strip()
        technique = str(a.get("technique", "")).strip()
        if (category, technique) not in valid_pairs:
            raise PlanStructuralError(
                f"attempts[{i}] names unknown (category, technique)=({category!r}, {technique!r}); "
                f"valid pairs include {sorted(valid_pairs)!r}"
            )
        per_budget = float(a.get("per_attempt_budget_usd", 0.50))
        if per_budget < 0:
            raise PlanStructuralError(
                f"attempts[{i}].per_attempt_budget_usd is negative: {per_budget}"
            )
        max_partials = int(a.get("max_consecutive_partials", 2))
        if not 0 <= max_partials <= 10:
            raise PlanStructuralError(
                f"attempts[{i}].max_consecutive_partials out of range: {max_partials}"
            )
        attempts.append(
            PlanAttempt(
                category=category,
                technique=technique,
                per_attempt_budget_usd=per_budget,
                max_consecutive_partials=max_partials,
            )
        )
        total_budget += per_budget

    declared_cap = float(raw.get("budget_usd_cap", budget_usd_cap))
    if declared_cap > budget_usd_cap + 1e-6:
        raise PlanStructuralError(
            f"plan.budget_usd_cap ({declared_cap}) exceeds operator budget ({budget_usd_cap})"
        )
    if total_budget > declared_cap + 1e-6:
        raise PlanStructuralError(
            f"sum(per_attempt_budget_usd)={total_budget:.4f} exceeds budget_usd_cap={declared_cap:.4f}"
        )

    halt_fails = int(raw.get("halt_on_consecutive_fails", 3))
    if not 1 <= halt_fails <= 20:
        raise PlanStructuralError(f"halt_on_consecutive_fails out of range: {halt_fails}")
    halt_errors = int(raw.get("halt_on_judge_errors", 2))
    if not 1 <= halt_errors <= 10:
        raise PlanStructuralError(f"halt_on_judge_errors out of range: {halt_errors}")

    rationale = str(raw.get("rationale", "")).strip()
    if len(rationale) < 30:
        raise PlanStructuralError(
            f"plan.rationale is too short ({len(rationale)} chars); the operator needs context"
        )
    confidence = str(raw.get("confidence", "medium")).strip().lower()
    if confidence not in ("low", "medium", "high"):
        confidence = "medium"

    return PlannedCampaign(
        attempts=attempts,
        rationale=rationale,
        confidence=confidence,
        halt_on_consecutive_fails=halt_fails,
        halt_on_judge_errors=halt_errors,
        budget_usd_cap=declared_cap,
    )


__all__ = [
    "MAX_ATTEMPTS_PER_PLAN",
    "ORCHESTRATOR_MODEL_ROLE",
    "PlanProposal",
    "PlanStructuralError",
    "propose_plan",
]
