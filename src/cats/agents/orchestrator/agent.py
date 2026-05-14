"""Orchestrator LangGraph agent.

One :func:`run_orchestrator_agent` call drives one campaign-planning
session to completion. The agent picks tools, drills into coverage /
findings / regressions / prior campaigns, and decides when to call the
terminal :func:`run_submit_plan` tool — autonomously. The worker
supplies the project + budget and consumes the :class:`PlanProposal`.

Topology::

    START → planner → (tool_calls?) → tool_executor → planner → ... → END

Two nodes:

- **planner** — runs the LLM with :data:`ALL_TOOLS` advertised. Returns
  ``messages`` with the assistant turn appended (text + tool_calls).
- **tool_executor** — dispatches each tool call from the latest
  assistant turn through :func:`tools.dispatch`. Appends one
  ``role=tool`` message per call. When :data:`SUBMIT_PLAN` returns a
  validated plan, the outcome is terminal and the next conditional
  edge routes to END.

Stop conditions (in order of preference):

1. The agent calls ``submit_plan`` with a valid plan — its own
   decision, based on enough tool signal to author a defensible plan.
2. USD budget cap hit (:data:`DEFAULT_BUDGET_USD_CAP`, $0.50).
3. Tool-call cap hit (:data:`MAX_TOOL_CALLS`, 30).
4. LLM-turn cap hit (:data:`MAX_AGENT_TURNS`, 20).

Unlike the Red Team agent — which synthesizes a fake
``submit_for_judgment(fail)`` on cap-hit so a transcript still reaches
the Judge — the Orchestrator on cap-hit-without-submit raises
:class:`PlanStructuralError`. The worker's existing ``_mark_plan_failed``
path then surfaces the failure to the operator, who can retry. There
is no "synthesize a fallback plan" path: a half-finished plan is more
dangerous than no plan.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID, uuid4

from langgraph.graph import END, START, StateGraph
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from cats.agents.orchestrator.tools import (
    ALL_TOOLS,
    AgentTurnCost,
    OrchestratorContext,
    dispatch,
)
from cats.db.repositories.audit_repo import write_audit
from cats.llm.client import LLMClient, LLMResult, ToolCall, get_llm
from cats.llm.models import AgentRole
from cats.logging import get_logger
from cats.messaging.envelopes import PlannedCampaign

if TYPE_CHECKING:
    from cats.agents.orchestrator.planner import PlanProposal

log = get_logger(__name__)


# Defense-in-depth caps. None of these are the agent's "target" — the
# agent should call ``submit_plan`` with a valid plan well before any
# of them trips. They exist so a runaway model can't burn unbounded
# spend or wedge the worker.
MAX_AGENT_TURNS: int = 20
MAX_TOOL_CALLS: int = 30
DEFAULT_BUDGET_USD_CAP: float = 0.50


ORCHESTRATOR_ROLE: AgentRole = "orchestrator"


# ---------------------------------------------------------------------------
# Result the worker reads back (mirrors planner.PlanProposal)
# ---------------------------------------------------------------------------
#
# ``PlanProposal`` lives in ``planner.py`` so the worker's
# ``from cats.agents.orchestrator.planner import propose_plan`` import
# surface stays stable. The agent entrypoint constructs and returns it
# at the end of the run.


# ---------------------------------------------------------------------------
# LangGraph state
# ---------------------------------------------------------------------------


class _Message(BaseModel):
    """One chat message carried in the graph state. Flat dict shape so
    the LangGraph checkpointer can serialize it without fighting
    Pydantic union dispatch."""

    model_config = ConfigDict(extra="allow")

    role: str
    content: str = ""
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    tool_call_id: str = ""
    name: str = ""

    def to_openai(self) -> dict[str, Any]:
        out: dict[str, Any] = {"role": self.role, "content": self.content}
        if self.tool_calls:
            out["tool_calls"] = [
                {
                    "id": tc["id"],
                    "type": "function",
                    "function": {
                        "name": tc["name"],
                        "arguments": json.dumps(tc.get("arguments") or {}),
                    },
                }
                for tc in self.tool_calls
            ]
        if self.tool_call_id:
            out["tool_call_id"] = self.tool_call_id
        if self.name:
            out["name"] = self.name
        return out


class _PlannerGraphState(BaseModel):
    """LangGraph state. Holds the message list + a key into the
    process-global :data:`_CTX_HOLDER` (which owns the mutable
    :class:`OrchestratorContext`). The ctx is intentionally NOT part of
    the serializable graph state — the in-memory checkpointer is fine,
    but a Postgres-backed checkpointer would choke on the AsyncSession."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    messages: list[_Message] = Field(default_factory=list)
    ctx_key: str = ""
    finished: bool = False


# Process-global holder for ``OrchestratorContext`` instances keyed by a
# per-session string. The LangGraph state only carries the key; the
# real context lives here so ``AsyncSession`` + ``LLMClient`` don't
# round-trip through the checkpointer.
_CTX_HOLDER: dict[str, OrchestratorContext] = {}


# ---------------------------------------------------------------------------
# System prompt loader
# ---------------------------------------------------------------------------


_SYSTEM_PROMPT_PATH = Path(__file__).parent / "system_prompt.md"
_SYSTEM_PROMPT_TEMPLATE: str = _SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")


def _load_system_prompt(
    *,
    budget_usd: float,
    budget_usd_cap: float,
    max_agent_turns: int,
) -> str:
    """Interpolate the prompt template with the operator's budget (what
    we're planning against), this agent's own LLM-loop spend cap, and
    its turn cap. The agent reads all three so it can pace itself.

    Uses ``str.replace`` rather than ``str.format`` because the prompt
    contains literal ``{...}`` JSON examples that would collide with
    format-string placeholders."""
    return (
        _SYSTEM_PROMPT_TEMPLATE.replace("${budget_usd_cap:.2f}", f"${budget_usd_cap:.2f}")
        .replace("${budget_usd:.2f}", f"${budget_usd:.2f}")
        .replace("{max_agent_turns}", str(max_agent_turns))
    )


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------


def _ctx(state: _PlannerGraphState) -> OrchestratorContext:
    return _CTX_HOLDER[state.ctx_key]


async def _planner_node(state: _PlannerGraphState) -> dict[str, Any]:
    """Call the LLM with the 8 tools advertised. Append the assistant
    turn to messages and record cost on ctx."""
    ctx = _ctx(state)
    llm = ctx.llm
    openai_messages = [m.to_openai() for m in state.messages]
    result: LLMResult = await llm.chat(
        role=ORCHESTRATOR_ROLE,
        messages=openai_messages,
        tools=list(ALL_TOOLS),
        tool_choice="auto",
        max_tokens=1500,
        temperature=0.2,
    )
    ctx.record_cost(role=ORCHESTRATOR_ROLE, result=result)
    if ctx.session is not None:
        await write_audit(
            ctx.session,
            actor="orchestrator_agent",
            action="planner_turn",
            target_kind="campaign" if ctx.campaign_id else "project",
            target_id=ctx.campaign_id or ctx.project_id,
            payload={
                "tool_calls": [tc.name for tc in result.tool_calls],
                "tokens_in": result.tokens_in,
                "tokens_out": result.tokens_out,
                "usd_estimate": result.usd_estimate,
                "model": result.model,
            },
            trace_id=result.trace_id,
        )
    new_msg = _Message(
        role="assistant",
        content=result.text,
        tool_calls=[
            {"id": tc.id, "name": tc.name, "arguments": tc.arguments} for tc in result.tool_calls
        ],
    )
    return {"messages": [*state.messages, new_msg]}


async def _tool_executor_node(state: _PlannerGraphState) -> dict[str, Any]:
    """Dispatch the latest assistant turn's tool_calls. One ``role=tool``
    message per call appended. Pre/post cap checks short-circuit the
    inner loop on a cap trip — without them a parallel-tool-call batch
    could burn past MAX_TOOL_CALLS before the conditional edge sees it."""
    ctx = _ctx(state)
    llm = ctx.llm
    last = state.messages[-1]
    if not last.tool_calls:
        # No tool calls — the conditional edge mis-routed here.
        ctx.stop_reason = ctx.stop_reason or "no_tool_calls"
        return {"messages": state.messages, "finished": True}

    new_messages = list(state.messages)
    terminal_hit = False
    for tc_dict in last.tool_calls:
        # Once the agent has a validated plan, ignore any further calls
        # in the same batch.
        if terminal_hit or ctx.submitted_plan is not None:
            break
        # Budget cap (USD).
        if ctx.budget_consumed_usd >= ctx.budget_usd_cap and ctx.budget_usd_cap > 0:
            ctx.stop_reason = "cap_reached_budget"
            terminal_hit = True
            break
        # Tool-call cap.
        if ctx.tool_call_count >= ctx.max_tool_calls:
            ctx.stop_reason = "cap_reached_tool_calls"
            terminal_hit = True
            break
        tc = ToolCall(
            id=str(tc_dict.get("id") or ""),
            name=str(tc_dict.get("name") or ""),
            arguments=cast(dict[str, Any], tc_dict.get("arguments") or {}),
        )
        outcome = await dispatch(ctx, name=tc.name, args=tc.arguments, llm=llm)
        new_messages.append(
            _Message(
                role="tool",
                tool_call_id=tc.id,
                name=tc.name,
                content=json.dumps(outcome.payload, default=str),
            )
        )
        if ctx.session is not None:
            await write_audit(
                ctx.session,
                actor="orchestrator_agent",
                action=("agent_submitted" if outcome.terminal else f"tool:{tc.name}"),
                target_kind="campaign" if ctx.campaign_id else "project",
                target_id=ctx.campaign_id or ctx.project_id,
                payload={
                    "arguments_keys": sorted((tc.arguments or {}).keys()),
                    "outcome_keys": sorted(outcome.payload.keys()),
                    "submission_attempts": ctx.submission_attempts,
                },
                trace_id=ctx.trace_id,
            )
        if outcome.terminal:
            terminal_hit = True
            # ctx.stop_reason already set by run_submit_plan.
        # Post-dispatch cap checks — the tool itself may have pushed
        # us across a cap.
        if (
            ctx.budget_consumed_usd >= ctx.budget_usd_cap
            and ctx.budget_usd_cap > 0
            and not terminal_hit
        ):
            ctx.stop_reason = "cap_reached_budget"
            terminal_hit = True
        if ctx.tool_call_count >= ctx.max_tool_calls and not terminal_hit:
            ctx.stop_reason = "cap_reached_tool_calls"
            terminal_hit = True
    finished = terminal_hit or ctx.submitted_plan is not None
    return {"messages": new_messages, "finished": finished}


# ---------------------------------------------------------------------------
# Conditional edges
# ---------------------------------------------------------------------------


def _route_after_planner(state: _PlannerGraphState) -> str:
    """If the model emitted no tool calls or burned the LLM-turn cap,
    end. Otherwise hand off to the tool_executor."""
    ctx = _ctx(state)
    last = state.messages[-1] if state.messages else None
    if last is None or last.role != "assistant":
        return END
    if not last.tool_calls:
        # Pure prose with no tool call: treat as a give-up. The agent
        # is required to terminate via submit_plan.
        ctx.stop_reason = ctx.stop_reason or "no_tool_calls"
        return END
    assistant_turns = sum(1 for m in state.messages if m.role == "assistant")
    if assistant_turns >= ctx.max_agent_turns:
        # Will trip the post-tool route check after this dispatch.
        return "tool_executor"
    return "tool_executor"


def _route_after_tools(state: _PlannerGraphState) -> str:
    """If anything terminal happened (submit succeeded, cap tripped),
    end. Otherwise loop back to the planner for the next LLM turn."""
    ctx = _ctx(state)
    if state.finished or ctx.submitted_plan is not None:
        return END
    if ctx.stop_reason and ctx.stop_reason != "agent_submitted":
        return END
    assistant_turns = sum(1 for m in state.messages if m.role == "assistant")
    if assistant_turns >= ctx.max_agent_turns:
        ctx.stop_reason = ctx.stop_reason or "cap_reached_llm_turns"
        return END
    return "planner"


# ---------------------------------------------------------------------------
# Build + run
# ---------------------------------------------------------------------------


def _build_graph() -> Any:
    g: StateGraph[_PlannerGraphState] = StateGraph(_PlannerGraphState)
    g.add_node("planner", _planner_node)
    g.add_node("tool_executor", _tool_executor_node)
    g.add_edge(START, "planner")
    g.add_conditional_edges("planner", _route_after_planner)
    g.add_conditional_edges("tool_executor", _route_after_tools)
    return g.compile()


_COMPILED_GRAPH: Any | None = None


def _get_graph() -> Any:
    global _COMPILED_GRAPH
    if _COMPILED_GRAPH is None:
        _COMPILED_GRAPH = _build_graph()
    return _COMPILED_GRAPH


async def run_orchestrator_agent(
    *,
    llm: LLMClient | None = None,
    session: AsyncSession | None,
    project_id: UUID,
    project_version_id: UUID,
    budget_usd: float,
    campaign_id: UUID | None = None,
    trace_id: str = "",
    budget_usd_cap: float = DEFAULT_BUDGET_USD_CAP,
    max_agent_turns: int = MAX_AGENT_TURNS,
    max_tool_calls: int = MAX_TOOL_CALLS,
) -> PlanProposal:
    """Run one Orchestrator agent session and return a validated
    :class:`PlanProposal`.

    Raises :class:`PlanStructuralError` if the agent never produces a
    validated plan (cap hit, give-up, or unrecoverable graph crash).
    The worker's existing exception path surfaces this to the operator
    as a ``failed`` ``campaign_plans`` row.
    """
    from cats.agents.orchestrator.planner import PlanProposal, PlanStructuralError

    if llm is None:
        llm = get_llm()
    if trace_id == "":
        trace_id = f"orchestrator-{uuid4()}"

    ctx = OrchestratorContext(
        session=session,
        llm=llm,
        project_id=project_id,
        project_version_id=project_version_id,
        trace_id=trace_id,
        budget_usd=budget_usd,
        budget_usd_cap=budget_usd_cap,
        max_agent_turns=max_agent_turns,
        max_tool_calls=max_tool_calls,
        campaign_id=campaign_id,
    )
    ctx_key = f"{campaign_id or project_id}:{trace_id or 'no-trace'}"
    _CTX_HOLDER[ctx_key] = ctx

    system_prompt = _load_system_prompt(
        budget_usd=budget_usd,
        budget_usd_cap=budget_usd_cap,
        max_agent_turns=max_agent_turns,
    )
    initial_state = _PlannerGraphState(
        ctx_key=ctx_key,
        messages=[
            _Message(role="system", content=system_prompt),
            _Message(
                role="user",
                content=(
                    "Author a campaign plan for this project. Start by calling "
                    "list_attack_categories to learn the valid (category, technique) "
                    "pairs. Then gather coverage / open findings / recent regressions "
                    "and any other signal you need (drill into coverage_for_category, "
                    "check recent_campaigns for cross-campaign context). When you have "
                    "enough information to write a rationale that names specific tool "
                    "outputs, call submit_plan."
                ),
            ),
        ],
    )

    if session is not None:
        await write_audit(
            session,
            actor="orchestrator_agent",
            action="agent_started",
            target_kind="campaign" if campaign_id else "project",
            target_id=campaign_id or project_id,
            payload={
                "budget_usd": budget_usd,
                "budget_usd_cap": budget_usd_cap,
                "max_agent_turns": max_agent_turns,
                "max_tool_calls": max_tool_calls,
            },
            trace_id=trace_id,
        )

    try:
        graph = _get_graph()
        await graph.ainvoke(
            initial_state,
            config={"recursion_limit": (max_agent_turns * 2) + 4},
        )
    except Exception as exc:
        log.exception(
            "orchestrator_agent.crashed",
            error=repr(exc),
            project_id=str(project_id),
        )
        if ctx.submitted_plan is None:
            ctx.stop_reason = ctx.stop_reason or "agent_error"
            _CTX_HOLDER.pop(ctx_key, None)
            raise PlanStructuralError(
                f"orchestrator agent crashed before submitting a valid plan: {exc!r}"
            ) from exc
    finally:
        _CTX_HOLDER.pop(ctx_key, None)

    if ctx.submitted_plan is None:
        reason = ctx.stop_reason or "agent_gave_up"
        raise PlanStructuralError(
            f"orchestrator agent stopped without a validated plan (stop_reason={reason!r}); "
            f"submission_attempts={ctx.submission_attempts}, "
            f"tool_calls={ctx.tool_call_count}, "
            f"llm_turns={len(ctx.costs)}, "
            f"usd_consumed={ctx.budget_consumed_usd:.4f}"
        )

    plan: PlannedCampaign = ctx.submitted_plan
    # Cold-start = the agent's coverage/findings/regressions tool calls
    # all returned empty rows. Derive from the transcript so the worker
    # gets the same signal the old planner gave.
    cold_start = _detect_cold_start(ctx.tool_transcript)
    return PlanProposal(
        plan=plan,
        tool_transcript=list(ctx.tool_transcript),
        cost_usd=ctx.cost_usd,
        model=ctx.model,
        trace_id=trace_id,
        cold_start=cold_start,
    )


def _detect_cold_start(transcript: list[dict[str, Any]]) -> bool:
    """The agent has 'no signal to plan against' when the three
    observability tools all returned empty ``rows``. Match the
    pre-LangGraph definition the worker logs."""
    has_coverage = False
    has_findings = False
    has_regressions = False
    for entry in transcript:
        tool = entry.get("tool")
        out = entry.get("output") or {}
        if not isinstance(out, dict):
            continue
        rows = out.get("rows") or []
        if tool == "list_coverage" and rows:
            has_coverage = True
        elif tool == "list_open_findings" and rows:
            has_findings = True
        elif tool == "list_recent_regressions" and rows:
            has_regressions = True
    return not (has_coverage or has_findings or has_regressions)


__all__ = [
    "DEFAULT_BUDGET_USD_CAP",
    "MAX_AGENT_TURNS",
    "MAX_TOOL_CALLS",
    "ORCHESTRATOR_ROLE",
    "AgentTurnCost",
    "run_orchestrator_agent",
]
