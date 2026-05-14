"""Documentation Agent — LangGraph rollup-report graph.

The documenter is now a proper LangGraph agent, modeled on the Red
Team's :mod:`cats.agents.red_team.agent`. Two nodes drive the
campaign-report tool loop:

- **author** — invokes the documentation LLM with the report tool
  catalog. Appends one assistant turn (text + tool_calls) to the
  graph state.
- **tool_executor** — dispatches the tool calls from the latest
  assistant turn (data lookups, SVG renders, ``finish_report``).
  Appends one ``role=tool`` message per call.

Topology::

    START → author → (tool_calls?) → tool_executor → author → ... → END

Stop conditions:

1. The agent calls ``finish_report`` — its own decision, body_markdown
   is the final report.
2. The optional ``keep_alive_hook`` returns ``False`` (worker lost its
   bus claim, operator cancelled).
3. ``max_turns`` budget exhausted — the writer falls back to a
   deterministic minimal report so the operator always sees *something*.

Side effects (artifact persistence, audit log) all happen via the
tools; this module is the graph driver. The graph is compiled lazily
and cached process-wide.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast
from uuid import UUID

from langgraph.graph import END, START, StateGraph
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from cats.agents.documentation import campaign_tools as ct
from cats.config import get_settings
from cats.db.repositories.campaign_report_artifact_repo import (
    delete_artifacts,
    upsert_artifact,
)
from cats.llm.client import LLMClient, LLMResult, ToolCall
from cats.logging import get_logger

log = get_logger(__name__)


# Optional async hook the agent calls at the top of every author turn.
# Returning ``False`` aborts the loop — workers pass a hook that calls
# ``self.touch_claim`` so a long LLM tool loop doesn't trigger a false
# redelivery. Returning ``True``/``None`` continues normally.
KeepAliveHook = Callable[[int], Awaitable[bool | None]]


# NB: the campaign rollup prompt is a SEPARATE file from
# ``system_prompt.md``. That file is the per-finding writer's prompt
# (the Documentation Agent's other workload); the campaign-rollup
# prompt has different requirements (talks in runs, names every run,
# coverage charts, etc.) so it lives standalone.
_SYSTEM_PROMPT_PATH = Path(__file__).parent / "campaign_system_prompt.md"


def _load_system_prompt() -> str:
    """Read the campaign-rollup system prompt from disk. The prompt is
    checked into the repo so a non-engineer can iterate on tone /
    structure without a Python deploy."""
    return _SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Result returned to the worker
# ---------------------------------------------------------------------------


@dataclass
class CampaignReportResult:
    """What the agent returns to the worker. The worker persists this
    via ``campaign_report_repo.mark_report_completed``."""

    body_markdown: str
    artifacts: list[dict[str, Any]]
    tool_transcript: list[dict[str, Any]]
    model: str
    tokens_in: int
    tokens_out: int
    usd_estimate: float
    used_fallback: bool = False
    fallback_reason: str = ""


# ---------------------------------------------------------------------------
# Mutable context the graph nodes share. Not part of the LangGraph
# state — see _CTX_HOLDER below for the rationale.
# ---------------------------------------------------------------------------


@dataclass
class DocumenterContext:
    """Side-effect-bearing context the documenter graph nodes share.

    Kept out of the LangGraph state so the postgres checkpointer
    (which serializes state) never needs to round-trip an AsyncSession
    or repository handles. Replaces the loose ``_LoopState`` of the
    pre-agent writer."""

    session: AsyncSession
    campaign_id: UUID
    llm: LLMClient
    keep_alive_hook: KeepAliveHook | None = None
    max_turns: int = 16

    # Running totals — the worker reads these back after the graph runs.
    tokens_in: int = 0
    tokens_out: int = 0
    usd_estimate: float = 0.0
    model: str = ""
    body_markdown: str | None = None
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    tool_transcript: list[dict[str, Any]] = field(default_factory=list)
    finished: bool = False
    aborted_reason: str = ""


# Process-global holder for DocumenterContext keyed by a per-invocation
# uuid string. The LangGraph state carries only the key. Mirrors the
# Red Team agent's approach — keeps AsyncSession out of the serialized
# graph state.
_CTX_HOLDER: dict[str, DocumenterContext] = {}


# ---------------------------------------------------------------------------
# LangGraph state
# ---------------------------------------------------------------------------


class _Message(BaseModel):
    """One chat message carried in the graph state. Flat dict shape so
    it survives the langgraph checkpointer's serialization."""

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


class _DocGraphState(BaseModel):
    """Graph state — messages + a ctx key. The DocumenterContext lives
    in ``_CTX_HOLDER`` so it stays out of the checkpointer."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    messages: list[_Message] = Field(default_factory=list)
    ctx_key: str = ""
    finished: bool = False
    turn: int = 0


def _ctx(state: _DocGraphState) -> DocumenterContext:
    return _CTX_HOLDER[state.ctx_key]


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------


async def _author_node(state: _DocGraphState) -> dict[str, Any]:
    """One LLM author turn. Fires the keep-alive hook (if any) before
    burning more tokens; aborts cleanly when the hook says claim lost."""
    ctx = _ctx(state)
    turn = state.turn

    if ctx.keep_alive_hook is not None:
        ok = await ctx.keep_alive_hook(turn)
        if ok is False:
            log.warning(
                "campaign_report.aborted_by_hook",
                campaign_id=str(ctx.campaign_id),
                turn=turn,
            )
            ctx.aborted_reason = "writer aborted by keep-alive hook (likely a lost bus claim)"
            ctx.finished = True
            return {"finished": True, "turn": turn + 1}

    if turn >= ctx.max_turns:
        ctx.finished = True
        return {"finished": True, "turn": turn}

    tools = ct.report_tool_catalog()
    openai_messages = [m.to_openai() for m in state.messages]
    result: LLMResult = await ctx.llm.chat(
        role="documentation",
        messages=openai_messages,
        tools=tools,
        max_tokens=4000,
        temperature=0.2,
    )
    ctx.model = result.model
    ctx.tokens_in += result.tokens_in
    ctx.tokens_out += result.tokens_out
    ctx.usd_estimate += result.usd_estimate

    new_msg = _Message(
        role="assistant",
        content=result.text or "",
        tool_calls=[
            {"id": tc.id, "name": tc.name, "arguments": tc.arguments} for tc in result.tool_calls
        ],
    )

    if not result.tool_calls and not (result.text or "").strip():
        # The model said nothing — bail rather than loop forever.
        log.warning(
            "campaign_report.empty_turn",
            campaign_id=str(ctx.campaign_id),
            turn=turn,
        )
        ctx.finished = True
        return {
            "messages": [*state.messages, new_msg],
            "finished": True,
            "turn": turn + 1,
        }

    if not result.tool_calls:
        # Free-form text without finish_report. If we have budget left,
        # nudge the model once; otherwise treat the prose as the body.
        if turn >= ctx.max_turns - 1:
            ctx.body_markdown = result.text
            ctx.finished = True
            return {
                "messages": [*state.messages, new_msg],
                "finished": True,
                "turn": turn + 1,
            }
        nudge = _Message(
            role="user",
            content=(
                "Call tools to gather facts, then finish_report. "
                "Free-form text without finish_report does not "
                "produce a saved report."
            ),
        )
        return {
            "messages": [*state.messages, new_msg, nudge],
            "turn": turn + 1,
        }

    return {"messages": [*state.messages, new_msg], "turn": turn + 1}


async def _tool_executor_node(state: _DocGraphState) -> dict[str, Any]:
    """Dispatch the latest assistant turn's tool_calls. One ``role=tool``
    message per call appended; setting ``finished`` when the assistant
    called ``finish_report``."""
    ctx = _ctx(state)
    last = state.messages[-1] if state.messages else None
    if last is None or not last.tool_calls:
        # Conditional edge mis-routed — defensive no-op.
        return {"finished": True}

    new_messages = list(state.messages)
    finished_local = False
    for tc_dict in last.tool_calls:
        tc = ToolCall(
            id=str(tc_dict.get("id") or ""),
            name=str(tc_dict.get("name") or ""),
            arguments=cast(dict[str, Any], tc_dict.get("arguments") or {}),
        )
        tool_result = await _dispatch_tool(tc, ctx=ctx)
        ctx.tool_transcript.append(
            {
                "turn": state.turn - 1,
                "tool": tc.name,
                "arguments": tc.arguments,
                "result_excerpt": _excerpt(tool_result),
            }
        )
        new_messages.append(
            _Message(
                role="tool",
                tool_call_id=tc.id,
                name=tc.name,
                content=ct.serialize_tool_result(tool_result),
            )
        )
        if tc.name == "finish_report":
            ctx.body_markdown = str(tc.arguments.get("body_markdown") or "")
            finished_local = True
            # Any subsequent tool calls in the same batch are ignored —
            # the prompt is explicit that finish_report is terminal.
            break
    if finished_local:
        ctx.finished = True
    return {"messages": new_messages, "finished": finished_local}


# ---------------------------------------------------------------------------
# Conditional edges
# ---------------------------------------------------------------------------


def _route_after_author(state: _DocGraphState) -> str:
    """If the model emitted no tool calls (and we didn't already nudge
    it in the same node) we're done. Otherwise dispatch tools."""
    ctx = _ctx(state)
    if ctx.finished:
        return END
    last = state.messages[-1] if state.messages else None
    if last is None or last.role != "assistant":
        return END
    if not last.tool_calls:
        # author appended either a nudge (and we should loop back for
        # the next LLM turn) or treated the prose as the body (in
        # which case ctx.finished is already True and the early-out
        # above caught it).
        return "author"
    return "tool_executor"


def _route_after_tools(state: _DocGraphState) -> str:
    """End when finish_report fired; otherwise loop back to the author
    for another turn."""
    ctx = _ctx(state)
    if state.finished or ctx.finished:
        return END
    if state.turn >= ctx.max_turns:
        ctx.finished = True
        return END
    return "author"


# ---------------------------------------------------------------------------
# Tool dispatcher
# ---------------------------------------------------------------------------


async def _dispatch_tool(tc: ToolCall, *, ctx: DocumenterContext) -> Any:
    """Run one tool call and return its result. Render tools persist
    the SVG to ``campaign_report_artifacts`` and return the artifact
    descriptor the LLM uses to reference it in markdown. Tool errors
    are returned as ``{"error": "..."}`` so the LLM can retry or skip
    the data point without crashing the graph."""
    args = tc.arguments or {}
    try:
        if tc.name == "data_campaign_summary":
            return await ct.data_campaign_summary(ctx.session, campaign_id=ctx.campaign_id)
        if tc.name == "data_run_outcomes":
            return await ct.data_run_outcomes(ctx.session, campaign_id=ctx.campaign_id)
        if tc.name == "data_verdict_breakdown":
            return await ct.data_verdict_breakdown(ctx.session, campaign_id=ctx.campaign_id)
        if tc.name == "data_findings":
            return await ct.data_findings(ctx.session, campaign_id=ctx.campaign_id)
        if tc.name == "data_recent_failures":
            limit = int(args.get("limit", 10))
            return await ct.data_recent_failures(
                ctx.session, campaign_id=ctx.campaign_id, limit=limit
            )
        if tc.name == "data_cost_breakdown":
            return await ct.data_cost_breakdown(ctx.session, campaign_id=ctx.campaign_id)
        if tc.name == "data_timeline":
            limit = int(args.get("limit", 60))
            return await ct.data_timeline(ctx.session, campaign_id=ctx.campaign_id, limit=limit)
        if tc.name == "render_verdict_histogram":
            return await _persist_artifact(
                ctx,
                kind="verdict-histogram",
                svg=ct.render_verdict_histogram(args.get("verdict_breakdown") or {}),
                title=str(args.get("title") or "Verdict breakdown"),
            )
        if tc.name == "render_cost_breakdown":
            return await _persist_artifact(
                ctx,
                kind="cost-breakdown",
                svg=ct.render_cost_breakdown(args.get("cost") or {}),
                title=str(args.get("title") or "Cost breakdown"),
            )
        if tc.name == "render_coverage_heatmap":
            return await _persist_artifact(
                ctx,
                kind="coverage-heatmap",
                svg=ct.render_coverage_heatmap(args.get("verdict_breakdown") or {}),
                title=str(args.get("title") or "Coverage heatmap"),
            )
        if tc.name == "render_timeline":
            return await _persist_artifact(
                ctx,
                kind="timeline",
                svg=ct.render_timeline(args.get("timeline") or {}),
                title=str(args.get("title") or "Run timeline"),
            )
        if tc.name == "finish_report":
            return {"ok": True}
        return {"error": f"unknown tool: {tc.name}"}
    except Exception as e:  # pragma: no cover - defensive
        log.exception("campaign_report.tool_error", tool=tc.name)
        return {"error": f"{type(e).__name__}: {e}"}


async def _persist_artifact(
    ctx: DocumenterContext, *, kind: str, svg: str, title: str
) -> dict[str, Any]:
    """Save the SVG to ``campaign_report_artifacts`` and append to the
    context's artifact list. Returns the descriptor the LLM embeds in
    markdown via ``![alt](name)``."""
    base = kind
    existing = {a["name"].removesuffix(".svg") for a in ctx.artifacts}
    name = base
    i = 1
    while name in existing:
        i += 1
        name = f"{base}-{i}"
    filename = f"{name}.svg"
    await upsert_artifact(
        ctx.session,
        campaign_id=ctx.campaign_id,
        name=filename,
        kind=kind,
        title=title,
        alt=title,
        body=svg,
    )
    artifact = {
        "name": filename,
        "kind": kind,
        "path": filename,
        "title": title,
        "alt": title,
    }
    ctx.artifacts.append(artifact)
    return {"path": filename, "alt": title, "name": filename}


def _excerpt(payload: Any, *, limit: int = 400) -> str:
    """Trim a tool result for the persisted transcript so we don't
    bloat the row with full SVG bodies or large query results."""
    try:
        s = json.dumps(payload, default=str)
    except (TypeError, ValueError):
        s = str(payload)
    return s[:limit]


# ---------------------------------------------------------------------------
# Build + run
# ---------------------------------------------------------------------------


def _build_graph() -> Any:
    g: StateGraph[_DocGraphState] = StateGraph(_DocGraphState)
    g.add_node("author", _author_node)
    g.add_node("tool_executor", _tool_executor_node)
    g.add_edge(START, "author")
    g.add_conditional_edges("author", _route_after_author)
    g.add_conditional_edges("tool_executor", _route_after_tools)
    return g.compile()


_COMPILED_GRAPH: Any | None = None


def _get_graph() -> Any:
    global _COMPILED_GRAPH
    if _COMPILED_GRAPH is None:
        _COMPILED_GRAPH = _build_graph()
    return _COMPILED_GRAPH


async def run_documenter_agent(
    *,
    llm: LLMClient,
    session: AsyncSession,
    campaign_id: UUID,
    keep_alive_hook: KeepAliveHook | None = None,
    max_turns: int | None = None,
) -> CampaignReportResult:
    """Drive the documenter graph to completion. Returns the rendered
    report + the side-effect totals the worker logs.

    Replaces the prior hand-rolled tool loop in ``campaign_writer``.
    The public surface is identical (the writer module re-exports
    this as ``write_campaign_report`` for backward compatibility)."""
    settings = get_settings()
    turns_cap = max_turns if max_turns is not None else settings.campaign_report_max_turns

    # Wipe any prior artifact set for this campaign so the regenerated
    # report's artifact URLs reflect what the LLM rendered this round —
    # never a stale chart from a prior attempt.
    await delete_artifacts(session, campaign_id=campaign_id)

    ctx = DocumenterContext(
        session=session,
        campaign_id=campaign_id,
        llm=llm,
        keep_alive_hook=keep_alive_hook,
        max_turns=turns_cap,
    )
    ctx_key = f"docagent:{campaign_id}:{id(ctx)}"
    _CTX_HOLDER[ctx_key] = ctx

    system_prompt = _load_system_prompt()
    initial_state = _DocGraphState(
        ctx_key=ctx_key,
        messages=[
            _Message(role="system", content=system_prompt),
            _Message(
                role="user",
                content=(
                    f"Write the rollup report for campaign_id={campaign_id}.\n"
                    "Call data tools to gather facts (start with "
                    "data_campaign_summary, then data_run_outcomes to "
                    "enumerate every run), render the charts you want to "
                    "embed, then call finish_report with the complete "
                    "markdown body."
                ),
            ),
        ],
    )
    try:
        graph = _get_graph()
        # The graph's natural END is finish_report or an explicit cap.
        # ``recursion_limit`` is langgraph's defense against an infinite
        # node loop; we keep it well above max_turns since one logical
        # turn produces an author + executor pair.
        await graph.ainvoke(
            initial_state,
            config={"recursion_limit": (turns_cap * 2) + 8},
        )
    except Exception:
        log.exception("campaign_report.graph_crashed", campaign_id=str(campaign_id))
        # Fall through to the fallback below.
    finally:
        _CTX_HOLDER.pop(ctx_key, None)

    if ctx.body_markdown is None:
        # Either we hit max turns without finish_report, the keep-alive
        # hook aborted, or the graph crashed. Fall back so the operator
        # still sees something.
        if ctx.aborted_reason:
            reason = ctx.aborted_reason
        else:
            reason = f"LLM did not call finish_report within {ctx.max_turns} turns"
            log.warning(
                "campaign_report.loop_budget_exhausted",
                campaign_id=str(campaign_id),
                turns=ctx.max_turns,
            )
        body = await _fallback_minimal_report(session, campaign_id=campaign_id)
        return CampaignReportResult(
            body_markdown=body,
            artifacts=ctx.artifacts,
            tool_transcript=ctx.tool_transcript,
            model=ctx.model,
            tokens_in=ctx.tokens_in,
            tokens_out=ctx.tokens_out,
            usd_estimate=ctx.usd_estimate,
            used_fallback=True,
            fallback_reason=reason,
        )

    return CampaignReportResult(
        body_markdown=ctx.body_markdown,
        artifacts=ctx.artifacts,
        tool_transcript=ctx.tool_transcript,
        model=ctx.model,
        tokens_in=ctx.tokens_in,
        tokens_out=ctx.tokens_out,
        usd_estimate=ctx.usd_estimate,
    )


async def _fallback_minimal_report(session: AsyncSession, *, campaign_id: UUID) -> str:
    """Deterministic minimal report when the LLM tool loop fails. The
    operator still gets the headline numbers + a flag that the
    automated narrative didn't land."""
    summary = await ct.data_campaign_summary(session, campaign_id=campaign_id)
    outcomes = await ct.data_run_outcomes(session, campaign_id=campaign_id)
    breakdown = await ct.data_verdict_breakdown(session, campaign_id=campaign_id)
    failures = await ct.data_recent_failures(session, campaign_id=campaign_id, limit=10)
    cost = await ct.data_cost_breakdown(session, campaign_id=campaign_id)

    lines: list[str] = []
    lines.append("# Campaign report (fallback)\n")
    lines.append(
        "> The automated documentation tool loop did not produce a narrative "
        "within its budget; this is the deterministic minimal rollup. "
        "Re-run with `POST /campaigns/{id}/report` to retry.\n"
    )
    lines.append("## Summary")
    if "error" not in summary:
        lines.append(f"- Project: **{summary.get('project_name')}**")
        lines.append(f"- Campaign: **{summary.get('campaign_name')}**")
        lines.append(
            f"- Runs: **{summary.get('totals', {}).get('runs', 0)}** "
            f"firing **{summary.get('totals', {}).get('attacks_fired', 0)}** attempts"
        )
        lines.append(f"- Total cost: **${summary.get('totals', {}).get('usd_estimate', 0):.4f}**")
        verdicts = summary.get("verdicts", {}) or {}
        if verdicts:
            lines.append(f"- Verdicts (by run): {verdicts}")
    else:
        lines.append(summary["error"])
    lines.append("")

    if outcomes.get("count", 0):
        lines.append("## Runs")
        for r in outcomes.get("runs", []):
            lines.append(
                f"- `{r.get('category')}/{r.get('technique')}` "
                f"(`{r.get('run_id')}`): **{r.get('verdict')}** — "
                f"{r.get('attacks_fired')} attempt(s)"
            )
        lines.append("")

    lines.append("## Verdicts by category (per run)")
    for cat, techs in (breakdown.get("by_category") or {}).items():
        for tech, verdicts in techs.items():
            lines.append(f"- `{cat}/{tech}`: {verdicts}")
    lines.append("")

    if failures.get("count", 0):
        lines.append("## Inconclusive / failed runs")
        if failures.get("errors"):
            lines.append("### `verdict=error` runs (Judge could not evaluate)")
            for it in failures.get("errors", []):
                lines.append(
                    f"- `{it.get('category')}/{it.get('technique')}` — "
                    f"{(it.get('judge_rationale') or '')[:160]}"
                )
        if failures.get("failed_runs"):
            lines.append("### `run_failed` runs (platform-side failure)")
            for it in failures.get("failed_runs", []):
                lines.append(
                    f"- `{it.get('category')}/{it.get('technique')}` "
                    f"(`{it.get('run_id')}`) — "
                    f"{it.get('attacks_fired')} attempt(s) before failure"
                )
        lines.append("")

    lines.append("## Cost breakdown")
    for r in cost.get("by_role", []):
        lines.append(
            f"- `{r['agent_role']}`: ${r['usd_estimate']:.4f} "
            f"({r['calls']} calls, {r['tokens_in'] + r['tokens_out']:,} tokens)"
        )
    lines.append("")
    return "\n".join(lines)


__all__ = [
    "CampaignReportResult",
    "DocumenterContext",
    "KeepAliveHook",
    "run_documenter_agent",
]
