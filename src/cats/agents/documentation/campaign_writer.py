"""Campaign-report writer — runs the Documentation LLM in a tool loop.

Architecture: each turn, the LLM either calls one or more tools or
emits a final ``finish_report`` call carrying the markdown body. The
writer:

1. Calls ``data_*`` tools to gather facts from the platform's DB.
2. Calls ``render_*`` tools to produce visual artifacts (SVG strings
   the writer saves under ``settings.campaign_reports_dir/{cid}/``).
3. Calls ``finish_report`` with the assembled markdown.

The loop is bounded by ``settings.campaign_report_max_turns``. If the
LLM never calls ``finish_report`` within the budget, the writer falls
back to a deterministic minimal report (so the operator always gets
*something* even if the LLM misbehaves). Persisted via
``campaign_report_repo``.

The tool catalog and the data/render implementations live in
``campaign_tools``; this module is the orchestration loop.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from cats.agents.documentation import campaign_tools as ct
from cats.config import get_settings
from cats.llm.client import LLMClient, ToolCall, ToolSpec
from cats.logging import get_logger

log = get_logger(__name__)


_SYSTEM_PROMPT = """\
You are the Documentation Agent for CATS — Copilot Automated Tactical
Security. After a campaign finishes (all attacks fired, all verdicts
rendered), you produce ONE rollup report describing what happened.

The report's reader is a senior security engineer + the operator who
launched the campaign. They want:

1. Did the platform actually exercise the target, or did things break?
2. What was tested, and what was the verdict mix?
3. Which findings are open and where can the engineer go to reproduce?
4. Did any attacks land verdict=error (platform couldn't evaluate)?
   These are NOT defensive wins — flag them as actionable.
5. What did this cost?
6. What are the recommended next actions?

Verdict reminder:

- ``pass``    — attack succeeded; defense FAILED. This is a finding.
- ``fail``    — attack failed; defense HELD.
- ``partial`` — partial compliance; Mutator iterates.
- ``error``   — response was not evaluable. Inconclusive. Surface it.

You have a fixed catalog of tools. Use the ``data_*`` tools to gather
facts; use the ``render_*`` tools to produce visual artifacts you embed
in the markdown via ``![alt](path)`` (each render tool returns a
relative path you should use verbatim). When the report is ready,
call ``finish_report`` with the complete markdown body. Do not call
anything after ``finish_report``.

Style: professional, terse, no hedging. Write what the data says.
"""


@dataclass
class CampaignReportResult:
    """What the writer returns to the worker."""

    body_markdown: str
    artifacts: list[dict[str, Any]]
    tool_transcript: list[dict[str, Any]]
    model: str
    tokens_in: int
    tokens_out: int
    usd_estimate: float
    used_fallback: bool = False
    fallback_reason: str = ""


@dataclass
class _LoopState:
    """Mutable bookkeeping for the tool loop. Lives one campaign-report
    invocation."""

    messages: list[dict[str, Any]] = field(default_factory=list)
    transcript: list[dict[str, Any]] = field(default_factory=list)
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    tokens_in: int = 0
    tokens_out: int = 0
    usd_estimate: float = 0.0
    model: str = ""
    body_markdown: str | None = None
    artifacts_dir: Path = field(default_factory=Path)


async def write_campaign_report(
    *,
    llm: LLMClient,
    session: AsyncSession,
    campaign_id: UUID,
) -> CampaignReportResult:
    """Run the writer's tool loop and return the rendered report. The
    caller persists the result via ``campaign_report_repo``."""
    settings = get_settings()
    artifacts_root = Path(settings.campaign_reports_dir) / str(campaign_id) / "artifacts"
    artifacts_root.mkdir(parents=True, exist_ok=True)

    state = _LoopState(artifacts_dir=artifacts_root)
    tools = ct.report_tool_catalog()
    state.messages = [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                f"Write the rollup report for campaign_id={campaign_id}.\n"
                f"Call data tools to gather facts, render tools for any "
                f"charts you want to embed, then finish_report with the "
                f"complete markdown."
            ),
        },
    ]

    max_turns = settings.campaign_report_max_turns
    for turn in range(max_turns):
        result = await llm.chat(
            role="documentation",
            messages=state.messages,
            tools=tools,
            max_tokens=4000,
            temperature=0.2,
        )
        state.model = result.model
        state.tokens_in += result.tokens_in
        state.tokens_out += result.tokens_out
        state.usd_estimate += result.usd_estimate

        if not result.tool_calls and not result.text:
            log.warning(
                "campaign_report.empty_turn",
                campaign_id=str(campaign_id),
                turn=turn,
            )
            break

        # Record the assistant turn into the message history so the LLM
        # sees its own prior tool calls on the next round.
        assistant_msg: dict[str, Any] = {"role": "assistant", "content": result.text or ""}
        if result.tool_calls:
            assistant_msg["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.name,
                        "arguments": json.dumps(tc.arguments),
                    },
                }
                for tc in result.tool_calls
            ]
        state.messages.append(assistant_msg)

        if not result.tool_calls:
            # LLM emitted plain text without finishing. Treat as the
            # body if it looks substantive; otherwise nudge it once.
            if turn == max_turns - 1:
                state.body_markdown = result.text
            else:
                state.messages.append(
                    {
                        "role": "user",
                        "content": (
                            "Call tools to gather facts, then finish_report. "
                            "Free-form text without finish_report does not "
                            "produce a saved report."
                        ),
                    }
                )
            continue

        finished = False
        for tc in result.tool_calls:
            tool_result = await _dispatch_tool(
                tc, session=session, state=state, campaign_id=campaign_id
            )
            state.transcript.append(
                {
                    "turn": turn,
                    "tool": tc.name,
                    "arguments": tc.arguments,
                    "result_excerpt": _excerpt(tool_result),
                }
            )
            state.messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "name": tc.name,
                    "content": ct.serialize_tool_result(tool_result),
                }
            )
            if tc.name == "finish_report":
                state.body_markdown = str(tc.arguments.get("body_markdown") or "")
                finished = True
        if finished:
            break

    if state.body_markdown is None:
        # Hit max turns without finish_report. Fall back so the operator
        # still sees something — minimal markdown summarizing whatever
        # data we have already gathered.
        log.warning(
            "campaign_report.loop_budget_exhausted",
            campaign_id=str(campaign_id),
            turns=max_turns,
        )
        state.body_markdown = await _fallback_minimal_report(session, campaign_id=campaign_id)
        return CampaignReportResult(
            body_markdown=state.body_markdown,
            artifacts=state.artifacts,
            tool_transcript=state.transcript,
            model=state.model,
            tokens_in=state.tokens_in,
            tokens_out=state.tokens_out,
            usd_estimate=state.usd_estimate,
            used_fallback=True,
            fallback_reason=f"LLM did not call finish_report within {max_turns} turns",
        )

    return CampaignReportResult(
        body_markdown=state.body_markdown,
        artifacts=state.artifacts,
        tool_transcript=state.transcript,
        model=state.model,
        tokens_in=state.tokens_in,
        tokens_out=state.tokens_out,
        usd_estimate=state.usd_estimate,
    )


async def _dispatch_tool(
    tc: ToolCall,
    *,
    session: AsyncSession,
    state: _LoopState,
    campaign_id: UUID,
) -> Any:
    """Run one tool call and return its result. Render tools save SVGs
    to disk and return the relative path; data tools return the query
    result dict; finish_report returns a closing confirmation. Tool
    errors are returned as a dict ``{"error": "..."}`` rather than
    raised so the LLM can choose to retry or finish without that data."""
    args = tc.arguments or {}
    try:
        if tc.name == "data_campaign_summary":
            return await ct.data_campaign_summary(session, campaign_id=campaign_id)
        if tc.name == "data_verdict_breakdown":
            return await ct.data_verdict_breakdown(session, campaign_id=campaign_id)
        if tc.name == "data_findings":
            return await ct.data_findings(session, campaign_id=campaign_id)
        if tc.name == "data_recent_failures":
            limit = int(args.get("limit", 10))
            return await ct.data_recent_failures(session, campaign_id=campaign_id, limit=limit)
        if tc.name == "data_cost_breakdown":
            return await ct.data_cost_breakdown(session, campaign_id=campaign_id)
        if tc.name == "data_timeline":
            limit = int(args.get("limit", 60))
            return await ct.data_timeline(session, campaign_id=campaign_id, limit=limit)
        if tc.name == "render_verdict_histogram":
            return _persist_artifact(
                state,
                name="verdict-histogram",
                svg=ct.render_verdict_histogram(args.get("verdict_breakdown") or {}),
                title=str(args.get("title") or "Verdict breakdown"),
            )
        if tc.name == "render_cost_breakdown":
            return _persist_artifact(
                state,
                name="cost-breakdown",
                svg=ct.render_cost_breakdown(args.get("cost") or {}),
                title=str(args.get("title") or "Cost breakdown"),
            )
        if tc.name == "render_coverage_heatmap":
            return _persist_artifact(
                state,
                name="coverage-heatmap",
                svg=ct.render_coverage_heatmap(args.get("verdict_breakdown") or {}),
                title=str(args.get("title") or "Coverage heatmap"),
            )
        if tc.name == "render_timeline":
            return _persist_artifact(
                state,
                name="timeline",
                svg=ct.render_timeline(args.get("timeline") or {}),
                title=str(args.get("title") or "Attack timeline"),
            )
        if tc.name == "finish_report":
            return {"ok": True}
        return {"error": f"unknown tool: {tc.name}"}
    except Exception as e:  # pragma: no cover - defensive
        log.exception("campaign_report.tool_error", tool=tc.name)
        return {"error": f"{type(e).__name__}: {e}"}


def _persist_artifact(state: _LoopState, *, name: str, svg: str, title: str) -> dict[str, Any]:
    """Save the SVG under ``artifacts_dir`` and append to state. Returns
    the artifact descriptor the LLM uses to reference it in markdown."""
    # De-dup repeated render calls — append an index if we've already
    # written a file with this name in this campaign's directory.
    base = name
    existing = {a["name"] for a in state.artifacts}
    i = 1
    while name in existing:
        i += 1
        name = f"{base}-{i}"
    rel_path = f"{name}.svg"
    full_path = state.artifacts_dir / rel_path
    full_path.write_text(svg, encoding="utf-8")
    artifact = {
        "name": name,
        "kind": base,
        "path": rel_path,
        "title": title,
        "alt": title,
    }
    state.artifacts.append(artifact)
    return {"path": rel_path, "alt": title, "name": name}


def _excerpt(payload: Any, *, limit: int = 400) -> str:
    """Trim a tool result for the persisted transcript so we don't
    bloat the row with full SVG bodies or large query results."""
    try:
        s = json.dumps(payload, default=str)
    except (TypeError, ValueError):
        s = str(payload)
    return s[:limit]


async def _fallback_minimal_report(session: AsyncSession, *, campaign_id: UUID) -> str:
    """Deterministic minimal report when the LLM tool loop exhausts its
    budget. Operator still gets the headline numbers + a flag that the
    automated narrative didn't land."""
    summary = await ct.data_campaign_summary(session, campaign_id=campaign_id)
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
            f"- Attacks fired: **{summary.get('totals', {}).get('attacks_fired', 0)}** "
            f"across **{summary.get('totals', {}).get('runs', 0)}** runs"
        )
        lines.append(f"- Total cost: **${summary.get('totals', {}).get('usd_estimate', 0):.4f}**")
        verdicts = summary.get("verdicts", {}) or {}
        if verdicts:
            lines.append(f"- Verdicts: {verdicts}")
    else:
        lines.append(summary["error"])
    lines.append("")

    lines.append("## Verdicts by category")
    for cat, techs in (breakdown.get("by_category") or {}).items():
        for tech, verdicts in techs.items():
            lines.append(f"- `{cat}/{tech}`: {verdicts}")
    lines.append("")

    if failures.get("count", 0):
        lines.append("## Inconclusive runs (verdict=error)")
        lines.append("These attacks could not be evaluated. Not defensive wins.")
        for it in failures.get("errors", []):
            lines.append(
                f"- `{it.get('category')}/{it.get('technique')}` — "
                f"HTTP {it.get('target_status_code')} — "
                f"{(it.get('judge_rationale') or '')[:120]}"
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


__all__ = ["CampaignReportResult", "write_campaign_report"]


# Hint mypy that ToolSpec is intentionally imported (used in type
# hints inside docstrings + future extensions).
_ = ToolSpec
