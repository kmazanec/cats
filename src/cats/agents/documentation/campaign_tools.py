"""Data tools the Documentation Agent's campaign-report writer calls.

Each function in the ``data_*`` family takes a session + a campaign id
and returns a JSON-serializable dict the LLM can consume. The
``render_*`` family returns SVG strings the writer saves to disk and
embeds in the markdown.

These functions are *the entire surface* the report writer's LLM sees.
Anything the LLM wants to know about a campaign has to be queryable
through one of these tools, by design — the report stays grounded in
real platform data and the LLM cannot hallucinate fields that the
queries don't expose.

Verdict semantics reminder (matches the Judge contract):

- ``pass``    — attack succeeded; defense failed.
- ``fail``    — attack failed; defense held.
- ``partial`` — partial compliance; mutator's responsibility.
- ``error``   — response was not evaluable (target errored, empty body,
  unparseable). NOT a defensive win.
"""

from __future__ import annotations

import html
import json
from collections import defaultdict
from typing import Any
from uuid import UUID

from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from cats.db.schema import (
    attack_executions,
    attacks,
    campaigns,
    findings,
    judge_verdicts,
    projects,
    runs,
)
from cats.llm.client import ToolSpec

# ---------------------------------------------------------------------------
# Data tools — read-only queries.
# ---------------------------------------------------------------------------


async def data_campaign_summary(session: AsyncSession, *, campaign_id: UUID) -> dict[str, Any]:
    """High-level rollup: project, mode, trigger, when it ran, how many
    runs / attacks landed in each terminal state, total cost. The
    headline numbers the report leads with."""
    cam = (
        await session.execute(
            select(
                campaigns.c.id,
                campaigns.c.name,
                campaigns.c.mode,
                campaigns.c.trigger,
                campaigns.c.budget,
                campaigns.c.created_at,
                projects.c.name.label("project_name"),
                projects.c.base_url.label("target_base_url"),
            )
            .select_from(campaigns.join(projects, projects.c.id == campaigns.c.project_id))
            .where(campaigns.c.id == campaign_id)
        )
    ).first()
    if cam is None:
        return {"error": f"campaign {campaign_id} not found"}

    run_rows = (
        await session.execute(
            select(
                runs.c.status,
                func.count(runs.c.id).label("n"),
                func.sum(runs.c.attacks_fired).label("attacks_fired"),
                func.sum(runs.c.budget_consumed_usd).label("usd"),
                func.min(runs.c.started_at).label("first_started"),
                func.max(runs.c.ended_at).label("last_ended"),
            )
            .where(runs.c.campaign_id == campaign_id)
            .group_by(runs.c.status)
        )
    ).all()
    run_status: dict[str, dict[str, Any]] = {}
    first_started = None
    last_ended = None
    total_runs = 0
    total_usd = 0.0
    total_attacks = 0
    for r in run_rows:
        run_status[r.status] = {
            "count": int(r.n or 0),
            "attacks_fired": int(r.attacks_fired or 0),
            "usd_estimate": float(r.usd or 0.0),
        }
        total_runs += int(r.n or 0)
        total_usd += float(r.usd or 0.0)
        total_attacks += int(r.attacks_fired or 0)
        if r.first_started is not None and (
            first_started is None or r.first_started < first_started
        ):
            first_started = r.first_started
        if r.last_ended is not None and (last_ended is None or r.last_ended > last_ended):
            last_ended = r.last_ended

    verdict_rows = (
        await session.execute(
            select(judge_verdicts.c.verdict, func.count(judge_verdicts.c.id).label("n"))
            .select_from(
                attack_executions.join(
                    judge_verdicts, judge_verdicts.c.id == attack_executions.c.judge_verdict_id
                ).join(runs, runs.c.id == attack_executions.c.run_id)
            )
            .where(runs.c.campaign_id == campaign_id)
            .group_by(judge_verdicts.c.verdict)
        )
    ).all()
    verdicts = {r.verdict: int(r.n or 0) for r in verdict_rows}

    duration_seconds: float | None = None
    if first_started is not None and last_ended is not None:
        duration_seconds = (last_ended - first_started).total_seconds()

    return {
        "campaign_id": str(cam.id),
        "campaign_name": cam.name,
        "project_name": cam.project_name,
        "target_base_url": cam.target_base_url,
        "mode": cam.mode,
        "trigger": cam.trigger,
        "budget": cam.budget,
        "created_at": cam.created_at.isoformat() if cam.created_at else None,
        "first_started_at": first_started.isoformat() if first_started else None,
        "last_ended_at": last_ended.isoformat() if last_ended else None,
        "duration_seconds": duration_seconds,
        "totals": {
            "runs": total_runs,
            "attacks_fired": total_attacks,
            "usd_estimate": round(total_usd, 4),
        },
        "runs_by_status": run_status,
        "verdicts": verdicts,
    }


async def data_verdict_breakdown(session: AsyncSession, *, campaign_id: UUID) -> dict[str, Any]:
    """Per (category, technique) tally of verdicts. Surfaces which
    techniques landed and how. The headline cell of any coverage view."""
    rows = (
        await session.execute(
            select(
                attacks.c.category,
                attacks.c.payload["technique"].astext.label("technique"),
                judge_verdicts.c.verdict,
                func.count(attack_executions.c.id).label("n"),
            )
            .select_from(
                attack_executions.join(attacks, attacks.c.id == attack_executions.c.attack_id)
                .join(runs, runs.c.id == attack_executions.c.run_id)
                .outerjoin(
                    judge_verdicts, judge_verdicts.c.id == attack_executions.c.judge_verdict_id
                )
            )
            .where(runs.c.campaign_id == campaign_id)
            .group_by(attacks.c.category, "technique", judge_verdicts.c.verdict)
            .order_by(attacks.c.category, "technique")
        )
    ).all()

    breakdown: dict[str, dict[str, dict[str, int]]] = defaultdict(lambda: defaultdict(dict))
    for r in rows:
        verdict = r.verdict or "pending"
        breakdown[r.category][r.technique or "?"][verdict] = int(r.n or 0)
    return {"by_category": {k: dict(v) for k, v in breakdown.items()}}


async def data_findings(session: AsyncSession, *, campaign_id: UUID) -> dict[str, Any]:
    """Open findings produced by this campaign — each one is a
    confirmed exploit the Documentation Agent already wrote a
    per-attack vulnerability report for. The campaign report links
    out to those."""
    rows = (
        await session.execute(
            select(
                findings.c.id,
                findings.c.category,
                findings.c.severity,
                findings.c.title,
                findings.c.signature,
                findings.c.atlas_technique_id,
                findings.c.owasp_llm_id,
                findings.c.created_at,
            )
            .select_from(findings.join(runs, runs.c.id == findings.c.run_id))
            .where(runs.c.campaign_id == campaign_id)
            .order_by(desc(findings.c.created_at))
        )
    ).all()
    return {
        "findings": [
            {
                "finding_id": str(r.id),
                "category": r.category,
                "severity": r.severity,
                "title": r.title,
                "signature": r.signature,
                "atlas_technique_id": r.atlas_technique_id,
                "owasp_llm_id": r.owasp_llm_id,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ],
        "count": len(rows),
    }


async def data_recent_failures(
    session: AsyncSession, *, campaign_id: UUID, limit: int = 10
) -> dict[str, Any]:
    """Attacks that landed ``verdict=error`` — runs the platform fired
    but couldn't actually evaluate. These are the *most* actionable
    items in a report: a defense isn't holding the attack, the platform
    just didn't get a meaningful response. Operator needs to fix the
    plumbing before drawing conclusions about the target."""
    rows = (
        await session.execute(
            select(
                attack_executions.c.id,
                attack_executions.c.run_id,
                attacks.c.category,
                attacks.c.payload["technique"].astext.label("technique"),
                attacks.c.title,
                attack_executions.c.target_status_code,
                attack_executions.c.error,
                attack_executions.c.target_response,
                judge_verdicts.c.rationale,
            )
            .select_from(
                attack_executions.join(attacks, attacks.c.id == attack_executions.c.attack_id)
                .join(runs, runs.c.id == attack_executions.c.run_id)
                .join(judge_verdicts, judge_verdicts.c.id == attack_executions.c.judge_verdict_id)
            )
            .where(runs.c.campaign_id == campaign_id)
            .where(judge_verdicts.c.verdict == "error")
            .order_by(desc(attack_executions.c.created_at))
            .limit(limit)
        )
    ).all()

    items: list[dict[str, Any]] = []
    for r in rows:
        response_excerpt = ""
        if isinstance(r.target_response, dict):
            response_excerpt = str(r.target_response.get("text") or "")[:280]
        items.append(
            {
                "attack_execution_id": str(r.id),
                "run_id": str(r.run_id),
                "category": r.category,
                "technique": r.technique,
                "title": r.title,
                "target_status_code": r.target_status_code,
                "transport_error": r.error,
                "response_excerpt": response_excerpt,
                "judge_rationale": (r.rationale or "")[:280],
            }
        )
    return {"errors": items, "count": len(items)}


async def data_cost_breakdown(session: AsyncSession, *, campaign_id: UUID) -> dict[str, Any]:
    """Tokens + USD broken out by agent role (redteam_injection,
    redteam_exfil, judge, mutator, documentation, ...). The report's
    cost answer to 'how much did this run cost and where did it go.'"""
    rows = (
        await session.execute(
            select(
                attack_executions.c.agent_role,
                func.sum(attack_executions.c.tokens_in).label("tokens_in"),
                func.sum(attack_executions.c.tokens_out).label("tokens_out"),
                func.sum(attack_executions.c.usd_estimate).label("usd"),
                func.count(attack_executions.c.id).label("calls"),
            )
            .select_from(attack_executions.join(runs, runs.c.id == attack_executions.c.run_id))
            .where(runs.c.campaign_id == campaign_id)
            .group_by(attack_executions.c.agent_role)
            .order_by(desc("usd"))
        )
    ).all()
    by_role = [
        {
            "agent_role": r.agent_role or "unknown",
            "tokens_in": int(r.tokens_in or 0),
            "tokens_out": int(r.tokens_out or 0),
            "usd_estimate": round(float(r.usd or 0.0), 4),
            "calls": int(r.calls or 0),
        }
        for r in rows
    ]
    total_usd: float = sum(float(b["usd_estimate"]) for b in by_role)
    total_tokens_in: int = sum(int(b["tokens_in"]) for b in by_role)
    total_tokens_out: int = sum(int(b["tokens_out"]) for b in by_role)
    return {
        "by_role": by_role,
        "totals": {
            "usd_estimate": round(total_usd, 4),
            "tokens_in": total_tokens_in,
            "tokens_out": total_tokens_out,
        },
    }


async def data_timeline(
    session: AsyncSession, *, campaign_id: UUID, limit: int = 60
) -> dict[str, Any]:
    """Chronological log of runs and their per-attack verdicts. The
    report uses this to narrate 'what happened in what order' — what
    each agent did, when, and what came of it (PRD observability
    requirement)."""
    rows = (
        await session.execute(
            select(
                runs.c.id.label("run_id"),
                runs.c.status,
                runs.c.started_at,
                runs.c.ended_at,
                attacks.c.category,
                attacks.c.payload["technique"].astext.label("technique"),
                judge_verdicts.c.verdict,
            )
            .select_from(
                runs.outerjoin(attack_executions, attack_executions.c.run_id == runs.c.id)
                .outerjoin(attacks, attacks.c.id == attack_executions.c.attack_id)
                .outerjoin(
                    judge_verdicts, judge_verdicts.c.id == attack_executions.c.judge_verdict_id
                )
            )
            .where(runs.c.campaign_id == campaign_id)
            .order_by(runs.c.started_at)
            .limit(limit)
        )
    ).all()
    items = [
        {
            "run_id": str(r.run_id),
            "status": r.status,
            "started_at": r.started_at.isoformat() if r.started_at else None,
            "ended_at": r.ended_at.isoformat() if r.ended_at else None,
            "category": r.category,
            "technique": r.technique,
            "verdict": r.verdict,
        }
        for r in rows
    ]
    return {"timeline": items, "count": len(items)}


# ---------------------------------------------------------------------------
# Artifact tools — render SVG strings the writer saves + embeds.
# ---------------------------------------------------------------------------

_VERDICT_COLORS = {
    "pass": "#dc2626",  # red — attacker won, defender lost
    "fail": "#16a34a",  # green — defense held
    "partial": "#f59e0b",  # amber — mid-state
    "error": "#6b7280",  # gray — inconclusive
    "pending": "#9ca3af",
}
_AGENT_COLORS = {
    "redteam_injection": "#7c3aed",
    "redteam_exfil": "#a855f7",
    "redteam_indirect_injection": "#c084fc",
    "redteam_mutator": "#ec4899",
    "judge": "#0ea5e9",
    "documentation": "#0d9488",
    "orchestrator": "#f59e0b",
    "unknown": "#6b7280",
}


def _svg_header(width: int, height: int, title: str = "") -> str:
    """Common SVG envelope. Inline styles keep the file render-anywhere
    (no external CSS dependency from the served page)."""
    safe_title = html.escape(title)
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
        f'role="img" aria-label="{safe_title}">'
        f"<style>"
        f"text {{ font: 12px ui-sans-serif, system-ui, -apple-system, sans-serif; fill: #1f2937; }}"
        f".title {{ font-weight: 600; font-size: 14px; }}"
        f".muted {{ fill: #6b7280; }}"
        f"</style>"
    )


def _svg_footer() -> str:
    return "</svg>"


def render_verdict_histogram(verdict_breakdown: dict[str, Any]) -> str:
    """Stacked bar per category showing the verdict mix.

    ``verdict_breakdown`` is the dict ``data_verdict_breakdown``
    returns. We aggregate down to per-category totals; the by-technique
    drilldown is dense enough that a stacked-by-technique chart would
    be illegible — keep it summary-level."""
    by_cat = verdict_breakdown.get("by_category") or {}
    if not by_cat:
        return _empty_svg("No attacks fired in this campaign.")

    # Aggregate per-category totals.
    cats: list[tuple[str, dict[str, int]]] = []
    for cat, techs in by_cat.items():
        totals: dict[str, int] = defaultdict(int)
        for verdicts in techs.values():
            for v, n in verdicts.items():
                totals[v] += n
        cats.append((cat, dict(totals)))
    cats.sort(key=lambda kv: -sum(kv[1].values()))

    width = 720
    row_h = 40
    pad_x = 160
    pad_y = 50
    height = pad_y + row_h * len(cats) + 30

    max_total = max((sum(v.values()) for _, v in cats), default=1) or 1
    bar_max_w = width - pad_x - 30

    parts: list[str] = [_svg_header(width, height, "Verdict breakdown by category")]
    parts.append('<text x="20" y="28" class="title">Verdicts by category</text>')

    # Legend
    legend_x = pad_x
    legend_y = 30
    for v, c in _VERDICT_COLORS.items():
        if v == "pending":
            continue
        parts.append(f'<rect x="{legend_x}" y="{legend_y - 9}" width="10" height="10" fill="{c}"/>')
        parts.append(f'<text x="{legend_x + 14}" y="{legend_y}">{v}</text>')
        legend_x += 80

    for i, (cat, totals) in enumerate(cats):
        y = pad_y + i * row_h
        parts.append(f'<text x="20" y="{y + 20}" font-weight="600">{html.escape(cat)}</text>')
        total = sum(totals.values())
        x_cursor = pad_x
        for verdict in ("pass", "fail", "partial", "error"):
            count = totals.get(verdict, 0)
            if count == 0:
                continue
            w = max(2, int(bar_max_w * count / max_total))
            color = _VERDICT_COLORS.get(verdict, "#9ca3af")
            parts.append(
                f'<rect x="{x_cursor}" y="{y + 6}" width="{w}" height="20" '
                f'fill="{color}"><title>{verdict}={count}</title></rect>'
            )
            if w > 28:
                parts.append(
                    f'<text x="{x_cursor + 6}" y="{y + 20}" fill="white" font-size="11">{count}</text>'
                )
            x_cursor += w
        parts.append(f'<text x="{x_cursor + 8}" y="{y + 20}" class="muted">n={total}</text>')

    parts.append(_svg_footer())
    return "".join(parts)


def render_cost_breakdown(cost: dict[str, Any]) -> str:
    """Horizontal-bar breakdown of cost by agent role."""
    rows = cost.get("by_role") or []
    if not rows:
        return _empty_svg("No LLM calls recorded.")

    width = 720
    row_h = 30
    pad_x = 220
    pad_y = 50
    height = pad_y + row_h * len(rows) + 20

    max_usd = max((r["usd_estimate"] for r in rows), default=0.0) or 1.0
    bar_max_w = width - pad_x - 80

    parts: list[str] = [_svg_header(width, height, "Cost breakdown by agent role")]
    parts.append('<text x="20" y="28" class="title">Cost by agent</text>')
    parts.append(
        f'<text x="{width - 20}" y="28" text-anchor="end" class="muted">'
        f"total ${cost.get('totals', {}).get('usd_estimate', 0):.4f}</text>"
    )

    for i, r in enumerate(rows):
        y = pad_y + i * row_h
        role = r["agent_role"]
        color = _AGENT_COLORS.get(role, _AGENT_COLORS["unknown"])
        parts.append(f'<text x="20" y="{y + 18}">{html.escape(role)}</text>')
        w = max(2, int(bar_max_w * r["usd_estimate"] / max_usd))
        parts.append(
            f'<rect x="{pad_x}" y="{y + 6}" width="{w}" height="18" fill="{color}">'
            f"<title>{role}: ${r['usd_estimate']:.4f}, calls={r['calls']}</title></rect>"
        )
        parts.append(
            f'<text x="{pad_x + w + 8}" y="{y + 19}" class="muted">'
            f"${r['usd_estimate']:.4f} · {r['calls']} calls · "
            f"{r['tokens_in'] + r['tokens_out']:,} tokens</text>"
        )
    parts.append(_svg_footer())
    return "".join(parts)


def render_coverage_heatmap(verdict_breakdown: dict[str, Any]) -> str:
    """Grid: category (rows) by technique (cols). Each cell is colored
    by its dominant verdict (most-frequent). Empty cells mean a
    (category, technique) pair wasn't touched by this campaign."""
    by_cat = verdict_breakdown.get("by_category") or {}
    if not by_cat:
        return _empty_svg("No coverage data.")

    techniques: list[str] = []
    seen: set[str] = set()
    for techs in by_cat.values():
        for t in techs:
            if t not in seen:
                seen.add(t)
                techniques.append(t)
    cats = sorted(by_cat.keys())

    cell_w = 60
    cell_h = 32
    pad_left = 180
    pad_top = 90
    width = pad_left + cell_w * max(1, len(techniques)) + 20
    height = pad_top + cell_h * len(cats) + 30

    parts: list[str] = [_svg_header(width, height, "Coverage heatmap")]
    parts.append('<text x="20" y="28" class="title">Coverage heatmap</text>')
    parts.append(
        '<text x="20" y="46" class="muted">'
        "cell color = dominant verdict for that (category, technique)</text>"
    )

    # Column headers — rotated 45°.
    for j, tech in enumerate(techniques):
        cx = pad_left + j * cell_w + cell_w // 2
        parts.append(
            f'<text x="{cx}" y="{pad_top - 8}" text-anchor="end" '
            f'transform="rotate(-45 {cx} {pad_top - 8})" font-size="11">'
            f"{html.escape(tech[:24])}</text>"
        )

    # Rows.
    for i, cat in enumerate(cats):
        y = pad_top + i * cell_h
        parts.append(
            f'<text x="{pad_left - 8}" y="{y + cell_h // 2 + 4}" text-anchor="end" '
            f'font-weight="600">{html.escape(cat)}</text>'
        )
        for j, tech in enumerate(techniques):
            x = pad_left + j * cell_w
            cell = by_cat.get(cat, {}).get(tech)
            if not cell:
                parts.append(
                    f'<rect x="{x}" y="{y}" width="{cell_w - 2}" height="{cell_h - 2}" '
                    f'fill="#f3f4f6" stroke="#e5e7eb"/>'
                )
                continue
            dominant = max(cell.items(), key=lambda kv: kv[1])
            n_total = sum(cell.values())
            color = _VERDICT_COLORS.get(dominant[0], "#9ca3af")
            parts.append(
                f'<rect x="{x}" y="{y}" width="{cell_w - 2}" height="{cell_h - 2}" '
                f'fill="{color}" opacity="0.85">'
                f"<title>{cat}/{tech}: {dominant[0]}={dominant[1]} (n={n_total})</title>"
                f"</rect>"
            )
            parts.append(
                f'<text x="{x + (cell_w - 2) // 2}" y="{y + cell_h // 2 + 4}" '
                f'text-anchor="middle" fill="white" font-size="11" font-weight="600">'
                f"{n_total}</text>"
            )

    parts.append(_svg_footer())
    return "".join(parts)


def render_timeline(timeline: dict[str, Any]) -> str:
    """Horizontal dot-plot: x = time since campaign start, y = run
    index. Each dot's color = verdict; hover surfaces (category,
    technique, verdict). Useful for spotting clumps of failures or
    cost spikes."""
    items = timeline.get("timeline") or []
    if not items:
        return _empty_svg("No runs.")

    starts = [it["started_at"] for it in items if it["started_at"]]
    ends = [it["ended_at"] for it in items if it["ended_at"]]
    if not starts:
        return _empty_svg("No timing data on runs.")

    from datetime import datetime

    def _parse(ts: str) -> datetime:
        # tolerate fractional seconds + timezone suffix
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))

    t0 = min(_parse(s) for s in starts)
    t1 = max(_parse(s) for s in (ends or starts))
    span = max(1.0, (t1 - t0).total_seconds())

    width = 720
    pad_left = 80
    pad_top = 40
    height = pad_top + 14 * len(items) + 30

    parts: list[str] = [_svg_header(width, height, "Attack timeline")]
    parts.append('<text x="20" y="28" class="title">Attack timeline</text>')

    for i, it in enumerate(items):
        if not it["started_at"]:
            continue
        y = pad_top + i * 14
        x_start = _parse(it["started_at"])
        rel = (x_start - t0).total_seconds() / span
        x = pad_left + int((width - pad_left - 20) * rel)
        color = _VERDICT_COLORS.get(it.get("verdict") or "pending", "#9ca3af")
        cat = it.get("category") or "?"
        tech = it.get("technique") or "?"
        verdict = it.get("verdict") or "pending"
        parts.append(
            f'<circle cx="{x}" cy="{y}" r="4" fill="{color}">'
            f"<title>{cat}/{tech} → {verdict} @ {it['started_at']}</title>"
            f"</circle>"
        )
        parts.append(
            f'<text x="{pad_left - 6}" y="{y + 4}" text-anchor="end" class="muted" font-size="10">'
            f"#{i + 1}</text>"
        )

    parts.append(f'<text x="{pad_left}" y="{height - 12}" class="muted">{t0.isoformat()}</text>')
    parts.append(
        f'<text x="{width - 20}" y="{height - 12}" class="muted" text-anchor="end">'
        f"{t1.isoformat()}</text>"
    )
    parts.append(_svg_footer())
    return "".join(parts)


def _empty_svg(message: str) -> str:
    return (
        _svg_header(420, 100, message)
        + f'<text x="20" y="50" class="muted">{html.escape(message)}</text>'
        + _svg_footer()
    )


# ---------------------------------------------------------------------------
# Tool catalog — what the LLM sees in its system prompt.
# ---------------------------------------------------------------------------


def report_tool_catalog() -> list[ToolSpec]:
    """The tools the campaign-report writer's LLM may call. Order
    matters only for prompt readability; the LLM picks its own
    sequence. Schemas are intentionally tight: every input is a
    constant from the campaign's row (campaign_id) so the model can't
    accidentally query the wrong campaign."""
    return [
        ToolSpec(
            name="data_campaign_summary",
            description=(
                "Top-level rollup for the campaign currently being reported on: "
                "project, mode, when it started/ended, run/attack/verdict totals, "
                "total cost. Call this first — its output is the headline."
            ),
            parameters={"type": "object", "properties": {}, "required": []},
        ),
        ToolSpec(
            name="data_verdict_breakdown",
            description=(
                "Per (category, technique) verdict tally. Use to write the "
                "'what we tested and how it went' body of the report."
            ),
            parameters={"type": "object", "properties": {}, "required": []},
        ),
        ToolSpec(
            name="data_findings",
            description=(
                "List of confirmed-exploit Findings this campaign produced "
                "(severity, ATLAS/OWASP labels, signature). Each finding has "
                "its own vulnerability report — link them by finding_id."
            ),
            parameters={"type": "object", "properties": {}, "required": []},
        ),
        ToolSpec(
            name="data_recent_failures",
            description=(
                "Attacks the Judge ruled 'error' (the platform could not "
                "evaluate the response — invalid envelope, transport error, "
                "empty body, etc). These are NOT defensive wins; they are "
                "platform actionables. Always surface them in the report."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 10}
                },
                "required": [],
            },
        ),
        ToolSpec(
            name="data_cost_breakdown",
            description=(
                "USD + tokens spent in this campaign, broken out by agent "
                "role. Use for the cost section."
            ),
            parameters={"type": "object", "properties": {}, "required": []},
        ),
        ToolSpec(
            name="data_timeline",
            description=(
                "Chronological log of runs and per-attack verdicts in this "
                "campaign. Use to write the 'what happened in what order' "
                "narrative."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 60}
                },
                "required": [],
            },
        ),
        ToolSpec(
            name="render_verdict_histogram",
            description=(
                "Render a stacked-bar SVG showing the verdict mix per category. "
                "Pass the dict returned by data_verdict_breakdown. The tool "
                "saves the SVG to disk and returns a relative path + alt text "
                "you embed in the markdown via "
                "![alt](path)."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "verdict_breakdown": {
                        "type": "object",
                        "description": "Exactly the dict data_verdict_breakdown returned.",
                    },
                    "title": {"type": "string"},
                },
                "required": ["verdict_breakdown"],
            },
        ),
        ToolSpec(
            name="render_cost_breakdown",
            description=(
                "Render a horizontal-bar SVG of cost by agent role. Pass the "
                "dict returned by data_cost_breakdown."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "cost": {"type": "object"},
                    "title": {"type": "string"},
                },
                "required": ["cost"],
            },
        ),
        ToolSpec(
            name="render_coverage_heatmap",
            description=(
                "Render a category x technique grid SVG. Cells are colored "
                "by their dominant verdict. Pass the dict from "
                "data_verdict_breakdown."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "verdict_breakdown": {"type": "object"},
                    "title": {"type": "string"},
                },
                "required": ["verdict_breakdown"],
            },
        ),
        ToolSpec(
            name="render_timeline",
            description=(
                "Render a horizontal timeline dot-plot. Pass the dict from data_timeline."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "timeline": {"type": "object"},
                    "title": {"type": "string"},
                },
                "required": ["timeline"],
            },
        ),
        ToolSpec(
            name="finish_report",
            description=(
                "Emit the final markdown report. Call this exactly once "
                "after gathering data + rendering whichever artifacts you "
                "want to embed. Embed artifacts via standard markdown image "
                "syntax: ![alt](relative-path-returned-by-render-tool). "
                "Do not call any tools after finish_report."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "body_markdown": {
                        "type": "string",
                        "description": (
                            "The complete report body in markdown. Should "
                            "cover: campaign summary, what was tested, what "
                            "the verdicts showed, open findings, platform "
                            "errors (verdict=error attacks), cost, and a "
                            "short 'recommended next actions' section."
                        ),
                    },
                },
                "required": ["body_markdown"],
            },
        ),
    ]


def serialize_tool_result(payload: Any) -> str:
    """Standard wire format for tool results sent back to the LLM —
    JSON with sorted keys + default str fallback for UUID/datetime."""
    return json.dumps(payload, sort_keys=True, default=str)
