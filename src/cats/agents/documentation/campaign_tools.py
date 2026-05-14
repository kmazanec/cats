"""Data + render tools the Documentation Agent's campaign-report
writer calls.

Each ``data_*`` function takes a session + a campaign id and returns
a JSON-serializable dict the LLM consumes. The ``render_*`` family
returns SVG strings; the writer persists them under
``campaign_report_artifacts`` (Postgres, served by the api directly —
no shared filesystem with the worker).

The unit of analysis is the **run** (one (category, technique)
scenario in the Week-3 brief sense), not the attack execution. The
R10-followup Red Team agent fires N executions inside one run (one
per conversation turn) and the Judge rules **once** over the whole
conversation, attaching its verdict to the *decisive* execution row.
So joining ``attack_executions`` against ``judge_verdicts`` directly
would tally one verdict per run but N nulls for the non-decisive
turns — the model would then report "N pending attempts" for a run
the platform actually finished. These tools always speak in runs.

Verdict semantics reminder (matches the Judge contract):

- ``pass``    — attack succeeded; defense failed. This is a finding.
- ``fail``    — attack failed; defense held.
- ``partial`` — partial compliance; mutator's responsibility.
- ``error``   — response was not evaluable (target errored, empty body,
  unparseable). NOT a defensive win.
- ``run_failed`` — the run itself failed (status='failed') and no
  Judge verdict was rendered. Platform-side issue, not a defense.
- ``unjudged``  — run finished but no verdict was attached (the agent
  never submitted, or the Judge dropped the message). Surface
  separately so they aren't silently bucketed as "pending forever".
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
# Run-centric helpers — used by multiple data tools.
# ---------------------------------------------------------------------------

# Verdicts the report bucket synthesizes for runs that didn't produce
# a Judge verdict, so they aren't lost in aggregation.
_VERDICT_RUN_FAILED = "run_failed"
_VERDICT_UNJUDGED = "unjudged"


async def _per_run_rows(session: AsyncSession, *, campaign_id: UUID) -> list[dict[str, Any]]:
    """Return one row per run in the campaign, joined to its terminal
    Judge verdict (if any) and the first attack's (category, technique)
    so the report has a useful label to write against. The first
    execution row by ``seed_idx`` defines the run's scenario; the
    Judge's row is reached through ``judge_verdict_id`` on whichever
    execution carried the submission.

    Returns rows whose verdict has been canonicalized to one of the
    extended set documented at the top of this module — never a NULL
    that the LLM would have to guess at."""
    # Per-run scenario label: the attack on the first execution
    # (seed_idx = min) is the prompt the agent led with — the right
    # name to call the scenario by.
    label_q = (
        select(
            attack_executions.c.run_id.label("run_id"),
            attacks.c.category.label("category"),
            attacks.c.payload["technique"].astext.label("technique"),
            attacks.c.title.label("attack_title"),
        )
        .select_from(attack_executions.join(attacks, attacks.c.id == attack_executions.c.attack_id))
        .where(
            attack_executions.c.seed_idx
            == select(func.min(attack_executions.c.seed_idx))
            .where(attack_executions.c.run_id == runs.c.id)
            .correlate(runs)
            .scalar_subquery()
        )
        .subquery("run_label")
    )

    # Per-run verdict: a run has at most one judge_verdicts row reached
    # via attack_executions.judge_verdict_id. Pick it.
    verdict_q = (
        select(
            attack_executions.c.run_id.label("run_id"),
            judge_verdicts.c.verdict.label("verdict"),
            judge_verdicts.c.rationale.label("rationale"),
            judge_verdicts.c.exploitability.label("exploitability"),
            judge_verdicts.c.decisive_seed_idx.label("decisive_seed_idx"),
            judge_verdicts.c.total_seeds.label("total_seeds"),
        )
        .select_from(
            attack_executions.join(
                judge_verdicts,
                judge_verdicts.c.id == attack_executions.c.judge_verdict_id,
            )
        )
        .subquery("run_verdict")
    )

    rows = (
        await session.execute(
            select(
                runs.c.id.label("run_id"),
                runs.c.status.label("run_status"),
                runs.c.started_at.label("started_at"),
                runs.c.ended_at.label("ended_at"),
                runs.c.attacks_fired.label("attacks_fired"),
                runs.c.budget_consumed_usd.label("usd_estimate"),
                label_q.c.category,
                label_q.c.technique,
                label_q.c.attack_title,
                verdict_q.c.verdict,
                verdict_q.c.rationale,
                verdict_q.c.exploitability,
                verdict_q.c.decisive_seed_idx,
                verdict_q.c.total_seeds,
            )
            .select_from(
                runs.outerjoin(label_q, label_q.c.run_id == runs.c.id).outerjoin(
                    verdict_q, verdict_q.c.run_id == runs.c.id
                )
            )
            .where(runs.c.campaign_id == campaign_id)
            .order_by(runs.c.started_at.nulls_last(), runs.c.id)
        )
    ).all()

    out: list[dict[str, Any]] = []
    for r in rows:
        verdict = r.verdict
        if verdict is None:
            verdict = _VERDICT_RUN_FAILED if r.run_status == "failed" else _VERDICT_UNJUDGED
        out.append(
            {
                "run_id": str(r.run_id),
                "run_status": r.run_status,
                "category": r.category,
                "technique": r.technique,
                "attack_title": r.attack_title,
                "attacks_fired": int(r.attacks_fired or 0),
                "usd_estimate": round(float(r.usd_estimate or 0.0), 4),
                "started_at": r.started_at.isoformat() if r.started_at else None,
                "ended_at": r.ended_at.isoformat() if r.ended_at else None,
                "verdict": verdict,
                "judge_rationale": (r.rationale or "")[:400],
                "exploitability": r.exploitability,
                "decisive_seed_idx": r.decisive_seed_idx,
                "total_seeds": r.total_seeds,
            }
        )
    return out


# ---------------------------------------------------------------------------
# Data tools — read-only queries.
# ---------------------------------------------------------------------------


async def data_campaign_summary(session: AsyncSession, *, campaign_id: UUID) -> dict[str, Any]:
    """Headline rollup: project, mode, when it ran, run counts broken
    out by **terminal Judge verdict** (not by execution row), total
    cost. Runs without a Judge verdict are bucketed as ``run_failed``
    when the run itself failed, ``unjudged`` otherwise — never silently
    dropped or grouped as "pending"."""
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

    per_run = await _per_run_rows(session, campaign_id=campaign_id)
    total_runs = len(per_run)
    total_attacks = sum(r["attacks_fired"] for r in per_run)
    total_usd = sum(r["usd_estimate"] for r in per_run)
    verdicts: dict[str, int] = defaultdict(int)
    runs_by_status: dict[str, int] = defaultdict(int)
    first_started: str | None = None
    last_ended: str | None = None
    for r in per_run:
        verdicts[r["verdict"]] += 1
        runs_by_status[r["run_status"]] += 1
        if r["started_at"] and (first_started is None or r["started_at"] < first_started):
            first_started = r["started_at"]
        if r["ended_at"] and (last_ended is None or r["ended_at"] > last_ended):
            last_ended = r["ended_at"]

    duration_seconds: float | None = None
    if first_started and last_ended:
        from datetime import datetime

        try:
            t0 = datetime.fromisoformat(first_started.replace("Z", "+00:00"))
            t1 = datetime.fromisoformat(last_ended.replace("Z", "+00:00"))
            duration_seconds = (t1 - t0).total_seconds()
        except ValueError:
            duration_seconds = None

    return {
        "campaign_id": str(cam.id),
        "campaign_name": cam.name,
        "project_name": cam.project_name,
        "target_base_url": cam.target_base_url,
        "mode": cam.mode,
        "trigger": cam.trigger,
        "budget": cam.budget,
        "created_at": cam.created_at.isoformat() if cam.created_at else None,
        "first_started_at": first_started,
        "last_ended_at": last_ended,
        "duration_seconds": duration_seconds,
        "totals": {
            "runs": total_runs,
            "attacks_fired": total_attacks,
            "usd_estimate": round(total_usd, 4),
        },
        "runs_by_status": dict(runs_by_status),
        # verdicts is by RUN (one terminal verdict per run), with synthetic
        # 'run_failed' / 'unjudged' buckets that account for every run.
        "verdicts": dict(verdicts),
    }


async def data_run_outcomes(session: AsyncSession, *, campaign_id: UUID) -> dict[str, Any]:
    """The canonical per-run outcome list. One row per run, including
    runs that failed or were never judged — the report writer should
    walk this to enumerate every run in the campaign in its narrative."""
    per_run = await _per_run_rows(session, campaign_id=campaign_id)
    return {"runs": per_run, "count": len(per_run)}


async def data_verdict_breakdown(session: AsyncSession, *, campaign_id: UUID) -> dict[str, Any]:
    """Per (category, technique) tally of **run** verdicts. Runs that
    never got a Judge verdict are surfaced as ``run_failed`` (the run
    failed before submission) or ``unjudged`` (run completed, agent
    never submitted / Judge dropped the message). Categories whose
    runs all failed appear with the same status they were attempted
    under — they no longer vanish from the report."""
    per_run = await _per_run_rows(session, campaign_id=campaign_id)
    breakdown: dict[str, dict[str, dict[str, int]]] = defaultdict(
        lambda: defaultdict(lambda: defaultdict(int))
    )
    for r in per_run:
        cat = r["category"] or "?"
        tech = r["technique"] or "?"
        breakdown[cat][tech][r["verdict"]] += 1
    return {
        "by_category": {k: {t: dict(v) for t, v in techs.items()} for k, techs in breakdown.items()}
    }


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
    """Runs the Judge ruled ``error`` — runs the platform fired but
    couldn't actually evaluate. NOT defensive wins; platform
    actionables. The report should always surface them.

    Also include ``run_failed`` runs (the platform-side failure case)
    so the report can call those out separately — they look superficially
    like errors but represent a different class of problem."""
    per_run = await _per_run_rows(session, campaign_id=campaign_id)
    errored = [r for r in per_run if r["verdict"] == "error"][:limit]
    failed = [r for r in per_run if r["verdict"] == _VERDICT_RUN_FAILED][:limit]
    return {
        "errors": [
            {
                "run_id": r["run_id"],
                "category": r["category"],
                "technique": r["technique"],
                "title": r["attack_title"],
                "judge_rationale": r["judge_rationale"],
            }
            for r in errored
        ],
        "failed_runs": [
            {
                "run_id": r["run_id"],
                "category": r["category"],
                "technique": r["technique"],
                "title": r["attack_title"],
                "attacks_fired": r["attacks_fired"],
            }
            for r in failed
        ],
        "count": len(errored) + len(failed),
    }


async def data_cost_breakdown(session: AsyncSession, *, campaign_id: UUID) -> dict[str, Any]:
    """Tokens + USD broken out by agent role (redteam_injection,
    redteam_exfil, judge, mutator, documentation, ...). Cost is summed
    over execution rows — for cost, the per-execution granularity is
    the right one (every LLM call we made shows up here)."""
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
    """Chronological per-RUN log. One row per run with its terminal
    verdict — matches what an operator reads as 'what happened in
    what order'. Limit truncates to ``limit`` runs (most recent
    campaigns rarely exceed this)."""
    per_run = await _per_run_rows(session, campaign_id=campaign_id)
    items = per_run[:limit]
    return {
        "timeline": [
            {
                "run_id": r["run_id"],
                "status": r["run_status"],
                "started_at": r["started_at"],
                "ended_at": r["ended_at"],
                "category": r["category"],
                "technique": r["technique"],
                "verdict": r["verdict"],
                "attacks_fired": r["attacks_fired"],
            }
            for r in items
        ],
        "count": len(items),
    }


# ---------------------------------------------------------------------------
# Artifact tools — render SVG strings the writer persists + embeds.
# ---------------------------------------------------------------------------

_VERDICT_COLORS = {
    "pass": "#dc2626",  # red — attacker won, defender lost
    "fail": "#16a34a",  # green — defense held
    "partial": "#f59e0b",  # amber — mid-state
    "error": "#6b7280",  # gray — inconclusive
    "run_failed": "#991b1b",  # dark red — platform failure
    "unjudged": "#64748b",  # slate — no verdict ever rendered
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
    (no external CSS dependency from the served page).

    The palette is tuned for the CATS dashboard's dark theme — text
    fills are light (matching ``--ink``/``--ink-2`` in
    ``tokens.css``). A panel-tinted backdrop ``<rect>`` is included
    so the artifact stays legible when viewed standalone (e.g.
    fetched directly from the artifact-serving route) without
    relying on the surrounding page background.
    """
    safe_title = html.escape(title)
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
        f'role="img" aria-label="{safe_title}">'
        f"<style>"
        f"text {{ font: 12px ui-sans-serif, system-ui, -apple-system, sans-serif; "
        f"fill: #e7ecf5; }}"
        f".title {{ font-weight: 600; font-size: 14px; fill: #f8fafc; }}"
        f".muted {{ fill: #aab3c6; }}"
        f"</style>"
        f'<rect x="0" y="0" width="{width}" height="{height}" fill="#0f1424"/>'
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
        return _empty_svg("No runs in this campaign.")

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
    pad_y = 70
    height = pad_y + row_h * len(cats) + 30

    max_total = max((sum(v.values()) for _, v in cats), default=1) or 1
    bar_max_w = width - pad_x - 30

    parts: list[str] = [_svg_header(width, height, "Verdict breakdown by category")]
    parts.append('<text x="20" y="28" class="title">Verdicts by category (per run)</text>')

    legend_x = pad_x
    legend_y = 48
    for v, c in _VERDICT_COLORS.items():
        parts.append(f'<rect x="{legend_x}" y="{legend_y - 9}" width="10" height="10" fill="{c}"/>')
        parts.append(f'<text x="{legend_x + 14}" y="{legend_y}" font-size="11">{v}</text>')
        legend_x += 86

    for i, (cat, totals) in enumerate(cats):
        y = pad_y + i * row_h
        parts.append(f'<text x="20" y="{y + 20}" font-weight="600">{html.escape(cat)}</text>')
        total = sum(totals.values())
        x_cursor = pad_x
        for verdict in ("pass", "fail", "partial", "error", "unjudged", "run_failed"):
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
                    f'<text x="{x_cursor + 6}" y="{y + 20}" fill="white" '
                    f'font-size="11">{count}</text>'
                )
            x_cursor += w
        parts.append(f'<text x="{x_cursor + 8}" y="{y + 20}" class="muted">n={total} runs</text>')

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

    for j, tech in enumerate(techniques):
        cx = pad_left + j * cell_w + cell_w // 2
        parts.append(
            f'<text x="{cx}" y="{pad_top - 8}" text-anchor="end" '
            f'transform="rotate(-45 {cx} {pad_top - 8})" font-size="11">'
            f"{html.escape(tech[:24])}</text>"
        )

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
                    f'fill="#131a2e" stroke="#2a3756"/>'
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
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))

    t0 = min(_parse(s) for s in starts)
    t1 = max(_parse(s) for s in (ends or starts))
    span = max(1.0, (t1 - t0).total_seconds())

    width = 720
    pad_left = 80
    pad_top = 40
    height = pad_top + 14 * len(items) + 30

    parts: list[str] = [_svg_header(width, height, "Run timeline")]
    parts.append('<text x="20" y="28" class="title">Run timeline</text>')

    for i, it in enumerate(items):
        if not it["started_at"]:
            continue
        y = pad_top + i * 14
        x_start = _parse(it["started_at"])
        rel = (x_start - t0).total_seconds() / span
        x = pad_left + int((width - pad_left - 20) * rel)
        color = _VERDICT_COLORS.get(it.get("verdict") or "unjudged", "#9ca3af")
        cat = it.get("category") or "?"
        tech = it.get("technique") or "?"
        verdict = it.get("verdict") or "unjudged"
        parts.append(
            f'<circle cx="{x}" cy="{y}" r="4" fill="{color}">'
            f"<title>{cat}/{tech} → {verdict} @ {it['started_at']}</title>"
            f"</circle>"
        )
        parts.append(
            f'<text x="{pad_left - 6}" y="{y + 4}" text-anchor="end" class="muted" '
            f'font-size="10">#{i + 1}</text>'
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
    constant from the campaign's row (campaign_id is implicit, baked
    into the dispatcher) so the model can't accidentally query the
    wrong campaign."""
    return [
        ToolSpec(
            name="data_campaign_summary",
            description=(
                "Top-level rollup for the campaign currently being reported on: "
                "project, mode, when it started/ended, run/attack/verdict totals "
                "(verdict counts are PER RUN — synthetic 'run_failed' / "
                "'unjudged' buckets account for runs without a Judge verdict), "
                "total cost. Call this first — its output is the headline."
            ),
            parameters={"type": "object", "properties": {}, "required": []},
        ),
        ToolSpec(
            name="data_run_outcomes",
            description=(
                "The canonical per-run outcome list — one row per run in this "
                "campaign, including failed runs and runs the Judge never "
                "scored. Walk this to enumerate every run in the report's "
                "per-run breakdown."
            ),
            parameters={"type": "object", "properties": {}, "required": []},
        ),
        ToolSpec(
            name="data_verdict_breakdown",
            description=(
                "Per (category, technique) verdict tally — verdicts counted in "
                "RUNS, not in individual execution rows. Use to write the "
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
                "Two lists: runs the Judge ruled 'error' (response not "
                "evaluable — invalid envelope, transport error, empty body), "
                "and runs whose status is 'failed' (the platform never "
                "submitted them for judgment). Neither is a defensive win; "
                "both are platform actionables. Always surface them."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 50,
                        "default": 10,
                    }
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
                "Chronological per-RUN log with terminal verdicts in this "
                "campaign. Use to write the 'what happened in what order' "
                "narrative."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 200,
                        "default": 60,
                    }
                },
                "required": [],
            },
        ),
        ToolSpec(
            name="render_verdict_histogram",
            description=(
                "Render a stacked-bar SVG showing the verdict mix per category "
                "(bars are RUN counts). Pass the dict returned by "
                "data_verdict_breakdown. The tool persists the SVG to Postgres "
                "and returns a relative name + alt text you embed in the "
                "markdown via ![alt](name.svg)."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "verdict_breakdown": {
                        "type": "object",
                        "description": ("Exactly the dict data_verdict_breakdown returned."),
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
                "by their dominant verdict (RUN counts). Pass the dict from "
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
                "Render a horizontal timeline dot-plot of RUNS (one dot per "
                "run, color = terminal verdict). Pass the dict from data_timeline."
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
                "syntax: ![alt](name-returned-by-render-tool). "
                "Do not call any tools after finish_report."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "body_markdown": {
                        "type": "string",
                        "description": (
                            "The complete report body in markdown. Should "
                            "cover: campaign summary, every run accounted for "
                            "(do not silently drop run_failed / unjudged "
                            "runs — name them), what the verdicts showed, "
                            "open findings, platform errors, cost, and a "
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
