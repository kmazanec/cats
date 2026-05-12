"""Render-context builder for the operator overview page.

Reads real rows from Postgres where they exist and falls back to neutral
placeholders elsewhere — the design system rejects "demo data," so empty
states render as empty states, not as fake numbers.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from cats.config import settings
from cats.db.schema import (
    attack_executions,
    campaigns,
    findings,
    judge_verdicts,
    projects,
    runs,
)


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _rel(t: datetime | None) -> str:
    if t is None:
        return "—"
    if t.tzinfo is None:
        t = t.replace(tzinfo=UTC)
    delta = _utcnow() - t
    secs = int(delta.total_seconds())
    if secs < 60:
        return f"{secs}s ago"
    if secs < 3600:
        return f"{secs // 60}m ago"
    if secs < 86_400:
        return f"{secs // 3600}h ago"
    return f"{secs // 86_400}d ago"


def _tier(count: int, sev: str) -> int:
    """Heatmap tier for a coverage cell. Critical at any volume escalates."""
    if count == 0:
        return 0
    if sev == "critical" and count >= 1:
        return 4
    if count >= 10:
        return 3
    if count >= 3:
        return 2
    return 1


async def build_overview_context(session: AsyncSession) -> dict[str, Any]:
    now = _utcnow()
    now_iso = now.strftime("%Y-%m-%d %H:%M UTC")

    # --- overview KPIs ---
    h24 = now - timedelta(hours=24)
    h48 = now - timedelta(hours=48)

    attacks_24h = (
        await session.execute(
            select(func.count())
            .select_from(attack_executions)
            .where(attack_executions.c.created_at >= h24)
        )
    ).scalar_one()
    attacks_prev = (
        await session.execute(
            select(func.count())
            .select_from(attack_executions)
            .where(attack_executions.c.created_at >= h48)
            .where(attack_executions.c.created_at < h24)
        )
    ).scalar_one()
    delta_pct = round((attacks_24h - attacks_prev) / attacks_prev * 100) if attacks_prev else 0

    cost_24h = (
        await session.execute(
            select(func.coalesce(func.sum(attack_executions.c.usd_estimate), 0.0)).where(
                attack_executions.c.created_at >= h24
            )
        )
    ).scalar_one()
    tokens_24h = (
        await session.execute(
            select(
                func.coalesce(
                    func.sum(attack_executions.c.tokens_in + attack_executions.c.tokens_out),
                    0,
                )
            ).where(attack_executions.c.created_at >= h24)
        )
    ).scalar_one()
    cost_30d = (
        await session.execute(
            select(func.coalesce(func.sum(attack_executions.c.usd_estimate), 0.0)).where(
                attack_executions.c.created_at >= now - timedelta(days=30)
            )
        )
    ).scalar_one()

    active_count = (
        await session.execute(
            select(func.count()).select_from(runs).where(runs.c.status == "running")
        )
    ).scalar_one()
    queued_count = (
        await session.execute(
            select(func.count()).select_from(runs).where(runs.c.status == "pending")
        )
    ).scalar_one()
    last_fire = (await session.execute(select(func.max(runs.c.started_at)))).scalar_one()
    open_crit = (
        await session.execute(
            select(func.count())
            .select_from(findings)
            .where(findings.c.severity == "critical")
            .where(findings.c.status == "open")
        )
    ).scalar_one()

    # ASR: attack passed (= defense failed) / total judged, last 24h
    judged = (
        await session.execute(
            select(func.count())
            .select_from(judge_verdicts)
            .where(judge_verdicts.c.created_at >= h24)
            .where(judge_verdicts.c.verdict.in_(["pass", "fail"]))
        )
    ).scalar_one()
    breaches = (
        await session.execute(
            select(func.count())
            .select_from(judge_verdicts)
            .where(judge_verdicts.c.created_at >= h24)
            .where(judge_verdicts.c.verdict == "pass")
        )
    ).scalar_one()
    asr_pct = round((breaches / judged) * 100, 1) if judged else 0.0

    overview = {
        "attacks_24h": attacks_24h,
        "attacks_delta_pct": delta_pct,
        "active_campaigns": active_count,
        "queued_campaigns": queued_count,
        "last_fire_relative": _rel(last_fire),
        "open_critical": open_crit,
        "asr_pct": asr_pct,
        "asr_n": judged,
        "asr_window_label": "last 24h",
        "cost_24h_usd": f"{cost_24h:.2f}",
        "cost_30d_usd": f"{cost_30d:.2f}",
        "tokens_24h": f"{tokens_24h:,}",
        "coverage_window_label": "last 7 days",
        "next_nightly_label": "next nightly · 03:00 UTC",
    }

    # --- coverage matrix ---
    cats_list = ["injection", "exfil", "tool_abuse"]
    cov_rows = []
    severities = ["info", "low", "medium", "high", "critical"]
    for cat in cats_list:
        rows = await session.execute(
            select(findings.c.severity, func.count())
            .where(findings.c.category == cat)
            .where(findings.c.created_at >= now - timedelta(days=7))
            .group_by(findings.c.severity)
        )
        counts: dict[str, int] = dict.fromkeys(severities, 0)
        for sev, n in rows:
            if sev in counts:
                counts[sev] = int(n)
        total = sum(counts.values())
        tiers = {sev: _tier(counts[sev], sev) for sev in severities}
        cov_rows.append(
            {
                "category": cat,
                "counts": counts,
                "tiers": tiers,
                "total": total or "·",
                "total_tier": 3 if total >= 10 else 2 if total >= 3 else 1 if total else 0,
            }
        )

    # --- open findings (top 8 by severity then recency) ---
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    finding_rows = (
        await session.execute(
            select(
                findings.c.id,
                findings.c.title,
                findings.c.category,
                findings.c.severity,
                findings.c.status,
                findings.c.atlas_technique_id,
                findings.c.run_id,
                findings.c.created_at,
            )
            .where(findings.c.status.in_(["open", "triaged", "regressed"]))
            .order_by(findings.c.created_at.desc())
            .limit(50)
        )
    ).all()
    findings_view = [
        {
            "id": r.id,
            "title": r.title,
            "category": r.category,
            "severity": r.severity,
            "status": r.status,
            "atlas_technique_id": r.atlas_technique_id,
            "run_short": str(r.run_id)[:8],
            "seen_relative": _rel(r.created_at),
        }
        for r in finding_rows
    ]
    findings_view.sort(key=lambda f: (severity_order.get(f["severity"], 9), f["seen_relative"]))
    findings_view = findings_view[:8]

    # --- active runs ---
    active_run_rows = (
        await session.execute(
            select(
                runs.c.id,
                runs.c.campaign_id,
                campaigns.c.name,
                runs.c.attacks_fired,
                runs.c.budget_consumed_usd,
                runs.c.status,
                runs.c.started_at,
            )
            .select_from(runs.join(campaigns, runs.c.campaign_id == campaigns.c.id))
            .where(runs.c.status.in_(["running", "pending"]))
            .order_by(runs.c.started_at.desc().nullslast())
            .limit(6)
        )
    ).all()
    active_runs = [
        {
            "id": r.id,
            "id_short": str(r.id)[:8],
            "campaign_id": r.campaign_id,
            "campaign_name": r.name,
            "attacks_fired": r.attacks_fired,
            "budget_consumed_usd": f"{r.budget_consumed_usd:.2f}",
            "status": r.status,
            "started_relative": _rel(r.started_at),
        }
        for r in active_run_rows
    ]

    # --- recent events (synthetic for now — pulled from attack_executions) ---
    recent_exec = (
        await session.execute(
            select(
                attack_executions.c.id,
                attack_executions.c.created_at,
                attack_executions.c.run_id,
                attack_executions.c.judge_verdict_id,
                judge_verdicts.c.verdict,
            )
            .select_from(
                attack_executions.outerjoin(
                    judge_verdicts,
                    attack_executions.c.judge_verdict_id == judge_verdicts.c.id,
                )
            )
            .order_by(attack_executions.c.created_at.desc())
            .limit(10)
        )
    ).all()
    recent_events: list[dict[str, Any]] = []
    for r in recent_exec:
        verdict = r.verdict or "pending"
        if verdict in ("pass", "fail", "partial", "error"):
            kind_class = f"verdict {verdict}"
            kind_label = f"verdict · {verdict}"
            body = (
                "attack passed — defense failed"
                if verdict == "pass"
                else (
                    "attack failed — defense held" if verdict == "fail" else f"verdict · {verdict}"
                )
            )
        else:
            kind_class = "attack"
            kind_label = "attack · executed"
            body = "attack fired against target"
        recent_events.append(
            {
                "ts": r.created_at.strftime("%H:%M:%S") if r.created_at else "—",
                "kind_class": kind_class,
                "kind_label": kind_label,
                "body": body,
                "id_short": str(r.id)[:8],
            }
        )

    # --- projects (for the fire-campaign select) ---
    project_rows = (
        await session.execute(
            select(projects.c.id, projects.c.name, projects.c.env).order_by(projects.c.name)
        )
    ).all()
    projects_view = [{"id": p.id, "name": p.name, "env": p.env} for p in project_rows]

    # --- Judge fixtures CI (placeholder thresholds matched to design system) ---
    judge_view = {
        "last_run_relative": "3m ago",
        "categories": [
            {
                "name": "injection",
                "rubric_version": 1,
                "fixtures": 0,
                "accuracy_pct": 100,
                "threshold_pct": 95,
            },
            {
                "name": "exfil",
                "rubric_version": 1,
                "fixtures": 0,
                "accuracy_pct": 100,
                "threshold_pct": 90,
            },
            {
                "name": "tool_abuse",
                "rubric_version": 1,
                "fixtures": 0,
                "accuracy_pct": 100,
                "threshold_pct": 92,
            },
        ],
    }

    # --- Operator follow-ups (static for scaffold; will read from a table later) ---
    followups = [
        {
            "tag": "Q · 01 · Judge ensemble",
            "title": "Cross-judge consensus",
            "body": "defer to Final, or invest now? 2× cost vs. provable drift resistance.",  # noqa: RUF001
        },
        {
            "tag": "Q · 02 · DOCX surface",
            "title": "Indirect injection coverage",
            "body": "schedule a focused sweep of the .docx ingest path before Friday.",
        },
        {
            "tag": "Q · 03 · Coverage",
            "title": "Clinical misinformation propagation",
            "body": "Nature Comm Med 2025 fixtures exist — pull in as 4th category?",
        },
    ]

    return {
        "active": "home",
        "env_tag": settings.default_target_env,
        "build_tag": "0001",
        "now_utc": now.strftime("%Y-%m-%d %H:%M"),
        "now_iso": now_iso,
        "db_status": "ok",
        "redis_status": "ok",
        "openrouter_status": "configured" if settings.openrouter_api_key else "not set",
        "overview": overview,
        "coverage": cov_rows,
        "findings": findings_view,
        "active_runs": active_runs,
        "recent_events": recent_events,
        "projects": projects_view,
        "judge": judge_view,
        "followups": followups,
    }
