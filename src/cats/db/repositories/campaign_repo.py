"""Campaign + Run lifecycle helpers for the dashboard / CLI dispatchers."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import case, desc, insert, select
from sqlalchemy.ext.asyncio import AsyncSession

from cats.categories import taxonomy
from cats.db.schema import (
    attack_executions,
    attacks,
    campaign_plans,
    campaigns,
    findings,
    judge_verdicts,
    project_versions,
    projects,
    runs,
    vulnerability_reports,
)

# Severity floor per registered attack category — mirrors each
# manifest.toml's ``severity_default``. Used as a fallback for the
# campaign-detail Run-status table when a run has not yet promoted a
# Finding. Duplicated from ``agents.orchestrator.tools`` rather than
# imported to avoid pulling the orchestrator module's heavy LLM-tool
# imports into the DB layer.
_DEFAULT_SEVERITY_BY_CATEGORY: dict[str, str] = {
    "injection": "high",
    "indirect_injection": "critical",
    "exfil": "critical",
    "tool_abuse": "high",
    "clinical_misinformation": "critical",
    "xss": "critical",
}


def _default_severity_for(category: str) -> str:
    return _DEFAULT_SEVERITY_BY_CATEGORY.get(category, "medium")


def _utcnow() -> datetime:
    return datetime.now(UTC)


async def _resolve_project_version(session: AsyncSession, project_id: UUID) -> UUID:
    """Return the most-recent ProjectVersion for the Project, creating
    one labeled ``auto`` if none exists."""
    row = (
        await session.execute(
            select(project_versions.c.id)
            .where(project_versions.c.project_id == project_id)
            .order_by(desc(project_versions.c.deployed_at))
            .limit(1)
        )
    ).first()
    if row is not None:
        return UUID(str(row.id))
    new_pv = uuid4()
    await session.execute(
        insert(project_versions).values(
            id=new_pv,
            project_id=project_id,
            label="auto",
            deployed_at=_utcnow(),
        )
    )
    return new_pv


async def create_campaign(
    session: AsyncSession,
    *,
    project_id: UUID,
    name: str,
    budget_usd: float = 5.0,
    trigger: str = "on_demand",
) -> tuple[UUID, UUID]:
    """Create a Campaign + (re)use a ProjectVersion. Returns
    ``(campaign_id, project_version_id)``.

    No Run is materialized — the R4 Red Team worker creates runs
    per-attempt as it walks the approved plan. The trigger surface
    (API + CLI) calls this; the smoke path uses
    :func:`create_campaign_and_run` because it drives ``run_one``
    directly without going through the bus."""
    project_version_id = await _resolve_project_version(session, project_id)
    campaign_id = uuid4()
    await session.execute(
        insert(campaigns).values(
            id=campaign_id,
            name=name[:200],
            project_id=project_id,
            mode="blackhat",
            trigger=trigger,
            budget={"usd": budget_usd},
        )
    )
    return campaign_id, project_version_id


async def create_campaign_and_run(
    session: AsyncSession,
    *,
    project_id: UUID,
    name: str,
    category: str,
    budget_usd: float = 5.0,
    trigger: str = "on_demand",
) -> tuple[UUID, UUID, UUID]:
    """Returns ``(campaign_id, run_id, project_version_id)``. Used only
    by the R3 smoke path which drives ``run_one`` directly and needs a
    pre-materialized Run. The R4 bus trigger surface calls
    :func:`create_campaign` instead."""
    project_version_id = await _resolve_project_version(session, project_id)

    campaign_id = uuid4()
    await session.execute(
        insert(campaigns).values(
            id=campaign_id,
            name=name[:200],
            project_id=project_id,
            mode="blackhat",
            trigger=trigger,
            budget={"usd": budget_usd, "categories": [category]},
        )
    )
    run_id = uuid4()
    await session.execute(
        insert(runs).values(
            id=run_id,
            campaign_id=campaign_id,
            project_version_id=project_version_id,
            status="pending",
        )
    )
    return campaign_id, run_id, project_version_id


async def list_campaigns(session: AsyncSession, *, limit: int = 100) -> list[dict[str, Any]]:
    """Return campaigns (newest first) joined with their target project and
    a roll-up across **every** run in the campaign — attacks fired, spend,
    findings count, run count, and a campaign-level status derived from
    the per-run statuses.

    A campaign may carry many ``(category, technique)`` runs (the Red Team
    worker materialises one per planned attempt), so summing only the
    latest run's executions — as we used to — understated multi-run
    campaigns. ``attacks_fired`` and ``budget_consumed_usd`` are now the
    sum across all of the campaign's runs, matching the per-run totals on
    the detail page when they're added up by hand.
    """
    from sqlalchemy import case, func

    # Per-campaign run roll-up: how many runs, how many in each status,
    # and the wall-clock window across the whole campaign.
    run_rollup = (
        select(
            runs.c.campaign_id.label("campaign_id"),
            func.count(runs.c.id).label("run_count"),
            func.sum(case((runs.c.status == "running", 1), else_=0)).label("running_count"),
            func.sum(case((runs.c.status == "pending", 1), else_=0)).label("pending_count"),
            func.sum(case((runs.c.status == "failed", 1), else_=0)).label("failed_count"),
            func.sum(case((runs.c.status == "completed", 1), else_=0)).label("completed_count"),
            func.min(runs.c.started_at).label("first_started_at"),
            func.max(runs.c.ended_at).label("last_ended_at"),
        )
        .group_by(runs.c.campaign_id)
        .subquery()
    )
    # Per-campaign execution roll-up: sum across every run, not just the
    # latest one. Joining attack_executions → runs lets us group straight
    # by campaign_id without an intermediate per-run aggregation.
    exec_rollup = (
        select(
            runs.c.campaign_id.label("campaign_id"),
            func.count(attack_executions.c.id).label("exec_count"),
            func.coalesce(func.sum(attack_executions.c.usd_estimate), 0.0).label("usd_total"),
        )
        .select_from(attack_executions.join(runs, runs.c.id == attack_executions.c.run_id))
        .group_by(runs.c.campaign_id)
        .subquery()
    )
    findings_rollup = (
        select(
            runs.c.campaign_id.label("campaign_id"),
            func.count(findings.c.id).label("findings_count"),
        )
        .select_from(findings.join(runs, runs.c.id == findings.c.run_id))
        .group_by(runs.c.campaign_id)
        .subquery()
    )
    stmt = (
        select(
            campaigns.c.id,
            campaigns.c.name,
            campaigns.c.mode,
            campaigns.c.trigger,
            campaigns.c.budget,
            campaigns.c.created_at,
            projects.c.id.label("project_id"),
            projects.c.name.label("project_name"),
            projects.c.env.label("project_env"),
            run_rollup.c.run_count,
            run_rollup.c.running_count,
            run_rollup.c.pending_count,
            run_rollup.c.failed_count,
            run_rollup.c.completed_count,
            run_rollup.c.first_started_at,
            run_rollup.c.last_ended_at,
            exec_rollup.c.exec_count,
            exec_rollup.c.usd_total,
            findings_rollup.c.findings_count,
        )
        .select_from(
            campaigns.join(projects, campaigns.c.project_id == projects.c.id)
            .outerjoin(run_rollup, campaigns.c.id == run_rollup.c.campaign_id)
            .outerjoin(exec_rollup, campaigns.c.id == exec_rollup.c.campaign_id)
            .outerjoin(findings_rollup, campaigns.c.id == findings_rollup.c.campaign_id)
        )
        .order_by(desc(campaigns.c.created_at))
        .limit(limit)
    )
    rows = (await session.execute(stmt)).all()
    out: list[dict[str, Any]] = []
    for r in rows:
        run_count = int(r.run_count or 0)
        running = int(r.running_count or 0)
        pending = int(r.pending_count or 0)
        failed = int(r.failed_count or 0)
        completed = int(r.completed_count or 0)
        # Campaign-level status: surface the most operationally-interesting
        # signal. If anything is live, say "running". If everything is
        # terminal but at least one run failed, say "failed". Otherwise
        # "completed" when all runs are done, else "pending" / None.
        if run_count == 0:
            run_status: str | None = None
        elif running > 0:
            run_status = "running"
        elif pending > 0:
            run_status = "pending"
        elif failed > 0 and completed == 0:
            run_status = "failed"
        elif completed > 0 and failed == 0:
            run_status = "completed"
        elif completed > 0 and failed > 0:
            run_status = "partial"
        else:
            run_status = None
        # The allocated budget lives in ``campaigns.budget`` as a JSONB
        # ``{"usd": N}`` blob (see ``create_campaign``); pull the cap out
        # so the index can render "spent / allocated".
        budget_allocated_usd: float | None = None
        if isinstance(r.budget, dict):
            raw = r.budget.get("usd")
            if isinstance(raw, int | float):
                budget_allocated_usd = float(raw)
        out.append(
            {
                "id": r.id,
                "name": r.name,
                "mode": r.mode,
                "trigger": r.trigger,
                "budget": r.budget,
                "budget_allocated_usd": budget_allocated_usd,
                "created_at": r.created_at,
                "project_id": r.project_id,
                "project_name": r.project_name,
                "project_env": r.project_env,
                "run_status": run_status,
                "run_count": run_count,
                "runs_running": running,
                "runs_pending": pending,
                "runs_failed": failed,
                "runs_completed": completed,
                "attacks_fired": int(r.exec_count or 0),
                "budget_consumed_usd": float(r.usd_total or 0.0),
                "findings_count": int(r.findings_count or 0),
                "started_at": r.first_started_at,
                "ended_at": r.last_ended_at,
            }
        )
    return out


async def create_run_in_campaign(
    session: AsyncSession,
    *,
    campaign_id: UUID,
    project_version_id: UUID,
) -> UUID:
    """R3: create an additional Run row against an existing Campaign so
    one campaign exercises multiple distinct techniques. Each Run carries
    its own findings, executions, and per-agent cost rollup."""
    run_id = uuid4()
    await session.execute(
        insert(runs).values(
            id=run_id,
            campaign_id=campaign_id,
            project_version_id=project_version_id,
            status="pending",
        )
    )
    return run_id


async def get_campaign_with_project(
    session: AsyncSession, *, campaign_id: UUID
) -> dict[str, Any] | None:
    row = (
        await session.execute(
            select(
                campaigns.c.id,
                campaigns.c.name,
                campaigns.c.trigger,
                campaigns.c.created_at,
                projects.c.name.label("project_name"),
                projects.c.env.label("project_env"),
                projects.c.id.label("project_id"),
            )
            .select_from(campaigns.join(projects, campaigns.c.project_id == projects.c.id))
            .where(campaigns.c.id == campaign_id)
        )
    ).first()
    if row is None:
        return None
    return {
        "id": row.id,
        "name": row.name,
        "trigger": row.trigger,
        "created_at": row.created_at,
        "project_id": row.project_id,
        "project_name": row.project_name,
        "project_env": row.project_env,
    }


async def list_runs_for_campaign(
    session: AsyncSession, *, campaign_id: UUID
) -> list[dict[str, Any]]:
    # Per-run rollup driving the campaign-detail Run-status table.
    #
    # Everything that exists as a denorm on ``runs`` is re-derived from
    # ``attack_executions`` instead — the denorm columns were unreliable
    # (R3 worker hard-coded ``attacks_fired=1``; agent path sometimes
    # left ``budget_consumed_usd=0``). The execution rows are the source
    # of truth. We surface:
    #   - attacks_fired  = count(executions)
    #   - spend_usd      = sum(usd_estimate)
    #   - avg_latency_ms = avg(target_latency_ms)
    #   - elapsed_ms     = runs.ended_at - runs.started_at (wall clock)
    #   - judge_verdict  = verdict from the latest execution that has
    #                      one (the Red Team submits once at end-of-run;
    #                      typically only one execution carries a verdict)
    #
    # ``category``/``technique`` come from the run's first execution
    # (lowest seed_idx, tie-broken by created_at). Since a Run is
    # technique-scoped, every execution shares the same pair — picking
    # one is unambiguous.
    from sqlalchemy import func

    exec_stats = (
        select(
            attack_executions.c.run_id,
            func.avg(attack_executions.c.target_latency_ms).label("avg_latency"),
            func.count(attack_executions.c.id).label("exec_count"),
            func.coalesce(func.sum(attack_executions.c.usd_estimate), 0.0).label("usd_total"),
        )
        .group_by(attack_executions.c.run_id)
        .subquery()
    )
    first_exec = (
        select(
            attack_executions.c.run_id,
            attacks.c.category.label("category"),
            attacks.c.payload.label("attack_payload"),
            func.row_number()
            .over(
                partition_by=attack_executions.c.run_id,
                order_by=(attack_executions.c.seed_idx, attack_executions.c.created_at),
            )
            .label("rn"),
        )
        .select_from(attack_executions.join(attacks, attacks.c.id == attack_executions.c.attack_id))
        .subquery()
    )
    first_exec_filtered = (
        select(
            first_exec.c.run_id,
            first_exec.c.category,
            first_exec.c.attack_payload,
        )
        .where(first_exec.c.rn == 1)
        .subquery()
    )
    # Run-level Judge verdict: pick the latest execution row that has a
    # non-null verdict and join its judge_verdicts.verdict. The Red Team
    # submits the whole conversation once at end-of-run, so at most one
    # execution per run carries a verdict (typically the last fire).
    # Ranking by created_at desc handles the edge case where two
    # executions ended up with verdicts.
    verdict_exec = (
        select(
            attack_executions.c.run_id,
            judge_verdicts.c.verdict.label("judge_verdict"),
            judge_verdicts.c.exploitability.label("judge_exploitability"),
            func.row_number()
            .over(
                partition_by=attack_executions.c.run_id,
                order_by=desc(attack_executions.c.created_at),
            )
            .label("rn"),
        )
        .select_from(
            attack_executions.join(
                judge_verdicts, attack_executions.c.judge_verdict_id == judge_verdicts.c.id
            )
        )
        .subquery()
    )
    verdict_filtered = (
        select(
            verdict_exec.c.run_id,
            verdict_exec.c.judge_verdict,
            verdict_exec.c.judge_exploitability,
        )
        .where(verdict_exec.c.rn == 1)
        .subquery()
    )
    # Per-run finding rollup: max severity (by an ordinal floor) and a
    # regression flag if any finding on the run is in `regressed` state.
    # A run typically promotes 0-1 findings, but the schema allows more
    # (one per signature), so we aggregate rather than picking one.
    sev_rank = case(
        (findings.c.severity == "critical", 5),
        (findings.c.severity == "high", 4),
        (findings.c.severity == "medium", 3),
        (findings.c.severity == "low", 2),
        (findings.c.severity == "info", 1),
        else_=0,
    )
    findings_rollup = (
        select(
            findings.c.run_id,
            func.max(sev_rank).label("sev_rank"),
            func.bool_or(findings.c.status == "regressed").label("regression_flag"),
        )
        .group_by(findings.c.run_id)
        .subquery()
    )
    rows = (
        await session.execute(
            select(
                runs.c.id,
                runs.c.status,
                runs.c.started_at,
                runs.c.ended_at,
                exec_stats.c.avg_latency,
                exec_stats.c.exec_count,
                exec_stats.c.usd_total,
                first_exec_filtered.c.category,
                first_exec_filtered.c.attack_payload,
                verdict_filtered.c.judge_verdict,
                verdict_filtered.c.judge_exploitability,
                findings_rollup.c.sev_rank,
                findings_rollup.c.regression_flag,
            )
            .select_from(
                runs.outerjoin(exec_stats, runs.c.id == exec_stats.c.run_id)
                .outerjoin(first_exec_filtered, runs.c.id == first_exec_filtered.c.run_id)
                .outerjoin(verdict_filtered, runs.c.id == verdict_filtered.c.run_id)
                .outerjoin(findings_rollup, runs.c.id == findings_rollup.c.run_id)
            )
            .where(runs.c.campaign_id == campaign_id)
            .order_by(desc(runs.c.created_at))
        )
    ).all()
    out: list[dict[str, Any]] = []
    for r in rows:
        technique = ""
        if isinstance(r.attack_payload, dict):
            technique = str(r.attack_payload.get("technique", ""))
        elapsed_ms: int | None = None
        if r.started_at is not None and r.ended_at is not None:
            elapsed_ms = int((r.ended_at - r.started_at).total_seconds() * 1000)
        category = r.category or ""
        severity = _severity_from_rank(r.sev_rank) or _default_severity_for(category)
        owasp_label = taxonomy.lookup(category, technique) if category else None
        out.append(
            {
                "id": r.id,
                "status": r.status,
                "started_at": r.started_at,
                "ended_at": r.ended_at,
                "attacks_fired": int(r.exec_count or 0),
                "budget_consumed_usd": float(r.usd_total or 0.0),
                "avg_target_latency_ms": (
                    int(r.avg_latency) if r.avg_latency is not None else None
                ),
                "elapsed_ms": elapsed_ms,
                "category": category,
                "technique": technique,
                "judge_verdict": r.judge_verdict,
                # R12+: per-run security tagging surfaced on the
                # campaign-detail Run table. Severity prefers a promoted
                # Finding (the authoritative call); falls back to the
                # category manifest's default. Exploitability comes from
                # the Judge verdict if any. OWASP is looked up via the
                # taxonomy.toml for the (category, technique) pair, with
                # the category default when the technique is unknown.
                "severity": severity,
                "exploitability": r.judge_exploitability,
                "regression_flag": bool(r.regression_flag) if r.regression_flag else False,
                "owasp_llm_id": owasp_label.owasp_llm_id if owasp_label else None,
                "atlas_technique_id": (owasp_label.atlas_technique_id if owasp_label else None),
            }
        )
    return out


_SEVERITY_BY_RANK = {5: "critical", 4: "high", 3: "medium", 2: "low", 1: "info"}


def _severity_from_rank(rank: int | None) -> str | None:
    """Inverse of the ``sev_rank`` CASE used in :func:`list_runs_for_campaign`."""
    if rank is None or rank == 0:
        return None
    return _SEVERITY_BY_RANK.get(int(rank))


async def list_findings_for_run(session: AsyncSession, *, run_id: UUID) -> list[dict[str, Any]]:
    rows = (
        await session.execute(
            select(
                findings.c.id,
                findings.c.category,
                findings.c.severity,
                findings.c.status,
                findings.c.title,
                findings.c.summary,
                findings.c.created_at,
            )
            .where(findings.c.run_id == run_id)
            .order_by(desc(findings.c.created_at))
        )
    ).all()
    return [
        {
            "id": r.id,
            "category": r.category,
            "severity": r.severity,
            "status": r.status,
            "title": r.title,
            "summary": r.summary,
            "created_at": r.created_at,
        }
        for r in rows
    ]


async def list_executions_for_run(session: AsyncSession, *, run_id: UUID) -> list[dict[str, Any]]:
    rows = (
        await session.execute(
            select(
                attack_executions.c.id,
                attack_executions.c.agent_role,
                attack_executions.c.model,
                attack_executions.c.tokens_in,
                attack_executions.c.tokens_out,
                attack_executions.c.usd_estimate,
                attack_executions.c.output_filter_verdict,
                attack_executions.c.target_status_code,
                attack_executions.c.target_latency_ms,
                attack_executions.c.langsmith_trace_id,
            )
            .where(attack_executions.c.run_id == run_id)
            .order_by(attack_executions.c.created_at)
        )
    ).all()
    return [
        {
            "id": r.id,
            "agent_role": r.agent_role,
            "model": r.model,
            "tokens_in": r.tokens_in,
            "tokens_out": r.tokens_out,
            "usd": r.usd_estimate,
            "filter_verdict": r.output_filter_verdict,
            "target_status_code": r.target_status_code,
            "target_latency_ms": r.target_latency_ms,
            "trace_id": r.langsmith_trace_id,
        }
        for r in rows
    ]


async def get_finding_with_report(
    session: AsyncSession, *, finding_id: UUID
) -> dict[str, Any] | None:
    """Finding + report + run/campaign/project context. One query covers
    the finding header and breadcrumbs; the report lookup stays separate
    because not every finding has one (reports come from the
    Documentation agent's promotion path, which is gated)."""
    f_row = (
        await session.execute(
            select(
                findings.c.id,
                findings.c.run_id,
                findings.c.category,
                findings.c.severity,
                findings.c.status,
                findings.c.title,
                findings.c.summary,
                findings.c.atlas_technique_id,
                findings.c.owasp_llm_id,
                findings.c.decisive_seed_idx,
                findings.c.total_seeds,
                findings.c.created_at,
                campaigns.c.id.label("campaign_id"),
                campaigns.c.name.label("campaign_name"),
                projects.c.id.label("project_id"),
                projects.c.name.label("project_name"),
                projects.c.env.label("project_env"),
            )
            .select_from(
                findings.join(runs, findings.c.run_id == runs.c.id)
                .join(campaigns, runs.c.campaign_id == campaigns.c.id)
                .join(projects, campaigns.c.project_id == projects.c.id)
            )
            .where(findings.c.id == finding_id)
        )
    ).first()
    if f_row is None:
        return None
    r_row = (
        await session.execute(
            select(
                vulnerability_reports.c.id,
                vulnerability_reports.c.title,
                vulnerability_reports.c.body_markdown,
                vulnerability_reports.c.requires_approval,
                vulnerability_reports.c.approved_by,
            ).where(vulnerability_reports.c.finding_id == finding_id)
        )
    ).first()
    return {
        "id": f_row.id,
        "run_id": f_row.run_id,
        "category": f_row.category,
        "severity": f_row.severity,
        "status": f_row.status,
        "title": f_row.title,
        "summary": f_row.summary,
        "atlas_technique_id": f_row.atlas_technique_id,
        "owasp_llm_id": f_row.owasp_llm_id,
        "decisive_seed_idx": f_row.decisive_seed_idx,
        "total_seeds": f_row.total_seeds,
        "created_at": f_row.created_at,
        "campaign_id": f_row.campaign_id,
        "campaign_name": f_row.campaign_name,
        "project_id": f_row.project_id,
        "project_name": f_row.project_name,
        "project_env": f_row.project_env,
        "report": {
            "id": r_row.id,
            "title": r_row.title,
            "body_markdown": r_row.body_markdown,
            "requires_approval": r_row.requires_approval,
            "approved_by": r_row.approved_by,
        }
        if r_row
        else None,
    }


async def list_findings(session: AsyncSession, *, limit: int = 200) -> list[dict[str, Any]]:
    """Findings joined with their Run → Campaign → Project so the triage
    UI can show *where* each finding came from without N+1 lookups."""
    rows = (
        await session.execute(
            select(
                findings.c.id,
                findings.c.run_id,
                findings.c.category,
                findings.c.severity,
                findings.c.status,
                findings.c.title,
                findings.c.atlas_technique_id,
                findings.c.created_at,
                campaigns.c.id.label("campaign_id"),
                campaigns.c.name.label("campaign_name"),
                projects.c.id.label("project_id"),
                projects.c.name.label("project_name"),
                projects.c.env.label("project_env"),
            )
            .select_from(
                findings.join(runs, findings.c.run_id == runs.c.id)
                .join(campaigns, runs.c.campaign_id == campaigns.c.id)
                .join(projects, campaigns.c.project_id == projects.c.id)
            )
            .order_by(desc(findings.c.created_at))
            .limit(limit)
        )
    ).all()
    return [
        {
            "id": r.id,
            "run_id": r.run_id,
            "category": r.category,
            "severity": r.severity,
            "status": r.status,
            "title": r.title,
            "atlas_technique_id": r.atlas_technique_id,
            "created_at": r.created_at,
            "campaign_id": r.campaign_id,
            "campaign_name": r.campaign_name,
            "project_id": r.project_id,
            "project_name": r.project_name,
            "project_env": r.project_env,
        }
        for r in rows
    ]


async def get_run_with_campaign(
    session: AsyncSession, *, run_id: UUID, campaign_id: UUID
) -> dict[str, Any] | None:
    """Fetch one Run together with its parent Campaign + Project. Returns
    None if the run doesn't exist or doesn't belong to that campaign — the
    route layer uses that to 404 rather than leak unrelated runs.

    ``attacks_fired`` and ``budget_consumed_usd`` are derived from
    ``attack_executions`` rather than the denormed ``runs`` columns —
    same rationale as ``list_runs_for_campaign``: the legacy worker
    path set ``runs.attacks_fired`` to a fixed 1 and the agent path
    sometimes lands a 0/0 due to session timing; the per-execution
    rows are the source of truth."""
    from sqlalchemy import func

    row = (
        await session.execute(
            select(
                runs.c.id,
                runs.c.status,
                runs.c.started_at,
                runs.c.ended_at,
                runs.c.created_at,
                runs.c.failure_reason,
                campaigns.c.id.label("campaign_id"),
                campaigns.c.name.label("campaign_name"),
                campaigns.c.trigger,
                projects.c.name.label("project_name"),
                projects.c.env.label("project_env"),
            )
            .select_from(
                runs.join(campaigns, runs.c.campaign_id == campaigns.c.id).join(
                    projects, campaigns.c.project_id == projects.c.id
                )
            )
            .where(runs.c.id == run_id)
            .where(runs.c.campaign_id == campaign_id)
        )
    ).first()
    if row is None:
        return None
    exec_row = (
        await session.execute(
            select(
                func.count(attack_executions.c.id).label("exec_count"),
                func.coalesce(func.sum(attack_executions.c.usd_estimate), 0.0).label("usd_total"),
            ).where(attack_executions.c.run_id == run_id)
        )
    ).first()
    attacks_fired = int(exec_row.exec_count or 0) if exec_row else 0
    budget_consumed_usd = float(exec_row.usd_total or 0.0) if exec_row else 0.0
    return {
        "id": row.id,
        "status": row.status,
        "started_at": row.started_at,
        "ended_at": row.ended_at,
        "failure_reason": row.failure_reason,
        "attacks_fired": attacks_fired,
        "budget_consumed_usd": budget_consumed_usd,
        "created_at": row.created_at,
        "campaign_id": row.campaign_id,
        "campaign_name": row.campaign_name,
        "trigger": row.trigger,
        "project_name": row.project_name,
        "project_env": row.project_env,
    }


def _execution_row_to_dict(r: Any) -> dict[str, Any]:
    """Shared shape for execution rows. Used by both the per-run list and
    the per-execution detail helper so the template can rely on one schema."""
    return {
        "id": r.id,
        "attack_id": r.attack_id,
        "attack_title": r.attack_title,
        "attack_category": r.attack_category,
        "attack_signature": r.attack_signature,
        "attack_payload": r.attack_payload,
        "agent_role": r.agent_role,
        "model": r.model,
        "tokens_in": r.tokens_in,
        "tokens_out": r.tokens_out,
        "usd": r.usd_estimate,
        "filter_verdict": r.output_filter_verdict,
        "filter_reason": r.output_filter_reason,
        "target_status_code": r.target_status_code,
        "target_latency_ms": r.target_latency_ms,
        "target_response": r.target_response,
        "trace_id": r.langsmith_trace_id,
        "error": r.error,
        "started_at": r.started_at,
        "ended_at": r.ended_at,
        "created_at": r.created_at,
        "seed_idx": getattr(r, "seed_idx", 0),
        "judge_verdict": r.judge_verdict,
        "judge_exploitability": r.judge_exploitability,
        "judge_rationale": r.judge_rationale,
        "judge_evidence": r.judge_evidence,
        "judge_model": r.judge_model,
    }


_EXECUTION_COLS = (
    attack_executions.c.id,
    attack_executions.c.attack_id,
    attack_executions.c.agent_role,
    attack_executions.c.model,
    attack_executions.c.tokens_in,
    attack_executions.c.tokens_out,
    attack_executions.c.usd_estimate,
    attack_executions.c.output_filter_verdict,
    attack_executions.c.output_filter_reason,
    attack_executions.c.target_status_code,
    attack_executions.c.target_latency_ms,
    attack_executions.c.target_response,
    attack_executions.c.langsmith_trace_id,
    attack_executions.c.error,
    attack_executions.c.started_at,
    attack_executions.c.ended_at,
    attack_executions.c.created_at,
    attack_executions.c.seed_idx,
    attacks.c.title.label("attack_title"),
    attacks.c.category.label("attack_category"),
    attacks.c.signature.label("attack_signature"),
    attacks.c.payload.label("attack_payload"),
    judge_verdicts.c.verdict.label("judge_verdict"),
    judge_verdicts.c.exploitability.label("judge_exploitability"),
    judge_verdicts.c.rationale.label("judge_rationale"),
    judge_verdicts.c.evidence.label("judge_evidence"),
    judge_verdicts.c.judge_model.label("judge_model"),
)


async def list_executions_full(session: AsyncSession, *, run_id: UUID) -> list[dict[str, Any]]:
    """Per-run executions joined with their Attack and (optional) Judge
    verdict. Drives the per-run detail page's executions table — one row
    per attack fired, click expands to the payload/response/rationale."""
    rows = (
        await session.execute(
            select(*_EXECUTION_COLS)
            .select_from(
                attack_executions.join(
                    attacks, attack_executions.c.attack_id == attacks.c.id
                ).outerjoin(
                    judge_verdicts,
                    attack_executions.c.judge_verdict_id == judge_verdicts.c.id,
                )
            )
            .where(attack_executions.c.run_id == run_id)
            .order_by(attack_executions.c.created_at)
        )
    ).all()
    return [_execution_row_to_dict(r) for r in rows]


async def list_campaign_timeline(
    session: AsyncSession, *, campaign_id: UUID
) -> list[dict[str, Any]]:
    """Replay the campaign's historical events in the same envelope
    shape the live SSE stream uses. Drives the campaign-detail page's
    one-shot backfill on page load so the event log survives reloads.

    Sources, oldest-first by timestamp:
      - campaign_plans rows → plan_proposed / plan_approved
      - attack_executions rows (joined with attacks for category/technique
        and judge_verdicts for the verdict) → attack_executed and, when
        a verdict is recorded, judge_verdict_rendered
      - runs.ended_at → run_completed
      - findings → finding_promoted

    Events that have no DB row (the orchestrator's intra-planning
    chatter, output-filter intermediates) intentionally aren't backfilled
    — they're transient by design."""
    events: list[dict[str, Any]] = []

    plan_rows = (
        await session.execute(
            select(
                campaign_plans.c.id,
                campaign_plans.c.status,
                campaign_plans.c.created_at,
                campaign_plans.c.approved_at,
                campaign_plans.c.proposed_plan,
            )
            .where(campaign_plans.c.campaign_id == campaign_id)
            .order_by(campaign_plans.c.created_at)
        )
    ).all()
    for p in plan_rows:
        proposed = p.proposed_plan if isinstance(p.proposed_plan, dict) else {}
        attempts = proposed.get("attempts") if isinstance(proposed, dict) else None
        events.append(
            {
                "kind": "plan_proposed",
                "campaign_id": str(campaign_id),
                "run_id": None,
                "at": p.created_at,
                "payload": {
                    "plan_id": str(p.id),
                    "attempt_count": len(attempts) if isinstance(attempts, list) else 0,
                },
            }
        )
        if p.approved_at is not None and p.status in ("approved", "edited", "dispatched"):
            events.append(
                {
                    "kind": "plan_approved",
                    "campaign_id": str(campaign_id),
                    "run_id": None,
                    "at": p.approved_at,
                    "payload": {"plan_id": str(p.id)},
                }
            )

    exec_rows = (
        await session.execute(
            select(
                attack_executions.c.id,
                attack_executions.c.run_id,
                attack_executions.c.created_at,
                attack_executions.c.target_status_code,
                attack_executions.c.target_latency_ms,
                attack_executions.c.output_filter_verdict,
                attacks.c.payload.label("attack_payload"),
                judge_verdicts.c.verdict.label("judge_verdict"),
                judge_verdicts.c.rationale.label("judge_rationale"),
                judge_verdicts.c.created_at.label("judge_created_at"),
            )
            .select_from(
                attack_executions.join(runs, attack_executions.c.run_id == runs.c.id)
                .join(attacks, attack_executions.c.attack_id == attacks.c.id)
                .outerjoin(
                    judge_verdicts,
                    attack_executions.c.judge_verdict_id == judge_verdicts.c.id,
                )
            )
            .where(runs.c.campaign_id == campaign_id)
            .order_by(attack_executions.c.created_at)
        )
    ).all()
    for e in exec_rows:
        attack_payload = e.attack_payload if isinstance(e.attack_payload, dict) else {}
        events.append(
            {
                "kind": "attack_executed",
                "campaign_id": str(campaign_id),
                "run_id": str(e.run_id),
                "at": e.created_at,
                "payload": {
                    "category": attack_payload.get("category"),
                    "technique": attack_payload.get("technique"),
                    "status_code": e.target_status_code,
                    "latency_ms": e.target_latency_ms,
                    "filter_verdict": e.output_filter_verdict,
                },
            }
        )
        if e.judge_verdict is not None:
            events.append(
                {
                    "kind": "judge_verdict_rendered",
                    "campaign_id": str(campaign_id),
                    "run_id": str(e.run_id),
                    "at": e.judge_created_at or e.created_at,
                    "payload": {
                        "verdict": e.judge_verdict,
                        "rationale": e.judge_rationale or "",
                    },
                }
            )

    run_rows = (
        await session.execute(
            select(
                runs.c.id,
                runs.c.started_at,
                runs.c.ended_at,
                runs.c.attacks_fired,
                runs.c.budget_consumed_usd,
                runs.c.status,
            ).where(runs.c.campaign_id == campaign_id)
        )
    ).all()
    for r in run_rows:
        # Emit run_started for every run so the client-side runs table can
        # reconstruct rows on refresh — both for runs the server has
        # rendered (idempotent dedupe via data-run-id) and for any in-flight
        # run the server might not have surfaced yet.
        if r.started_at is not None:
            events.append(
                {
                    "kind": "run_started",
                    "campaign_id": str(campaign_id),
                    "run_id": str(r.id),
                    "at": r.started_at,
                    "payload": {},
                }
            )
        if r.ended_at is not None:
            events.append(
                {
                    "kind": "run_completed",
                    "campaign_id": str(campaign_id),
                    "run_id": str(r.id),
                    "at": r.ended_at,
                    "payload": {
                        "attacks_fired": r.attacks_fired,
                        "spend_usd": r.budget_consumed_usd,
                        "status": r.status,
                    },
                }
            )

    finding_rows = (
        await session.execute(
            select(
                findings.c.id,
                findings.c.run_id,
                findings.c.created_at,
                findings.c.severity,
                findings.c.title,
            )
            .select_from(findings.join(runs, findings.c.run_id == runs.c.id))
            .where(runs.c.campaign_id == campaign_id)
        )
    ).all()
    for f in finding_rows:
        events.append(
            {
                "kind": "finding_promoted",
                "campaign_id": str(campaign_id),
                "run_id": str(f.run_id),
                "at": f.created_at,
                "payload": {
                    "finding_id": str(f.id),
                    "severity": f.severity,
                    "title": f.title,
                },
            }
        )

    events.sort(key=lambda ev: ev["at"])
    for ev in events:
        ev["at"] = ev["at"].isoformat() if hasattr(ev["at"], "isoformat") else ev["at"]
    return events


async def get_execution_full(
    session: AsyncSession, *, execution_id: UUID, run_id: UUID
) -> dict[str, Any] | None:
    """Fetch a single execution with its joined Attack + Judge verdict.
    Scoped by run_id so the fragment route can refuse cross-run lookups."""
    row = (
        await session.execute(
            select(*_EXECUTION_COLS)
            .select_from(
                attack_executions.join(
                    attacks, attack_executions.c.attack_id == attacks.c.id
                ).outerjoin(
                    judge_verdicts,
                    attack_executions.c.judge_verdict_id == judge_verdicts.c.id,
                )
            )
            .where(attack_executions.c.id == execution_id)
            .where(attack_executions.c.run_id == run_id)
        )
    ).first()
    if row is None:
        return None
    return _execution_row_to_dict(row)
