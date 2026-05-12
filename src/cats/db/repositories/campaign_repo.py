"""Campaign + Run lifecycle helpers for the dashboard / CLI dispatchers."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import desc, insert, select
from sqlalchemy.ext.asyncio import AsyncSession

from cats.db.schema import (
    attack_executions,
    campaigns,
    findings,
    project_versions,
    projects,
    runs,
    vulnerability_reports,
)


def _utcnow() -> datetime:
    return datetime.now(UTC)


async def create_campaign_and_run(
    session: AsyncSession,
    *,
    project_id: UUID,
    name: str,
    category: str,
    budget_usd: float = 5.0,
    trigger: str = "on_demand",
) -> tuple[UUID, UUID, UUID]:
    """Returns (campaign_id, run_id, project_version_id). Reuses the most
    recent ProjectVersion for the Project, creating one on demand if none
    exists. The smoke path creates project_versions explicitly; the
    dashboard pathway falls back to an auto-version."""
    version_row = (
        await session.execute(
            select(project_versions.c.id)
            .where(project_versions.c.project_id == project_id)
            .order_by(desc(project_versions.c.deployed_at))
            .limit(1)
        )
    ).first()
    if version_row is None:
        new_pv = uuid4()
        await session.execute(
            insert(project_versions).values(
                id=new_pv,
                project_id=project_id,
                label="auto",
                deployed_at=_utcnow(),
            )
        )
        project_version_id = new_pv
    else:
        project_version_id = version_row.id

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
    rows = (
        await session.execute(
            select(
                runs.c.id,
                runs.c.status,
                runs.c.started_at,
                runs.c.ended_at,
                runs.c.attacks_fired,
                runs.c.budget_consumed_usd,
            )
            .where(runs.c.campaign_id == campaign_id)
            .order_by(desc(runs.c.created_at))
        )
    ).all()
    return [
        {
            "id": r.id,
            "status": r.status,
            "started_at": r.started_at,
            "ended_at": r.ended_at,
            "attacks_fired": r.attacks_fired,
            "budget_consumed_usd": r.budget_consumed_usd,
        }
        for r in rows
    ]


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
                findings.c.created_at,
            ).where(findings.c.id == finding_id)
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
        "created_at": f_row.created_at,
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
    rows = (
        await session.execute(
            select(
                findings.c.id,
                findings.c.run_id,
                findings.c.category,
                findings.c.severity,
                findings.c.status,
                findings.c.title,
                findings.c.created_at,
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
            "created_at": r.created_at,
        }
        for r in rows
    ]
