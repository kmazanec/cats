"""Persistence for the inner campaign loop (R2 — single attack per Run).

Smoke path keeps its own narrow `smoke_repo`; this module is the
runner's writer. Idempotent on `(run_id, signature)` so re-running a
checkpointed step doesn't duplicate rows.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from cats.db.schema import (
    attack_executions,
    attacks,
    findings,
    judge_verdicts,
    runs,
    vulnerability_reports,
)


def _utcnow() -> datetime:
    return datetime.now(UTC)


async def upsert_attack(
    session: AsyncSession,
    *,
    category: str,
    title: str,
    description: str,
    payload: dict[str, Any],
    signature: str,
    source: str = "red_team",
    run_id: UUID | None = None,
) -> UUID:
    """Look up by `(category, signature)`, insert if absent. The
    `attacks` table has separate indexes on category + signature but no
    unique constraint (deduplication is logical, not enforced), so we
    do this in two queries rather than ON CONFLICT."""
    from sqlalchemy import insert as sa_insert

    existing = await session.execute(
        select(attacks.c.id)
        .where(attacks.c.category == category)
        .where(attacks.c.signature == signature)
    )
    found = existing.scalar_one_or_none()
    if found:
        return found  # type: ignore[no-any-return]
    new_id = uuid4()
    await session.execute(
        sa_insert(attacks).values(
            id=new_id,
            category=category,
            title=title[:300],
            description=description,
            payload=payload,
            signature=signature,
            source=source,
            created_in_run_id=run_id,
        )
    )
    return new_id


async def record_verdict(
    session: AsyncSession,
    *,
    verdict: str,
    is_deterministic: bool,
    rationale: str,
    evidence: dict[str, Any],
    judge_model: str,
    rubric_version_id: UUID | None = None,
) -> UUID:
    new_id = uuid4()
    from sqlalchemy import insert

    await session.execute(
        insert(judge_verdicts).values(
            id=new_id,
            verdict=verdict,
            is_deterministic=is_deterministic,
            rationale=rationale[:2000],
            evidence=evidence,
            judge_model=judge_model[:120],
            rubric_version_id=rubric_version_id,
        )
    )
    return new_id


async def record_execution(
    session: AsyncSession,
    *,
    run_id: UUID,
    attack_id: UUID,
    project_version_id: UUID,
    target_response: dict[str, Any],
    target_status_code: int,
    target_latency_ms: int,
    output_filter_verdict: str,
    output_filter_reason: str,
    judge_verdict_id: UUID | None,
    model: str,
    agent_role: str,
    tokens_in: int,
    tokens_out: int,
    usd_estimate: float,
    langsmith_trace_id: str | None,
    error: str | None = None,
) -> UUID:
    new_id = uuid4()
    now = _utcnow()
    from sqlalchemy import insert

    await session.execute(
        insert(attack_executions).values(
            id=new_id,
            run_id=run_id,
            attack_id=attack_id,
            project_version_id=project_version_id,
            target_response=target_response,
            target_status_code=target_status_code,
            target_latency_ms=target_latency_ms,
            output_filter_verdict=output_filter_verdict,
            output_filter_reason=output_filter_reason[:1000],
            judge_verdict_id=judge_verdict_id,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            model=model[:120],
            usd_estimate=usd_estimate,
            agent_role=agent_role[:64],
            langsmith_trace_id=(langsmith_trace_id or "")[:120] or None,
            started_at=now,
            ended_at=now,
            error=error,
        )
    )
    return new_id


async def set_execution_verdict(
    session: AsyncSession,
    *,
    attack_execution_id: UUID,
    judge_verdict_id: UUID,
) -> None:
    """R4 — the Judge worker writes a verdict row and then links it back
    to the AttackExecution row that the Red Team worker created."""
    await session.execute(
        update(attack_executions)
        .where(attack_executions.c.id == attack_execution_id)
        .values(judge_verdict_id=judge_verdict_id)
    )


async def upsert_finding(
    session: AsyncSession,
    *,
    run_id: UUID,
    category: str,
    signature: str,
    title: str,
    severity: str = "high",
    summary: str = "",
    atlas_technique_id: str | None = "AML.T0051",
    owasp_llm_id: str | None = "LLM01",
) -> UUID:
    stmt = (
        pg_insert(findings)
        .values(
            run_id=run_id,
            category=category,
            signature=signature,
            title=title[:300],
            severity=severity,
            summary=summary[:2000],
            atlas_technique_id=atlas_technique_id,
            owasp_llm_id=owasp_llm_id,
        )
        .on_conflict_do_nothing(index_elements=["run_id", "category", "signature"])
        .returning(findings.c.id)
    )
    result = await session.execute(stmt)
    row = result.scalar_one_or_none()
    if row:
        return row  # type: ignore[no-any-return]
    again = await session.execute(
        select(findings.c.id)
        .where(findings.c.run_id == run_id)
        .where(findings.c.category == category)
        .where(findings.c.signature == signature)
    )
    return again.scalar_one()  # type: ignore[no-any-return]


async def record_report(
    session: AsyncSession,
    *,
    run_id: UUID,
    finding_id: UUID,
    title: str,
    body_markdown: str,
    requires_approval: bool = False,
) -> UUID:
    new_id = uuid4()
    from sqlalchemy import insert

    await session.execute(
        insert(vulnerability_reports).values(
            id=new_id,
            run_id=run_id,
            finding_id=finding_id,
            title=title[:300],
            body_markdown=body_markdown,
            requires_approval=requires_approval,
        )
    )
    return new_id


async def mark_run_running(session: AsyncSession, *, run_id: UUID) -> None:
    await session.execute(
        update(runs).where(runs.c.id == run_id).values(status="running", started_at=_utcnow())
    )


async def mark_run_completed(
    session: AsyncSession,
    *,
    run_id: UUID,
    attacks_fired: int,
    budget_consumed_usd: float,
) -> None:
    await session.execute(
        update(runs)
        .where(runs.c.id == run_id)
        .values(
            status="completed",
            ended_at=_utcnow(),
            attacks_fired=attacks_fired,
            budget_consumed_usd=budget_consumed_usd,
        )
    )


async def mark_run_failed(session: AsyncSession, *, run_id: UUID) -> None:
    """Mark a Run as failed and stamp ended_at. Used by the worker's
    exception path so a crashed dispatch doesn't leave the Run stuck at
    'running' in the UI forever."""
    await session.execute(
        update(runs).where(runs.c.id == run_id).values(status="failed", ended_at=_utcnow())
    )


async def sweep_orphaned_running_runs(session: AsyncSession) -> list[UUID]:
    """Mark every Run still at ``status='running'`` as failed.

    Called from the Red Team worker's startup hook. Runs only enter
    ``running`` from inside ``RedTeamWorker._handle_plan_approved``;
    that handler isn't checkpointed, so a container restart mid-loop
    orphans whatever runs were in flight. Sweeping at boot stops them
    from sitting in the UI forever. Returns the IDs swept so the
    caller can log them."""
    result = await session.execute(
        update(runs)
        .where(runs.c.status == "running")
        .values(status="failed", ended_at=_utcnow())
        .returning(runs.c.id)
    )
    return [row[0] for row in result.all()]
