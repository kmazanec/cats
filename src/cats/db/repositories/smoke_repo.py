"""Repository helpers used by the smoke path. Hand-written async SQL keeps
the layer thin and obvious; we'll generalize when there's a second caller."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import insert, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from cats.db.schema import (
    attack_executions,
    attacks,
    campaigns,
    finding_executions,
    findings,
    judge_verdicts,
    project_versions,
    projects,
    runs,
)


def _utcnow() -> datetime:
    return datetime.now(UTC)


async def upsert_project(
    session: AsyncSession,
    *,
    name: str,
    base_url: str,
    env: str = "local",
) -> UUID:
    """Idempotent project upsert by name."""
    existing = await session.execute(select(projects.c.id).where(projects.c.name == name))
    found = existing.scalar_one_or_none()
    if found:
        return found  # type: ignore[no-any-return]

    new_id = uuid4()
    await session.execute(
        insert(projects).values(
            id=new_id,
            name=name,
            base_url=base_url,
            env=env,
            allow_run_against=False,
        )
    )
    return new_id


async def upsert_project_version(
    session: AsyncSession,
    *,
    project_id: UUID,
    label: str,
) -> UUID:
    existing = await session.execute(
        select(project_versions.c.id)
        .where(project_versions.c.project_id == project_id)
        .where(project_versions.c.label == label)
    )
    found = existing.scalar_one_or_none()
    if found:
        return found  # type: ignore[no-any-return]

    new_id = uuid4()
    await session.execute(
        insert(project_versions).values(
            id=new_id,
            project_id=project_id,
            label=label,
            deployed_at=_utcnow(),
        )
    )
    return new_id


async def create_campaign(
    session: AsyncSession,
    *,
    name: str,
    project_id: UUID,
) -> UUID:
    new_id = uuid4()
    await session.execute(
        insert(campaigns).values(
            id=new_id,
            name=name,
            project_id=project_id,
            mode="blackhat",
            trigger="on_demand",
        )
    )
    return new_id


async def create_run(
    session: AsyncSession,
    *,
    campaign_id: UUID,
    project_version_id: UUID,
) -> UUID:
    new_id = uuid4()
    now = _utcnow()
    await session.execute(
        insert(runs).values(
            id=new_id,
            campaign_id=campaign_id,
            project_version_id=project_version_id,
            status="running",
            started_at=now,
        )
    )
    return new_id


async def upsert_attack(
    session: AsyncSession,
    *,
    category: str,
    title: str,
    payload: dict[str, Any],
    signature: str,
    source: str = "seed",
) -> UUID:
    """Upsert by (category, signature) — same attack template reused."""
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
        insert(attacks).values(
            id=new_id,
            category=category,
            title=title,
            payload=payload,
            signature=signature,
            source=source,
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
) -> UUID:
    new_id = uuid4()
    await session.execute(
        insert(judge_verdicts).values(
            id=new_id,
            verdict=verdict,
            is_deterministic=is_deterministic,
            rationale=rationale,
            evidence=evidence,
            judge_model=judge_model,
        )
    )
    return new_id


async def record_attack_execution(
    session: AsyncSession,
    *,
    run_id: UUID,
    attack_id: UUID,
    project_version_id: UUID,
    target_response: dict[str, Any],
    judge_verdict_id: UUID,
    model: str = "",
    tokens_in: int = 0,
    tokens_out: int = 0,
    usd_estimate: float = 0.0,
) -> UUID:
    new_id = uuid4()
    now = _utcnow()
    await session.execute(
        insert(attack_executions).values(
            id=new_id,
            run_id=run_id,
            attack_id=attack_id,
            project_version_id=project_version_id,
            target_response=target_response,
            judge_verdict_id=judge_verdict_id,
            model=model,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            usd_estimate=usd_estimate,
            started_at=now,
            ended_at=now,
        )
    )
    return new_id


async def upsert_finding(
    session: AsyncSession,
    *,
    run_id: UUID,
    category: str,
    signature: str,
    title: str,
    severity: str = "medium",
    summary: str = "",
) -> UUID:
    """Unique on (run_id, category, signature). PG ON CONFLICT keeps it idempotent
    if the same Mutator variant produces the same signature."""
    stmt = (
        pg_insert(findings)
        .values(
            run_id=run_id,
            category=category,
            signature=signature,
            title=title,
            severity=severity,
            summary=summary,
        )
        .on_conflict_do_nothing(index_elements=["run_id", "category", "signature"])
        .returning(findings.c.id)
    )
    result = await session.execute(stmt)
    row = result.scalar_one_or_none()
    if row:
        return row  # type: ignore[no-any-return]
    # Conflict — fetch the existing
    existing = await session.execute(
        select(findings.c.id)
        .where(findings.c.run_id == run_id)
        .where(findings.c.category == category)
        .where(findings.c.signature == signature)
    )
    return existing.scalar_one()  # type: ignore[no-any-return]


async def link_finding_execution(
    session: AsyncSession,
    *,
    finding_id: UUID,
    attack_execution_id: UUID,
) -> None:
    stmt = (
        pg_insert(finding_executions)
        .values(finding_id=finding_id, attack_execution_id=attack_execution_id)
        .on_conflict_do_nothing()
    )
    await session.execute(stmt)


async def complete_run(session: AsyncSession, *, run_id: UUID) -> None:
    from sqlalchemy import update

    await session.execute(
        update(runs).where(runs.c.id == run_id).values(status="completed", ended_at=_utcnow())
    )
