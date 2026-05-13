"""RegressionCase + RegressionSweep + RegressionRun persistence.

Wraps the three R8 tables. The runner and the sweep worker call into
this module; the routes read through it. The auto-promotion hook lives
here too — when the Documentation Agent promotes a Finding with a
``pass`` verdict, it calls :func:`ensure_regression_case` to record a
RegressionCase pinned to the locked rubric version that produced the
finding. Idempotent on ``source_finding_id`` so re-delivery of the
verdict envelope cannot create duplicate cases.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import desc, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from cats.db.schema import (
    findings,
    regression_cases,
    regression_runs,
    regression_sweeps,
    rubric_versions,
)


def _utcnow() -> datetime:
    return datetime.now(UTC)


# ---------------------------------------------------------------------------
# RegressionCase
# ---------------------------------------------------------------------------


async def ensure_regression_case(
    session: AsyncSession,
    *,
    source_finding_id: UUID,
    canonical_attack_id: UUID,
    locked_rubric_version_id: UUID | None,
) -> UUID:
    """Idempotent. Promotes a Finding into a RegressionCase. Returns the
    case id whether newly created or pre-existing. Appending a new
    canonical_attack_id to an existing case is handled here too — if
    the same Finding fires across multiple AttackExecutions later, we
    add to the list rather than splitting the case.
    """
    existing = (
        await session.execute(
            select(regression_cases.c.id, regression_cases.c.canonical_attack_ids).where(
                regression_cases.c.source_finding_id == source_finding_id
            )
        )
    ).first()
    if existing is not None:
        ids_raw = existing.canonical_attack_ids or []
        ids = [str(x) for x in ids_raw] if isinstance(ids_raw, list) else []
        if str(canonical_attack_id) not in ids:
            ids.append(str(canonical_attack_id))
            await session.execute(
                update(regression_cases)
                .where(regression_cases.c.id == existing.id)
                .values(canonical_attack_ids=ids)
            )
        return UUID(str(existing.id))

    new_id = uuid4()
    stmt = (
        pg_insert(regression_cases)
        .values(
            id=new_id,
            source_finding_id=source_finding_id,
            canonical_attack_ids=[str(canonical_attack_id)],
            refusal_exemplar_text="",
            refusal_exemplar_embedding=None,
            locked_rubric_version_id=locked_rubric_version_id,
        )
        .on_conflict_do_nothing(index_elements=["source_finding_id"])
        .returning(regression_cases.c.id)
    )
    result = await session.execute(stmt)
    row = result.scalar_one_or_none()
    if row is not None:
        return UUID(str(row))
    again = await session.execute(
        select(regression_cases.c.id).where(
            regression_cases.c.source_finding_id == source_finding_id
        )
    )
    return UUID(str(again.scalar_one()))


async def get_regression_case(session: AsyncSession, *, case_id: UUID) -> dict[str, Any] | None:
    row = (
        await session.execute(
            select(
                regression_cases.c.id,
                regression_cases.c.source_finding_id,
                regression_cases.c.canonical_attack_ids,
                regression_cases.c.refusal_exemplar_text,
                regression_cases.c.refusal_exemplar_embedding,
                regression_cases.c.locked_rubric_version_id,
                regression_cases.c.created_at,
            ).where(regression_cases.c.id == case_id)
        )
    ).first()
    if row is None:
        return None
    return _case_row_to_dict(row)


async def list_regression_cases(
    session: AsyncSession,
    *,
    project_id: UUID | None = None,
    limit: int = 200,
) -> list[dict[str, Any]]:
    """List cases. When ``project_id`` is set, joins through findings →
    runs → campaigns → projects so the sweep worker can pick exactly
    the cases for one project.
    """
    if project_id is None:
        rows = (
            await session.execute(
                select(
                    regression_cases.c.id,
                    regression_cases.c.source_finding_id,
                    regression_cases.c.canonical_attack_ids,
                    regression_cases.c.refusal_exemplar_text,
                    regression_cases.c.refusal_exemplar_embedding,
                    regression_cases.c.locked_rubric_version_id,
                    regression_cases.c.created_at,
                )
                .order_by(desc(regression_cases.c.created_at))
                .limit(limit)
            )
        ).all()
        return [_case_row_to_dict(r) for r in rows]
    # Project-scoped listing — join through findings → runs → campaigns.
    from cats.db.schema import campaigns, runs

    rows = (
        await session.execute(
            select(
                regression_cases.c.id,
                regression_cases.c.source_finding_id,
                regression_cases.c.canonical_attack_ids,
                regression_cases.c.refusal_exemplar_text,
                regression_cases.c.refusal_exemplar_embedding,
                regression_cases.c.locked_rubric_version_id,
                regression_cases.c.created_at,
            )
            .select_from(
                regression_cases.join(
                    findings, findings.c.id == regression_cases.c.source_finding_id
                )
                .join(runs, runs.c.id == findings.c.run_id)
                .join(campaigns, campaigns.c.id == runs.c.campaign_id)
            )
            .where(campaigns.c.project_id == project_id)
            .order_by(desc(regression_cases.c.created_at))
            .limit(limit)
        )
    ).all()
    return [_case_row_to_dict(r) for r in rows]


async def update_exemplar(
    session: AsyncSession,
    *,
    case_id: UUID,
    text_: str,
    embedding: list[float] | None,
) -> None:
    await session.execute(
        update(regression_cases)
        .where(regression_cases.c.id == case_id)
        .values(
            refusal_exemplar_text=text_,
            refusal_exemplar_embedding=embedding,
        )
    )


def _case_row_to_dict(r: Any) -> dict[str, Any]:
    ids_raw = r.canonical_attack_ids or []
    canonical_ids = [UUID(str(x)) for x in ids_raw] if isinstance(ids_raw, list) else []
    return {
        "id": UUID(str(r.id)),
        "source_finding_id": UUID(str(r.source_finding_id)),
        "canonical_attack_ids": canonical_ids,
        "refusal_exemplar_text": r.refusal_exemplar_text or "",
        "refusal_exemplar_embedding": r.refusal_exemplar_embedding,
        "locked_rubric_version_id": (
            UUID(str(r.locked_rubric_version_id))
            if r.locked_rubric_version_id is not None
            else None
        ),
        "created_at": r.created_at,
    }


async def get_locked_rubric_text(
    session: AsyncSession, *, rubric_version_id: UUID
) -> tuple[str, str, int] | None:
    """Returns (category, prompt_text, version_int) for the locked
    rubric_versions row. Empty result -> the case was promoted before
    a rubric_version_id was recorded (legacy) — caller falls back."""
    row = (
        await session.execute(
            select(
                rubric_versions.c.category,
                rubric_versions.c.prompt_text,
                rubric_versions.c.version,
            ).where(rubric_versions.c.id == rubric_version_id)
        )
    ).first()
    if row is None:
        return None
    return (row.category, row.prompt_text, int(row.version))


# ---------------------------------------------------------------------------
# RegressionSweep + RegressionRun
# ---------------------------------------------------------------------------


async def create_sweep(
    session: AsyncSession,
    *,
    project_id: UUID,
    version_tag: str = "",
    triggered_by: str = "manual_cli",
    sweep_id: UUID | None = None,
) -> UUID:
    # Optional ``sweep_id`` lets the caller pre-allocate a UUID before
    # the row exists — used by ``schedule_sweep_in_background`` so the
    # webhook can echo the id in its 200 response and the caller can
    # later look the sweep up via ``get_sweep``.
    new_id = sweep_id or uuid4()
    await session.execute(
        pg_insert(regression_sweeps).values(
            id=new_id,
            project_id=project_id,
            version_tag=version_tag[:120],
            triggered_by=triggered_by[:32],
            status="running",
        )
    )
    return new_id


async def finalize_sweep(
    session: AsyncSession,
    *,
    sweep_id: UUID,
    num_cases: int,
    num_fixed: int,
    num_regressed: int,
    num_needs_review: int,
    num_errored: int,
    status: str = "completed",
) -> None:
    await session.execute(
        update(regression_sweeps)
        .where(regression_sweeps.c.id == sweep_id)
        .values(
            status=status,
            num_cases=num_cases,
            num_fixed=num_fixed,
            num_regressed=num_regressed,
            num_needs_review=num_needs_review,
            num_errored=num_errored,
            finished_at=_utcnow(),
        )
    )


async def get_sweep(session: AsyncSession, *, sweep_id: UUID) -> dict[str, Any] | None:
    row = (
        await session.execute(select(regression_sweeps).where(regression_sweeps.c.id == sweep_id))
    ).first()
    if row is None:
        return None
    return dict(row._mapping)


async def record_run(
    session: AsyncSession,
    *,
    regression_case_id: UUID,
    sweep_id: UUID | None,
    status: str,
    gate_deterministic: bool | None,
    gate_judge: bool | None,
    gate_fingerprint: bool | None,
    reason: str,
    response_text: str,
    trace_id: str = "",
    triggered_by: str = "manual_cli",
) -> UUID:
    new_id = uuid4()
    await session.execute(
        pg_insert(regression_runs).values(
            id=new_id,
            regression_case_id=regression_case_id,
            sweep_id=sweep_id,
            status=status,
            gate_deterministic=gate_deterministic,
            gate_judge=gate_judge,
            gate_fingerprint=gate_fingerprint,
            reason=reason[:2000],
            # Cap the persisted response so a megabyte-sized SSE blob
            # doesn't bloat the row. The full payload is recoverable
            # from the LangSmith trace via trace_id.
            response_text=(response_text or "")[:32000],
            trace_id=(trace_id or "")[:120],
            finished_at=_utcnow(),
            triggered_by=triggered_by[:32],
        )
    )
    return new_id


async def latest_run_for_case(session: AsyncSession, *, case_id: UUID) -> dict[str, Any] | None:
    row = (
        await session.execute(
            select(regression_runs)
            .where(regression_runs.c.regression_case_id == case_id)
            .order_by(desc(regression_runs.c.started_at))
            .limit(1)
        )
    ).first()
    if row is None:
        return None
    return dict(row._mapping)


async def list_runs_for_sweep(session: AsyncSession, *, sweep_id: UUID) -> list[dict[str, Any]]:
    rows = (
        await session.execute(
            select(regression_runs)
            .where(regression_runs.c.sweep_id == sweep_id)
            .order_by(desc(regression_runs.c.started_at))
        )
    ).all()
    return [dict(r._mapping) for r in rows]


async def update_finding_status_from_run(
    session: AsyncSession, *, source_finding_id: UUID, run_status: str
) -> None:
    """Adjust the Finding's parent status based on the latest regression
    verdict. ``fixed_held`` → ``fixed``; ``regressed`` → ``regressed``;
    ``needs_review`` leaves the existing status alone so an operator
    explicitly resolves it."""
    if run_status == "fixed_held":
        new_status = "fixed"
    elif run_status == "regressed":
        new_status = "regressed"
    else:
        return
    await session.execute(
        update(findings)
        .where(findings.c.id == source_finding_id)
        .values(status=new_status, updated_at=_utcnow())
    )
