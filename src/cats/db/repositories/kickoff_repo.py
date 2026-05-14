"""Persistence for the per-Run briefing kickoff turn.

Every Run opens with a bare ``default_briefing`` request to the Co-Pilot
to harvest its server-minted ``conversationId``. That round-trip is not
an attack attempt (the Co-Pilot ignores ``question`` on
``default_briefing``), so it lives in its own table — counters, the
Judge, and regression queries all stay limited to ``attack_executions``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from cats.db.schema import kickoff_turns


def _utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class KickoffRow:
    id: UUID
    run_id: UUID
    conversation_id: str | None
    target_response: dict[str, Any]
    target_status_code: int | None
    target_latency_ms: int | None
    started_at: datetime | None
    ended_at: datetime | None
    error: str | None


async def record_kickoff(
    session: AsyncSession,
    *,
    run_id: UUID,
    conversation_id: str | None,
    target_response: dict[str, Any],
    target_status_code: int | None,
    target_latency_ms: int | None,
    started_at: datetime | None,
    ended_at: datetime | None,
    error: str | None,
) -> UUID:
    """Insert a kickoff row, idempotent on ``run_id``. Worker retries
    (bus redelivery, agent restart) re-enter ``propose_attack`` with a
    fresh ``ctx``; without ON CONFLICT the unique constraint would
    raise on the second kickoff. Returns the existing row's id when
    the run already had one — callers should treat that as the kickoff
    having "already happened" and prefer ``get_for_run`` for the
    canonical state."""
    row_id = uuid4()
    stmt = (
        pg_insert(kickoff_turns)
        .values(
            id=row_id,
            run_id=run_id,
            conversation_id=conversation_id,
            target_response=target_response,
            target_status_code=target_status_code,
            target_latency_ms=target_latency_ms,
            started_at=started_at,
            ended_at=ended_at,
            error=error,
            created_at=_utcnow(),
        )
        .on_conflict_do_nothing(index_elements=["run_id"])
        .returning(kickoff_turns.c.id)
    )
    result = await session.execute(stmt)
    inserted_id = result.scalar_one_or_none()
    await session.commit()
    if inserted_id is not None:
        return inserted_id  # type: ignore[no-any-return]
    # Conflict: the row already exists. Fetch and return its id.
    existing = await session.execute(
        select(kickoff_turns.c.id).where(kickoff_turns.c.run_id == run_id)
    )
    return existing.scalar_one()  # type: ignore[no-any-return]


async def get_for_run(session: AsyncSession, *, run_id: UUID) -> KickoffRow | None:
    result = await session.execute(select(kickoff_turns).where(kickoff_turns.c.run_id == run_id))
    row = result.mappings().one_or_none()
    if row is None:
        return None
    return KickoffRow(
        id=row["id"],
        run_id=row["run_id"],
        conversation_id=row["conversation_id"],
        target_response=row["target_response"] or {},
        target_status_code=row["target_status_code"],
        target_latency_ms=row["target_latency_ms"],
        started_at=row["started_at"],
        ended_at=row["ended_at"],
        error=row["error"],
    )
