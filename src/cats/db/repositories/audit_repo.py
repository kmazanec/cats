"""Audit-log writes + reads. Append-only is enforced by the Postgres trigger
in migration 20260511_0001 — this module provides the canonical write path
plus a simple list query for the dashboard."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import desc, insert, select
from sqlalchemy.ext.asyncio import AsyncSession

from cats.db.schema import audit_log


async def write_audit(
    session: AsyncSession,
    *,
    actor: str,
    action: str,
    target_kind: str,
    target_id: UUID | None = None,
    payload: dict[str, Any] | None = None,
    trace_id: str | None = None,
) -> None:
    """Record a user-or-platform action. Raises if the DB insert fails — by
    design: an audit-log write that silently swallows errors would let the
    rest of the action commit without a trace, defeating the audit boundary
    in `ARCHITECTURE.md` §6.1. The DB-level append-only trigger guarantees
    rows that *do* land cannot be modified or deleted afterward.
    """
    await session.execute(
        insert(audit_log).values(
            actor=actor,
            action=action,
            target_kind=target_kind,
            target_id=target_id,
            payload=payload or {},
            trace_id=trace_id,
        )
    )


async def list_audit(
    session: AsyncSession,
    *,
    limit: int = 200,
    actor: str | None = None,
    action: str | None = None,
) -> list[dict[str, Any]]:
    stmt = select(
        audit_log.c.id,
        audit_log.c.actor,
        audit_log.c.action,
        audit_log.c.target_kind,
        audit_log.c.target_id,
        audit_log.c.payload,
        audit_log.c.at,
    ).order_by(desc(audit_log.c.at))
    if actor:
        stmt = stmt.where(audit_log.c.actor == actor)
    if action:
        stmt = stmt.where(audit_log.c.action == action)
    stmt = stmt.limit(limit)
    rows = (await session.execute(stmt)).all()
    return [
        {
            "id": r.id,
            "actor": r.actor,
            "action": r.action,
            "target_kind": r.target_kind,
            "target_id": r.target_id,
            "payload": r.payload or {},
            "at": r.at,
        }
        for r in rows
    ]
