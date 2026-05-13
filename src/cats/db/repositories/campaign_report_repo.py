"""Repository for the per-campaign rollup report.

One row per campaign (enforced by the unique constraint on
``campaign_id``). The Documentation Agent's campaign-report writer
creates the row in ``generating`` status, then UPDATEs it to
``completed`` with the rendered markdown + artifact metadata when
the LLM tool-loop returns.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from cats.db.schema import campaign_reports


def _utcnow() -> datetime:
    return datetime.now(UTC)


async def get_campaign_report(session: AsyncSession, *, campaign_id: UUID) -> dict[str, Any] | None:
    """Fetch the report row for ``campaign_id``. Returns a dict
    (rather than a SQLAlchemy Row) so callers stay loop-decoupled
    after the session closes."""
    row = (
        await session.execute(
            select(
                campaign_reports.c.id,
                campaign_reports.c.campaign_id,
                campaign_reports.c.status,
                campaign_reports.c.body_markdown,
                campaign_reports.c.artifacts,
                campaign_reports.c.model,
                campaign_reports.c.tokens_in,
                campaign_reports.c.tokens_out,
                campaign_reports.c.usd_estimate,
                campaign_reports.c.tool_transcript,
                campaign_reports.c.generated_at,
                campaign_reports.c.created_at,
            ).where(campaign_reports.c.campaign_id == campaign_id)
        )
    ).first()
    if row is None:
        return None
    return {
        "id": row.id,
        "campaign_id": row.campaign_id,
        "status": row.status,
        "body_markdown": row.body_markdown,
        "artifacts": row.artifacts or [],
        "model": row.model,
        "tokens_in": row.tokens_in,
        "tokens_out": row.tokens_out,
        "usd_estimate": row.usd_estimate,
        "tool_transcript": row.tool_transcript or [],
        "generated_at": row.generated_at,
        "created_at": row.created_at,
    }


async def upsert_pending_report(session: AsyncSession, *, campaign_id: UUID) -> UUID:
    """Reserve the row for ``campaign_id`` in ``generating`` status.

    INSERT on the first call; if a row already exists (re-run path),
    re-stamp it to ``generating`` and zero the prior result. Returns
    the report id either way."""
    new_id = uuid4()
    stmt = (
        pg_insert(campaign_reports)
        .values(
            id=new_id,
            campaign_id=campaign_id,
            status="generating",
            body_markdown="",
            artifacts=[],
            tool_transcript=[],
        )
        .on_conflict_do_update(
            index_elements=["campaign_id"],
            set_={
                "status": "generating",
                "body_markdown": "",
                "artifacts": [],
                "tool_transcript": [],
                "generated_at": None,
            },
        )
        .returning(campaign_reports.c.id)
    )
    result = await session.execute(stmt)
    return UUID(str(result.scalar_one()))


async def mark_report_completed(
    session: AsyncSession,
    *,
    campaign_id: UUID,
    body_markdown: str,
    artifacts: list[dict[str, Any]],
    model: str,
    tokens_in: int,
    tokens_out: int,
    usd_estimate: float,
    tool_transcript: list[dict[str, Any]],
) -> None:
    """UPDATE the row to ``completed`` with the rendered narrative +
    artifact metadata. Callers that hit an unrecoverable failure should
    use :func:`mark_report_failed` instead."""
    await session.execute(
        campaign_reports.update()
        .where(campaign_reports.c.campaign_id == campaign_id)
        .values(
            status="completed",
            body_markdown=body_markdown,
            artifacts=artifacts,
            model=model[:120],
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            usd_estimate=usd_estimate,
            tool_transcript=tool_transcript,
            generated_at=_utcnow(),
        )
    )


async def mark_report_failed(
    session: AsyncSession,
    *,
    campaign_id: UUID,
    reason: str,
    tool_transcript: list[dict[str, Any]] | None = None,
) -> None:
    """Mark the report failed and stash the failure reason in
    ``body_markdown`` so the UI surfaces it. Tool transcript (when
    provided) is preserved for post-mortem."""
    await session.execute(
        campaign_reports.update()
        .where(campaign_reports.c.campaign_id == campaign_id)
        .values(
            status="failed",
            body_markdown=f"# Report generation failed\n\n{reason}",
            tool_transcript=tool_transcript or [],
            generated_at=_utcnow(),
        )
    )
