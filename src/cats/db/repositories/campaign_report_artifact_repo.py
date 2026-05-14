"""Repository for documenter-rendered SVG artifacts.

One row per rendered chart, scoped to a campaign. The documenter
writes an artifact when its ``render_*`` tools are invoked; the api's
``GET /campaigns/{cid}/report/artifacts/{name}`` route reads it
straight back out so embedded ``![alt](name)`` markdown references
resolve without any shared filesystem between containers.

``(campaign_id, name)`` is unique — re-rendering a chart under the
same name overwrites the prior body, which keeps regenerated reports
idempotent.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from cats.db.schema import campaign_report_artifacts


async def upsert_artifact(
    session: AsyncSession,
    *,
    campaign_id: UUID,
    name: str,
    kind: str,
    title: str,
    alt: str,
    body: str,
    content_type: str = "image/svg+xml",
) -> None:
    """Insert or overwrite the artifact named ``name`` for ``campaign_id``.

    Regenerating a campaign report replaces the prior artifact set in
    place — the operator's artifact URLs stay stable across re-runs."""
    stmt = (
        pg_insert(campaign_report_artifacts)
        .values(
            campaign_id=campaign_id,
            name=name,
            kind=kind,
            title=title,
            alt=alt,
            content_type=content_type,
            body=body,
        )
        .on_conflict_do_update(
            constraint="uq_campaign_report_artifacts_campaign_id_name",
            set_={
                "kind": kind,
                "title": title,
                "alt": alt,
                "content_type": content_type,
                "body": body,
            },
        )
    )
    await session.execute(stmt)


async def get_artifact(
    session: AsyncSession, *, campaign_id: UUID, name: str
) -> dict[str, Any] | None:
    """Fetch one artifact by (campaign_id, name). Returns ``None`` when
    no matching row exists — the route turns that into a 404."""
    row = (
        await session.execute(
            select(
                campaign_report_artifacts.c.name,
                campaign_report_artifacts.c.kind,
                campaign_report_artifacts.c.title,
                campaign_report_artifacts.c.alt,
                campaign_report_artifacts.c.content_type,
                campaign_report_artifacts.c.body,
            ).where(
                campaign_report_artifacts.c.campaign_id == campaign_id,
                campaign_report_artifacts.c.name == name,
            )
        )
    ).first()
    if row is None:
        return None
    return {
        "name": row.name,
        "kind": row.kind,
        "title": row.title,
        "alt": row.alt,
        "content_type": row.content_type,
        "body": row.body,
    }


async def list_artifacts(session: AsyncSession, *, campaign_id: UUID) -> list[dict[str, Any]]:
    """All artifacts for ``campaign_id``. Used by report-listing and
    eval assertions ("every body_markdown image reference exists")."""
    rows = (
        await session.execute(
            select(
                campaign_report_artifacts.c.name,
                campaign_report_artifacts.c.kind,
                campaign_report_artifacts.c.title,
                campaign_report_artifacts.c.alt,
                campaign_report_artifacts.c.content_type,
            )
            .where(campaign_report_artifacts.c.campaign_id == campaign_id)
            .order_by(campaign_report_artifacts.c.created_at)
        )
    ).all()
    return [
        {
            "name": r.name,
            "kind": r.kind,
            "title": r.title,
            "alt": r.alt,
            "content_type": r.content_type,
        }
        for r in rows
    ]


async def delete_artifacts(session: AsyncSession, *, campaign_id: UUID) -> int:
    """Wipe all artifacts for a campaign (used when a regeneration
    starts a clean run). Returns the row count deleted (or ``0`` when
    the driver doesn't surface ``rowcount`` — async drivers vary)."""
    result = await session.execute(
        delete(campaign_report_artifacts).where(
            campaign_report_artifacts.c.campaign_id == campaign_id
        )
    )
    # ``rowcount`` is an attribute on CursorResult but not on the base
    # Result protocol mypy infers — fall back to 0 when it's absent.
    return int(getattr(result, "rowcount", 0) or 0)
