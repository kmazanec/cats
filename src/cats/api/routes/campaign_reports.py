"""Campaign-report routes.

- ``GET /campaigns/{id}/report`` — render the persisted Markdown +
  embedded SVG artifacts as an HTML page.
- ``POST /campaigns/{id}/report`` — manually (re-)trigger the
  Documentation Agent's campaign-report writer.
- ``GET /campaigns/{id}/report/artifacts/{name}`` — serve a single
  rendered SVG straight out of the ``campaign_report_artifacts`` table.

The auto-trigger lives in ``cats.workers.documentation``; this
module is the operator-facing surface.
"""

from __future__ import annotations

import re
from typing import Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from markupsafe import Markup

from cats.api.auth import Principal, require_user
from cats.api.templating import templates
from cats.db.engine import session_scope
from cats.db.repositories.campaign_repo import get_campaign_with_project
from cats.db.repositories.campaign_report_artifact_repo import get_artifact
from cats.db.repositories.campaign_report_repo import (
    get_campaign_report,
    upsert_pending_report,
)
from cats.logging import get_logger
from cats.messaging import (
    Bus,
    CampaignReportRequestedPayload,
    Envelope,
    MessageKind,
)
from cats.security.csrf import require_csrf

router = APIRouter()
log = get_logger(__name__)


def _chrome_ctx(principal: Principal) -> dict[str, Any]:
    return {
        "user_email": principal.email,
        "is_admin": principal.role == "admin",
    }


@router.get("/{campaign_id}/report")
async def view_report(
    request: Request,
    campaign_id: UUID,
    principal: Principal = Depends(require_user),
) -> Any:
    """Operator-facing render of the persisted campaign report. The
    Markdown body's ``![alt](rel.svg)`` references are rewritten to
    point at the artifact-serving sibling route so the SVGs load
    inline without an additional client-side fetch."""
    async with session_scope() as session:
        campaign = await get_campaign_with_project(session, campaign_id=campaign_id)
        if campaign is None:
            raise HTTPException(status_code=404, detail="campaign not found")
        report = await get_campaign_report(session, campaign_id=campaign_id)

    ctx = _chrome_ctx(principal)
    rewritten_markdown = ""
    if report and report.get("body_markdown"):
        rewritten_markdown = _rewrite_artifact_paths(
            report["body_markdown"], campaign_id=campaign_id
        )
    ctx.update(
        {
            "campaign": campaign,
            "report": report,
            "body_markdown": rewritten_markdown,
        }
    )
    return templates.TemplateResponse(request, "campaign_report.html", ctx)


@router.get("/{campaign_id}/report/status")
async def report_status(
    campaign_id: UUID,
    principal: Principal = Depends(require_user),
) -> dict[str, Any]:
    """Lightweight JSON probe the report page polls for completion in
    case the SSE stream drops. Returns the row's status (or ``"none"``
    when no row exists yet) + the artifact count so the client can
    decide whether to reload."""
    _ = principal  # auth-gated by Depends
    async with session_scope() as session:
        report = await get_campaign_report(session, campaign_id=campaign_id)
    if report is None:
        return {"status": "none", "artifacts": 0, "generated_at": None}
    return {
        "status": report["status"],
        "artifacts": len(report.get("artifacts") or []),
        "generated_at": (
            report["generated_at"].isoformat() if report.get("generated_at") else None
        ),
    }


@router.post("/{campaign_id}/report", dependencies=[Depends(require_csrf)])
async def regenerate_report(
    request: Request,
    campaign_id: UUID,
    principal: Principal = Depends(require_user),
) -> Any:
    """Operator-triggered (re)generation. Enqueues a
    ``CampaignReportRequested`` envelope and redirects immediately;
    the Documentation worker picks the message off the bus and runs
    the LLM tool loop. The report page polls / listens on SSE for
    the writer's completion. This is the right shape for a 10-30s+
    LLM tool loop — the request returns in under a second so the
    operator's browser doesn't sit on a spinner.

    Idempotency key carries a uuid suffix so back-to-back manual
    regenerations each get a fresh message — unlike the auto-trigger
    path, which collapses on a fixed key so re-arriving verdicts
    don't pile up duplicate work."""
    async with session_scope() as session:
        campaign = await get_campaign_with_project(session, campaign_id=campaign_id)
        if campaign is None:
            raise HTTPException(status_code=404, detail="campaign not found")
        await upsert_pending_report(session, campaign_id=campaign_id)

        bus = Bus()
        request_uuid = uuid4()
        envelope = Envelope[CampaignReportRequestedPayload](
            kind=MessageKind.CAMPAIGN_REPORT_REQUESTED,
            from_agent="operator",
            to_agent="documentation",
            payload=CampaignReportRequestedPayload(
                campaign_id=campaign_id,
                reason="manual_regenerate",
                requested_by=principal.user_id,
            ),
            campaign_id=campaign_id,
            idempotency_key=(f"documentation:campaign_report:{campaign_id}:manual:{request_uuid}"),
        )
        await bus.emit(session, envelope)
        await session.commit()

    log.info(
        "campaign_report.manual_enqueued",
        campaign_id=str(campaign_id),
        actor=principal.email,
    )
    return RedirectResponse(url=f"/campaigns/{campaign_id}/report", status_code=303)


# Strict whitelist: artifact filenames are model-controlled output the
# documenter chose; they double as the row's ``name`` key. Constrain to
# our exact shape (kebab-case .svg) so a crafted request can't smuggle
# anything strange through the route parameter.
_ARTIFACT_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,80}\.svg$")


@router.get("/{campaign_id}/report/artifacts/{filename}")
async def serve_artifact(
    campaign_id: UUID,
    filename: str,
    principal: Principal = Depends(require_user),
) -> Any:
    """Serve a documenter-rendered SVG straight out of
    ``campaign_report_artifacts``. The filename is checked against a
    strict regex (kebab-case .svg only) before the lookup. Auth gating
    matches the rest of the campaigns surface."""
    _ = principal  # auth-gated by Depends
    if not _ARTIFACT_NAME_RE.match(filename):
        raise HTTPException(status_code=400, detail="invalid artifact name")
    async with session_scope() as session:
        row = await get_artifact(session, campaign_id=campaign_id, name=filename)
    if row is None:
        raise HTTPException(status_code=404, detail="artifact not found")
    return Response(
        content=row["body"],
        media_type=row.get("content_type") or "image/svg+xml",
    )


def _rewrite_artifact_paths(body_markdown: str, *, campaign_id: UUID) -> str:
    """Rewrite ``![alt](something.svg)`` references in the LLM-authored
    markdown so they point at the per-campaign artifact-serving route.
    The LLM emits relative filenames (e.g. ``verdict-histogram.svg``);
    the rendered page hits
    ``/campaigns/{cid}/report/artifacts/verdict-histogram.svg``."""

    def replace(match: re.Match[str]) -> str:
        alt = match.group(1)
        path = match.group(2).strip()
        # Only rewrite simple .svg filenames; leave external URLs alone.
        if path.startswith(("http://", "https://", "/")) or not path.endswith(".svg"):
            return match.group(0)
        # Strip directory prefixes the LLM may have added in error.
        name = path.rsplit("/", 1)[-1]
        return f"![{alt}](/campaigns/{campaign_id}/report/artifacts/{name})"

    return re.sub(r"!\[([^\]]*)\]\(([^)]+)\)", replace, body_markdown)


# Hint mypy that Markup is intentionally imported (re-exported for
# tests that want to render via the same filter).
_ = Markup
