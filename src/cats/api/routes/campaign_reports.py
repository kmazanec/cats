"""Campaign-report routes.

- ``GET /campaigns/{id}/report`` — render the persisted Markdown +
  embedded SVG artifacts as an HTML page.
- ``POST /campaigns/{id}/report`` — manually (re-)trigger the
  Documentation Agent's campaign-report writer.
- ``GET /campaigns/{id}/report/artifacts/{name}`` — serve a single
  rendered SVG off disk under ``settings.campaign_reports_dir``.

The auto-trigger lives in ``cats.workers.documentation``; this
module is the operator-facing surface.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, RedirectResponse
from markupsafe import Markup

from cats.api.auth import Principal, require_user
from cats.api.templating import templates
from cats.config import settings
from cats.db.engine import session_scope
from cats.db.repositories.campaign_repo import get_campaign_with_project
from cats.db.repositories.campaign_report_repo import (
    get_campaign_report,
    mark_report_completed,
    mark_report_failed,
    upsert_pending_report,
)
from cats.llm.client import get_llm
from cats.logging import get_logger
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


@router.post("/{campaign_id}/report", dependencies=[Depends(require_csrf)])
async def regenerate_report(
    request: Request,
    campaign_id: UUID,
    principal: Principal = Depends(require_user),
) -> Any:
    """Operator-triggered (re)generation. Runs the writer synchronously
    inside the request so the operator sees the result on redirect —
    this is rare (one click) and bounded by the tool-loop turn limit,
    so a request-scoped tool loop is acceptable. The auto-trigger from
    the Documentation worker is the volume path."""
    async with session_scope() as session:
        campaign = await get_campaign_with_project(session, campaign_id=campaign_id)
        if campaign is None:
            raise HTTPException(status_code=404, detail="campaign not found")
        await upsert_pending_report(session, campaign_id=campaign_id)
        await session.commit()

        # Import here to avoid a top-level cycle (worker imports api
        # context for SSE event publishing in some paths).
        from cats.agents.documentation.campaign_writer import write_campaign_report

        try:
            result = await write_campaign_report(
                llm=get_llm(),
                session=session,
                campaign_id=campaign_id,
            )
        except Exception as exc:
            log.exception(
                "campaign_report.manual_regenerate_failed",
                campaign_id=str(campaign_id),
            )
            await mark_report_failed(
                session,
                campaign_id=campaign_id,
                reason=f"{type(exc).__name__}: {exc}",
            )
            await session.commit()
            return RedirectResponse(url=f"/campaigns/{campaign_id}/report", status_code=303)
        await mark_report_completed(
            session,
            campaign_id=campaign_id,
            body_markdown=result.body_markdown,
            artifacts=result.artifacts,
            model=result.model,
            tokens_in=result.tokens_in,
            tokens_out=result.tokens_out,
            usd_estimate=result.usd_estimate,
            tool_transcript=result.tool_transcript,
        )

    log.info(
        "campaign_report.manual_regenerate_ok",
        campaign_id=str(campaign_id),
        actor=principal.email,
        artifacts=len(result.artifacts),
    )
    return RedirectResponse(url=f"/campaigns/{campaign_id}/report", status_code=303)


# Strict whitelist: artifact filenames are model-controlled output we
# wrote to disk. Constrain to our exact filename shape so a crafted
# request can't escape the artifacts directory even if the upstream
# rewrite logic ever drifts.
_ARTIFACT_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,80}\.svg$")


@router.get("/{campaign_id}/report/artifacts/{filename}")
async def serve_artifact(
    campaign_id: UUID,
    filename: str,
    principal: Principal = Depends(require_user),
) -> Any:
    """Serve a single SVG artifact off disk under
    ``settings.campaign_reports_dir/{cid}/artifacts/``. The filename
    is checked against a strict regex (kebab-case .svg only). The
    auth requirement is the same as the rest of the campaigns
    surface."""
    _ = principal  # auth-gated by Depends
    if not _ARTIFACT_NAME_RE.match(filename):
        raise HTTPException(status_code=400, detail="invalid artifact name")
    root = Path(settings.campaign_reports_dir) / str(campaign_id) / "artifacts"
    full = (root / filename).resolve()
    # Belt + suspenders: confirm the resolved path is still inside
    # the artifacts root (defense in depth — the regex already rules
    # out '..' but symlink trickery could in principle escape).
    try:
        full.relative_to(root.resolve())
    except ValueError as e:
        raise HTTPException(status_code=400, detail="invalid artifact path") from e
    if not full.is_file():
        raise HTTPException(status_code=404, detail="artifact not found")
    return FileResponse(str(full), media_type="image/svg+xml")


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
