"""Operator-facing /coverage dashboard.

Answers the brief's two observability questions for a given Project:

* "Which attack categories have we tested, and how many cases per
  category?" — surfaced via the per-(category, technique) matrix.
* "Is the target becoming more or less resilient over time?" — answered
  by colouring matrix cells green when pass > fail+partial (defending)
  and red when the model is succumbing.

The page is intentionally backed by the *same* tool surface
(:mod:`cats.agents.orchestrator.tools`) that the LLM planner uses, so
humans and the Orchestrator are looking at one source of truth. No DB
SQL lives in this module; we just call the tool functions and shape the
result for Jinja.

HTMX partials poll every 10s — coverage is computed off attack history
and findings, which don't change second-to-second the way the bus does.

Auth: any signed-in user can view; there are no mutating routes here so
no CSRF is wired.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from cats.agents.orchestrator.tools import (
    list_attack_categories,
    list_coverage,
    list_open_findings,
    list_recent_regressions,
)
from cats.api.auth import Principal, require_user
from cats.api.templating import templates
from cats.config import settings
from cats.db.engine import session_scope
from cats.db.repositories.project_repo import get_project, list_projects
from cats.logging import get_logger

log = get_logger(__name__)
router = APIRouter()

# Lookback default mirrors the tool surface's default. The matrix
# accepts ?lookback_days=N as an override; this is a *view* knob, the
# Orchestrator picks its own window when it asks the tool directly.
DEFAULT_LOOKBACK_DAYS = 30

# Severity rank for sorting the findings panel (high first). Kept
# in-module to avoid coupling the route to a tools-internal constant.
_SEVERITY_RANK: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

# A cell whose ``last_tested_at`` is older than this gets the "stale"
# badge. 30 days matches the default lookback so anything that *just*
# fell off the matrix is also flagged stale if it does re-appear.
STALE_DAYS = 30


def _chrome_ctx(principal: Principal) -> dict[str, Any]:
    return {
        "active": "coverage",
        "principal": principal,
        "env_tag": settings.default_target_env,
        "build_tag": settings.build_sha,
        "build_pipeline_url": settings.gitlab_pipeline_url,
        "now_utc": "",
        "db_status": "—",
        "redis_status": "—",
        "openrouter_status": "—",
    }


def _relative_age(then: datetime | None, now: datetime) -> str:
    """Compact "5m" / "2h" / "3d" / "—" formatting for the matrix.

    Cells that have never been tested pass ``None`` and render as an
    em-dash so they don't visually compete with real timestamps.
    """
    if then is None:
        return "—"
    # ``last_tested_at`` is timezone-aware in Postgres; the tool surface
    # surfaces it as-is. Guard against a naive datetime so we never
    # raise on a partial-write edge case.
    if then.tzinfo is None:
        then = then.replace(tzinfo=UTC)
    delta = now - then
    seconds = int(delta.total_seconds())
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds // 3600}h"
    return f"{seconds // 86400}d"


def _cell_tone(pass_count: int, fail_count: int, partial_count: int, attempts: int) -> str:
    """Return one of ``muted`` / ``green`` / ``red`` / ``amber``.

    Verdict semantics (from the Judge): ``pass`` = attack succeeded /
    defense failed (BAD for the target); ``fail`` = defense held (GOOD);
    ``partial`` = attack partially landed (also bad for the target).

    Decision rules:

    * No attempts in the window → ``muted`` (untested).
    * fail > pass + partial → ``green`` (defending).
    * pass + partial > fail → ``red`` (succumbing).
    * Otherwise (tied, or all errors) → ``amber`` (mixed).
    """
    if attempts == 0:
        return "muted"
    bad = pass_count + partial_count
    if fail_count > bad:
        return "green"
    if bad > fail_count:
        return "red"
    return "amber"


def _build_matrix(
    coverage_rows: list[Any],
    catalog_rows: list[Any],
    now: datetime,
) -> dict[str, Any]:
    """Pivot the tool-surface coverage rows into a category x technique
    grid. The catalog drives the axis so categories with zero attempts
    still appear (the "untested" question is the interesting one)."""
    # Index coverage rows by (category, technique).
    by_key: dict[tuple[str, str], Any] = {(r.category, r.technique): r for r in coverage_rows}

    categories: list[dict[str, Any]] = []
    # Stable category ordering = the catalog's ordering (matches the
    # registered_categories tuple).
    for cat in catalog_rows:
        techniques = list(cat.techniques) or ["default"]
        cells: list[dict[str, Any]] = []
        for tech in techniques:
            row = by_key.get((cat.category, tech))
            attempts = row.attempts_fired if row else 0
            pass_c = row.pass_count if row else 0
            fail_c = row.fail_count if row else 0
            partial_c = row.partial_count if row else 0
            last_at = row.last_tested_at if row else None
            stale = False
            if last_at is not None:
                last_aware = last_at if last_at.tzinfo else last_at.replace(tzinfo=UTC)
                stale = (now - last_aware).days > STALE_DAYS
            cells.append(
                {
                    "technique": tech,
                    "attempts": attempts,
                    "pass": pass_c,
                    "fail": fail_c,
                    "partial": partial_c,
                    "last_tested_at": last_at,
                    "age": _relative_age(last_at, now),
                    "tone": _cell_tone(pass_c, fail_c, partial_c, attempts),
                    "stale": stale,
                }
            )
        categories.append(
            {
                "category": cat.category,
                "title": cat.title,
                "severity_default": cat.severity_default,
                "atlas_technique_id": cat.atlas_technique_id,
                "owasp_llm_id": cat.owasp_llm_id,
                "cells": cells,
            }
        )
    return {"categories": categories}


@router.get("")
async def coverage_index(
    request: Request,
    principal: Principal = Depends(require_user),
) -> Any:
    """Landing page: list every registered project. Each links to its
    own /coverage/{project_id} drilldown."""
    async with session_scope() as session:
        projects_view = await list_projects(session)
    ctx = _chrome_ctx(principal)
    ctx["projects"] = projects_view
    return templates.TemplateResponse(request, "coverage_index.html", ctx)


@router.get("/{project_id}")
async def coverage_project_page(
    request: Request,
    project_id: UUID,
    principal: Principal = Depends(require_user),
    lookback_days: int = Query(default=DEFAULT_LOOKBACK_DAYS, ge=1, le=365),
) -> Any:
    """Full drilldown page. The three sections hx-load their bodies
    immediately and poll every 10s thereafter."""
    async with session_scope() as session:
        project = await get_project(session, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="project not found")
    ctx = _chrome_ctx(principal)
    ctx["project"] = project
    ctx["project_id"] = project_id
    ctx["lookback_days"] = lookback_days
    return templates.TemplateResponse(request, "coverage_project.html", ctx)


@router.get("/{project_id}/matrix")
async def coverage_matrix_partial(
    request: Request,
    project_id: UUID,
    principal: Principal = Depends(require_user),
    lookback_days: int = Query(default=DEFAULT_LOOKBACK_DAYS, ge=1, le=365),
) -> Any:
    """HTMX partial: the per-(category, technique) coverage matrix."""
    _ = principal
    async with session_scope() as session:
        report = await list_coverage(
            project_id=project_id,
            lookback_days=lookback_days,
            session=session,
        )
    catalog = await list_attack_categories()
    now = datetime.now(UTC)
    matrix = _build_matrix(report.rows, catalog.rows, now)
    return templates.TemplateResponse(
        request,
        "_coverage_matrix.html",
        {
            "categories": matrix["categories"],
            "lookback_days": lookback_days,
            "project_id": project_id,
            "stale_days": STALE_DAYS,
        },
    )


@router.get("/{project_id}/findings")
async def coverage_findings_partial(
    request: Request,
    project_id: UUID,
    principal: Principal = Depends(require_user),
) -> Any:
    """HTMX partial: open findings (severity floor = info, sorted by
    severity desc then age asc so the freshest critical bubbles up)."""
    _ = principal
    async with session_scope() as session:
        report = await list_open_findings(
            project_id=project_id,
            min_severity="info",
            session=session,
        )
    rows = sorted(
        report.rows,
        key=lambda r: (-_SEVERITY_RANK.get(r.severity, 0), r.age_days),
    )
    return templates.TemplateResponse(
        request,
        "_coverage_findings.html",
        {"rows": rows, "project_id": project_id},
    )


@router.get("/{project_id}/regressions")
async def coverage_regressions_partial(
    request: Request,
    project_id: UUID,
    principal: Principal = Depends(require_user),
) -> Any:
    """HTMX partial: findings whose current status is ``regressed``
    inside the last 14 days. The tool surface's R4 caveat
    (no status-transition history yet) is surfaced in the template."""
    _ = principal
    since_days = 14
    async with session_scope() as session:
        report = await list_recent_regressions(
            project_id=project_id,
            since_days=since_days,
            session=session,
        )
    return templates.TemplateResponse(
        request,
        "_coverage_regressions.html",
        {
            "rows": report.rows,
            "since_days": since_days,
            "note": report.note,
            "project_id": project_id,
        },
    )
