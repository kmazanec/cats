"""R8 regressions list + detail.

Two GET-only pages:

- ``GET /regressions`` — every RegressionCase with its latest
  ``regression_runs`` verdict, gate-by-gate. No filtering for R8;
  expected volumes (one row per confirmed finding) make this fine.
- ``GET /regressions/{case_id}`` — gate-by-gate detail for the most
  recent run plus the source finding metadata.

No POST routes — the only way to fire a regression sweep is the deploy
webhook or the CLI. A future UI button would need a CSRF-protected
form, which we deliberately omit for R8 to keep the surface tight.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import desc, select

from cats.api.auth import Principal, require_user
from cats.api.templating import templates
from cats.config import settings
from cats.db.engine import session_scope
from cats.db.repositories.regression_repo import (
    get_regression_case,
    latest_run_for_case,
    list_regression_cases,
)
from cats.db.schema import findings, regression_runs

router = APIRouter()


def _chrome_ctx(principal: Principal) -> dict[str, Any]:
    return {
        "active": "regressions",
        "principal": principal,
        "env_tag": settings.default_target_env,
        "build_tag": settings.build_sha,
        "build_pipeline_url": settings.gitlab_pipeline_url,
        "now_utc": "",
        "db_status": "—",
        "redis_status": "—",
        "openrouter_status": "—",
        "langsmith_url_base": settings.langsmith_url_base.rstrip("/"),
    }


async def _enrich_with_latest_run(
    cases: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if not cases:
        return cases
    case_ids = [c["id"] for c in cases]
    async with session_scope() as session:
        # Pull the most recent run per case via a row_number-style filter.
        # Volumes are low; a per-row subquery is fine and avoids a window
        # function the SQLAlchemy core surface doesn't model as cleanly.
        rows = (
            await session.execute(
                select(
                    regression_runs.c.regression_case_id,
                    regression_runs.c.status,
                    regression_runs.c.gate_deterministic,
                    regression_runs.c.gate_judge,
                    regression_runs.c.gate_fingerprint,
                    regression_runs.c.started_at,
                )
                .where(regression_runs.c.regression_case_id.in_(case_ids))
                .order_by(desc(regression_runs.c.started_at))
            )
        ).all()
        # Walk in started_at-desc order; first hit per case is the latest.
        latest: dict[UUID, dict[str, Any]] = {}
        for r in rows:
            cid = UUID(str(r.regression_case_id))
            if cid in latest:
                continue
            latest[cid] = {
                "status": r.status,
                "gate_deterministic": r.gate_deterministic,
                "gate_judge": r.gate_judge,
                "gate_fingerprint": r.gate_fingerprint,
                "started_at": r.started_at,
            }

        finding_rows = (
            await session.execute(
                select(
                    findings.c.id,
                    findings.c.title,
                    findings.c.category,
                    findings.c.severity,
                    findings.c.status,
                ).where(findings.c.id.in_([c["source_finding_id"] for c in cases]))
            )
        ).all()
        finding_lookup = {UUID(str(r.id)): dict(r._mapping) for r in finding_rows}

    enriched: list[dict[str, Any]] = []
    for c in cases:
        f = finding_lookup.get(c["source_finding_id"], {})
        run = latest.get(c["id"])
        enriched.append({**c, "finding": f, "latest_run": run})
    return enriched


@router.get("")
async def list_regressions_page(
    request: Request,
    principal: Principal = Depends(require_user),
) -> Any:
    async with session_scope() as session:
        cases = await list_regression_cases(session, limit=500)
    enriched = await _enrich_with_latest_run(cases)
    tally = {"fixed_held": 0, "regressed": 0, "needs_review": 0, "never_run": 0}
    for c in enriched:
        run = c.get("latest_run")
        if not run:
            tally["never_run"] += 1
        else:
            status = run["status"]
            if status in tally:
                tally[status] += 1
            else:
                tally["never_run"] += 1
    ctx = _chrome_ctx(principal)
    ctx.update({"cases": enriched, "tally": tally})
    return templates.TemplateResponse(request, "regressions_list.html", ctx)


@router.get("/{case_id}")
async def regression_detail(
    request: Request,
    case_id: UUID,
    principal: Principal = Depends(require_user),
) -> Any:
    async with session_scope() as session:
        case = await get_regression_case(session, case_id=case_id)
        if case is None:
            raise HTTPException(status_code=404, detail="regression case not found")
        run = await latest_run_for_case(session, case_id=case_id)
        finding_row = (
            await session.execute(
                select(
                    findings.c.id,
                    findings.c.title,
                    findings.c.category,
                    findings.c.severity,
                    findings.c.status,
                    findings.c.summary,
                ).where(findings.c.id == case["source_finding_id"])
            )
        ).first()
    finding = dict(finding_row._mapping) if finding_row else {}
    ctx = _chrome_ctx(principal)
    ctx.update({"case": case, "latest_run": run, "finding": finding})
    return templates.TemplateResponse(request, "regression_detail.html", ctx)
