"""Regressions list + detail + manual promote/run controls.

Three GET pages and three CSRF-protected POST endpoints:

- ``GET /regressions`` — every RegressionCase with its latest
  ``regression_runs`` verdict, gate-by-gate, plus per-project sweep
  controls.
- ``GET /regressions/{case_id}`` — gate-by-gate detail for the most
  recent run plus a "Run this case now" button.
- ``POST /regressions/promote/{execution_id}`` — manually promote an
  arbitrary attack execution into the regression suite, regardless of
  the Judge verdict. Used by the run-detail drawer's "Promote to
  regression" button so operators can capture interesting attacks even
  when they didn't (yet) breach.
- ``POST /regressions/{case_id}/run`` — fire one regression case
  through the triple-gate runner against the project's current target.
- ``POST /regressions/sweep/{project_id}`` — fire a full sweep over
  all cases for a project. Same code path the deploy webhook hits.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import desc, select

from cats.api.auth import Principal, require_user
from cats.api.templating import templates
from cats.config import settings
from cats.db.engine import session_scope
from cats.db.repositories.audit_repo import write_audit
from cats.db.repositories.regression_repo import (
    get_project_id_for_case,
    get_regression_case,
    latest_run_for_case,
    list_projects_with_cases,
    list_regression_cases,
    promote_attack_execution,
)
from cats.db.schema import findings, projects, regression_runs, regression_sweeps
from cats.logging import get_logger
from cats.security.csrf import require_csrf
from cats.workers.regression_sweep import (
    schedule_single_case_in_background,
    schedule_sweep_in_background,
)

log = get_logger(__name__)

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
    started: str | None = None,
    principal: Principal = Depends(require_user),
) -> Any:
    async with session_scope() as session:
        cases = await list_regression_cases(session, limit=500)
        projects_with_cases = await list_projects_with_cases(session)
        # Any sweep still in flight — drives the banner + auto-reload.
        # A sweep takes ~60s for a 6-case suite, so we expect at most
        # one row here under normal use; we still LIMIT for safety.
        running_rows = (
            await session.execute(
                select(
                    regression_sweeps.c.id,
                    regression_sweeps.c.project_id,
                    regression_sweeps.c.started_at,
                    regression_sweeps.c.num_cases,
                    regression_sweeps.c.triggered_by,
                )
                .where(regression_sweeps.c.status == "running")
                .order_by(desc(regression_sweeps.c.started_at))
                .limit(5)
            )
        ).all()
        running_sweeps = [
            {
                "id": str(r.id),
                "project_id": str(r.project_id),
                "started_at": r.started_at,
                "num_cases": r.num_cases,
                "triggered_by": r.triggered_by,
            }
            for r in running_rows
        ]
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
    # ``started`` is the just-fired sweep id echoed back from the POST
    # redirect. We only flash the toast if that id is actually one of
    # the running sweeps — otherwise the toast lingers after a reload.
    just_started_id = ""
    if started and any(s["id"] == started for s in running_sweeps):
        just_started_id = started
    ctx = _chrome_ctx(principal)
    ctx.update(
        {
            "cases": enriched,
            "tally": tally,
            "projects_with_cases": projects_with_cases,
            "running_sweeps": running_sweeps,
            "just_started_sweep_id": just_started_id,
        }
    )
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
    async with session_scope() as session:
        project_id = await get_project_id_for_case(session, case_id=case_id)
    ctx = _chrome_ctx(principal)
    ctx.update(
        {
            "case": case,
            "latest_run": run,
            "finding": finding,
            "project_id": project_id,
        }
    )
    return templates.TemplateResponse(request, "regression_detail.html", ctx)


# ---------------------------------------------------------------------------
# Mutating routes — promote, run-case, sweep
# ---------------------------------------------------------------------------


@router.post("/promote/{execution_id}", dependencies=[Depends(require_csrf)])
async def promote_execution(
    request: Request,
    execution_id: UUID,
    return_to: str = Form(""),
    principal: Principal = Depends(require_user),
) -> Any:
    """Manually promote an arbitrary attack execution into the regression
    suite — regardless of the Judge's verdict. Backs the per-execution
    "Promote to regression" button in the run-detail drawer.

    Idempotent on the underlying (run, category, signature) so re-clicking
    just returns the existing case. The form posts a ``return_to`` value
    so the browser lands back on the page the operator clicked from
    (run detail, finding detail, etc.).
    """
    async with session_scope() as session:
        outcome = await promote_attack_execution(
            session,
            attack_execution_id=execution_id,
        )
        if outcome is None:
            raise HTTPException(status_code=404, detail="attack execution not found")
        await write_audit(
            session,
            actor=f"user:{principal.email}",
            action="regression.case.promoted_manually",
            target_kind="regression_case",
            target_id=outcome["case_id"],
            payload={
                "attack_execution_id": str(execution_id),
                "finding_id": str(outcome["finding_id"]),
                "finding_created": bool(outcome["finding_created"]),
                "rubric_locked": bool(outcome["rubric_locked"]),
            },
        )
    log.info(
        "regression.case.promoted_manually",
        case_id=str(outcome["case_id"]),
        execution_id=str(execution_id),
        actor=principal.email,
    )
    target = return_to or f"/regressions/{outcome['case_id']}"
    if not target.startswith("/"):
        # Defensive: never honour an absolute or scheme-bearing return_to.
        target = f"/regressions/{outcome['case_id']}"
    return RedirectResponse(url=target, status_code=303)


@router.post("/{case_id}/run", dependencies=[Depends(require_csrf)])
async def run_case_now(
    request: Request,
    case_id: UUID,
    principal: Principal = Depends(require_user),
) -> Any:
    """Fire one RegressionCase through the triple-gate runner. Schedules
    the run in the background — the redirect returns immediately so the
    operator's browser doesn't sit on the LLM tool loop. The detail page
    surfaces the result once the run row lands via ``latest_run_for_case``.
    """
    async with session_scope() as session:
        case = await get_regression_case(session, case_id=case_id)
        if case is None:
            raise HTTPException(status_code=404, detail="regression case not found")
        project_id = await get_project_id_for_case(session, case_id=case_id)
        await write_audit(
            session,
            actor=f"user:{principal.email}",
            action="regression.case.run_manually",
            target_kind="regression_case",
            target_id=case_id,
            payload={"project_id": str(project_id) if project_id else None},
        )
    schedule_single_case_in_background(case_id=case_id, triggered_by="manual_ui")
    log.info(
        "regression.case.run_manually",
        case_id=str(case_id),
        actor=principal.email,
    )
    return RedirectResponse(url=f"/regressions/{case_id}", status_code=303)


@router.post("/sweep/{project_id}", dependencies=[Depends(require_csrf)])
async def sweep_project(
    request: Request,
    project_id: UUID,
    version_tag: str = Form("manual_ui"),
    principal: Principal = Depends(require_user),
) -> Any:
    """Fire a full sweep over every RegressionCase tied to a project.
    Same code path as the deploy webhook. Returns 303 to the
    regressions list so the operator can watch the SSE-driven updates
    swap in as cases finish."""
    async with session_scope() as session:
        row = (
            await session.execute(
                select(projects.c.id, projects.c.allow_run_against).where(
                    projects.c.id == project_id
                )
            )
        ).first()
        if row is None:
            raise HTTPException(status_code=404, detail="project not found")
        if not row.allow_run_against:
            raise HTTPException(
                status_code=403,
                detail="project does not allow attacks to be run against it",
            )
        sweep_id = schedule_sweep_in_background(
            project_id=project_id,
            version_tag=version_tag[:120] or "manual_ui",
            triggered_by="manual_ui",
        )
        await write_audit(
            session,
            actor=f"user:{principal.email}",
            action="regression.sweep.started_manually",
            target_kind="regression_sweep",
            target_id=sweep_id,
            payload={
                "project_id": str(project_id),
                "version_tag": version_tag or "manual_ui",
            },
        )
    log.info(
        "regression.sweep.started_manually",
        sweep_id=str(sweep_id),
        project_id=str(project_id),
        actor=principal.email,
    )
    return RedirectResponse(url=f"/regressions?started={sweep_id}", status_code=303)
