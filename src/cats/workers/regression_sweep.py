"""R8 regression sweep worker.

Iterates a project's RegressionCases through
:func:`cats.regression.runner.run_regression_case`, rolling up the
per-case verdicts into a parent ``regression_sweeps`` row. Catches
per-case exceptions so one pathological case can't fail the whole
sweep — failing cases produce a ``regression_runs`` row with
``status='error'`` and the sweep moves on.

Triggered three ways:

- The deploy webhook (``POST /webhooks/deploy``) enqueues a sweep on
  every authenticated CI signal.
- The ``cats regression sweep`` CLI for a hand-driven verification.
- Future: a scheduler (out of scope for R8).

Sweeps are linear — one case at a time — because the §6.4 gates are
LLM-bound and we don't want to surprise an operator with N parallel
target hits. Switching to bounded concurrency is a small follow-up
once we see real sweep volumes.
"""

from __future__ import annotations

import contextlib
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy.ext.asyncio import AsyncSession

from cats.db.engine import session_scope
from cats.db.repositories.audit_repo import write_audit
from cats.db.repositories.regression_repo import (
    create_sweep,
    finalize_sweep,
    list_regression_cases,
    record_run,
)
from cats.graph.events import publish
from cats.logging import get_logger
from cats.regression.runner import run_regression_case

log = get_logger(__name__)

# Tracks fire-and-forget sweep tasks so the asyncio loop doesn't garbage
# collect them mid-run (RUF006). The webhook handler returns 202 with a
# sweep id and immediately drops the awaitable; without a strong reference
# the loop is free to discard the coroutine. Tasks self-evict on completion.
_BACKGROUND_SWEEPS: set[Any] = set()


async def run_sweep(
    session: AsyncSession,
    *,
    project_id: UUID,
    version_tag: str = "",
    triggered_by: str = "manual_cli",
    sweep_id: UUID | None = None,
) -> UUID:
    """Synchronous sweep — caller awaits to completion. Returns the
    sweep id so the caller can deep-link to the result.

    ``sweep_id`` is optional. When provided, the sweep row uses that
    UUID (so a caller that pre-allocated an id for an HTTP response
    can look the row up later). Otherwise ``create_sweep`` mints one.

    Each per-case run lands in its own session via :func:`session_scope`
    so a per-case crash doesn't poison the outer transaction (the sweep
    row + audit log must persist even when individual runs error).
    """
    sweep_id = await create_sweep(
        session,
        project_id=project_id,
        version_tag=version_tag,
        triggered_by=triggered_by,
        sweep_id=sweep_id,
    )
    await write_audit(
        session,
        actor="cats.platform.regression",
        action="regression.sweep.started",
        target_kind="regression_sweep",
        target_id=sweep_id,
        payload={
            "project_id": str(project_id),
            "version_tag": version_tag,
            "triggered_by": triggered_by,
        },
    )
    await session.commit()

    await publish(
        kind="regression_sweep_started",
        campaign_id=None,
        run_id=None,
        payload={
            "sweep_id": str(sweep_id),
            "project_id": str(project_id),
            "version_tag": version_tag,
        },
    )

    # Discover cases in a fresh session so the truncate-list in tests
    # behaves predictably across the asynchronous boundary.
    async with session_scope() as discover_session:
        cases = await list_regression_cases(discover_session, project_id=project_id, limit=1000)

    counts = {
        "fixed": 0,
        "regressed": 0,
        "needs_review": 0,
        "error": 0,
    }
    for case in cases:
        case_id = case["id"]
        case_status: str
        try:
            async with session_scope() as run_session:
                verdict = await run_regression_case(
                    run_session,
                    case_id=case_id,
                    sweep_id=sweep_id,
                    triggered_by=triggered_by,
                )
            case_status = verdict.status
        except Exception as exc:
            log.warning(
                "regression.sweep.case_failed",
                case_id=str(case_id),
                error=repr(exc),
            )
            # Record an error row so the UI shows the case as attempted.
            async with session_scope() as err_session:
                await record_run(
                    err_session,
                    regression_case_id=case_id,
                    sweep_id=sweep_id,
                    status="error",
                    gate_deterministic=None,
                    gate_judge=None,
                    gate_fingerprint=None,
                    reason=f"sweep raised: {exc!r}",
                    response_text="",
                    triggered_by=triggered_by,
                )
            case_status = "error"

        if case_status == "fixed_held":
            counts["fixed"] += 1
        elif case_status == "regressed":
            counts["regressed"] += 1
        elif case_status == "needs_review":
            counts["needs_review"] += 1
        else:
            counts["error"] += 1

        # Best-effort live update so the UI can swap the case's row.
        with contextlib.suppress(Exception):
            await publish(
                kind="regression_case_finished",
                campaign_id=None,
                run_id=None,
                payload={
                    "sweep_id": str(sweep_id),
                    "case_id": str(case_id),
                    "status": case_status,
                },
            )

    async with session_scope() as final_session:
        await finalize_sweep(
            final_session,
            sweep_id=sweep_id,
            num_cases=len(cases),
            num_fixed=counts["fixed"],
            num_regressed=counts["regressed"],
            num_needs_review=counts["needs_review"],
            num_errored=counts["error"],
            status="completed",
        )
        await write_audit(
            final_session,
            actor="cats.platform.regression",
            action="regression.sweep.completed",
            target_kind="regression_sweep",
            target_id=sweep_id,
            payload={
                "project_id": str(project_id),
                "num_cases": len(cases),
                **counts,
            },
        )

    await publish(
        kind="regression_sweep_finished",
        campaign_id=None,
        run_id=None,
        payload={
            "sweep_id": str(sweep_id),
            "num_cases": len(cases),
            "num_fixed": counts["fixed"],
            "num_regressed": counts["regressed"],
            "num_needs_review": counts["needs_review"],
        },
    )
    return sweep_id


def schedule_single_case_in_background(
    *,
    case_id: UUID,
    triggered_by: str = "manual_ui",
) -> None:
    """Fire-and-forget a single RegressionCase through the triple-gate
    runner from a route handler. Backs the per-case "Run now" button on
    ``/regressions/{case_id}``. The case runs against the project's
    current target without a parent sweep row, so ``latest_run_for_case``
    surfaces the new verdict on the detail page.

    Same loop-keepalive pattern as ``schedule_sweep_in_background``: the
    task is held in ``_BACKGROUND_SWEEPS`` so the loop doesn't GC the
    coroutine before it finishes."""
    import asyncio

    from cats.regression.runner import run_regression_case

    async def _go() -> None:
        async with session_scope() as session:
            await run_regression_case(
                session,
                case_id=case_id,
                sweep_id=None,
                triggered_by=triggered_by,
            )

    task = asyncio.create_task(_go(), name=f"regression-case-{case_id}")
    _BACKGROUND_SWEEPS.add(task)
    task.add_done_callback(_BACKGROUND_SWEEPS.discard)


def schedule_sweep_in_background(
    *,
    project_id: UUID,
    version_tag: str = "",
    triggered_by: str = "deploy_webhook",
) -> UUID:
    """Fire-and-forget. Pre-allocates a sweep id so the webhook can
    echo it in the 200 response, then schedules the actual sweep as
    an asyncio task that creates the row with the same id. The
    returned id IS the eventual ``regression_sweeps.id`` so the caller
    can look the row up via ``GET /regressions``.

    NOTE: this is good enough for the R8 webhook because the FastAPI
    process keeps long-lived event-loop tasks alive. Once a separate
    sweep worker process exists (post-R8), the webhook will enqueue an
    AgentMessage instead and this helper goes away.
    """
    import asyncio

    sweep_id = uuid4()

    async def _go() -> None:
        async with session_scope() as session:
            await run_sweep(
                session,
                project_id=project_id,
                version_tag=version_tag,
                triggered_by=triggered_by,
                sweep_id=sweep_id,
            )

    task = asyncio.create_task(_go(), name=f"regression-sweep-{project_id}")
    _BACKGROUND_SWEEPS.add(task)
    task.add_done_callback(_BACKGROUND_SWEEPS.discard)
    return sweep_id
