"""``cats regression`` subcommands.

- ``capture-exemplar <finding-id>`` — run the finding's canonical attack
  against the project's current target and store the response as the
  refusal exemplar (plus its embedding) for the gate-3 fingerprint
  check.

- ``run-case <case-id>`` — re-run a single RegressionCase through the
  triple gate. Useful for hand-driven verification before wiring the
  webhook into a production CI.

- ``sweep <project-id>`` — fire all RegressionCases for a project
  through the runner sequentially. Same code path the deploy webhook
  exercises; the CLI is the manual fallback.
"""

from __future__ import annotations

import asyncio
from typing import Annotated
from uuid import UUID

import typer

from cats.db.engine import session_scope

regression_app = typer.Typer(no_args_is_help=True, help="Regression-verification harness (R8).")


@regression_app.command("capture-exemplar")
def capture_exemplar(
    finding_id: Annotated[
        str,
        typer.Argument(help="UUID of the Finding whose RegressionCase to update."),
    ],
) -> None:
    """Fire the canonical attack against the current target, store the
    response text as the refusal exemplar, and compute + persist its
    embedding. After a fix lands, run this once to give gate-3 a
    safe-refusal anchor to compare future responses against."""
    asyncio.run(_capture_exemplar(UUID(finding_id)))


@regression_app.command("run-case")
def run_case(
    case_id: Annotated[str, typer.Argument(help="UUID of the RegressionCase to re-run.")],
) -> None:
    """Run one RegressionCase through the triple gate and print the
    per-gate verdict + overall status."""
    asyncio.run(_run_case(UUID(case_id)))


@regression_app.command("sweep")
def sweep(
    project_id: Annotated[
        str,
        typer.Argument(help="UUID of the Project whose RegressionCases to sweep."),
    ],
    version_tag: Annotated[
        str,
        typer.Option(
            "--version-tag",
            help="Free-form Co-Pilot version identifier (commit SHA, image tag).",
        ),
    ] = "manual",
) -> None:
    """Run every RegressionCase tied to a project. Persists a
    regression_sweeps row + per-case regression_runs rows."""
    asyncio.run(_run_sweep(UUID(project_id), version_tag=version_tag))


# ---------------------------------------------------------------------------
# Implementations
# ---------------------------------------------------------------------------


async def _capture_exemplar(finding_id: UUID) -> None:
    from sqlalchemy import select

    from cats.db.repositories.regression_repo import (
        get_regression_case,
        update_exemplar,
    )
    from cats.db.schema import regression_cases as rc_t
    from cats.llm.embeddings import get_embedding_client
    from cats.regression.runner import (
        _build_target_client,
        _envelope_from_attack,
        _load_case_context,
    )

    async with session_scope() as session:
        # Find the RegressionCase whose source_finding matches.
        row = (
            await session.execute(select(rc_t.c.id).where(rc_t.c.source_finding_id == finding_id))
        ).first()
        if row is None:
            typer.echo(
                f"no regression_case found for finding {finding_id}; is the finding promoted?",
                err=True,
            )
            raise typer.Exit(code=2)
        case_id = UUID(str(row.id))
        case = await get_regression_case(session, case_id=case_id)
        assert case is not None
        ctx = await _load_case_context(session, case_id=case_id)
        if ctx is None:
            typer.echo(
                "regression_case context could not be loaded (missing attack or project row)",
                err=True,
            )
            raise typer.Exit(code=2)
        attack = ctx["attack"]
        project = ctx["project"]
        target = await _build_target_client(project)
        envelope = _envelope_from_attack(attack["payload"] or {})

        typer.echo(f"firing canonical attack for case {case_id} ...")
        result = await target.attack(envelope)
        response_text = result.text or ""
        typer.echo(f"captured response ({len(response_text)} chars, status={result.status_code})")

        embed = get_embedding_client()
        try:
            vector = await embed.embed(response_text)
        except Exception as exc:
            typer.echo(f"embedding call failed: {exc!r}", err=True)
            raise typer.Exit(code=3) from exc

        await update_exemplar(
            session,
            case_id=case_id,
            text_=response_text[:32000],
            embedding=vector if vector else None,
        )
        typer.echo(
            f"stored exemplar for case {case_id} (embedding dim={len(vector) if vector else 0})"
        )


async def _run_case(case_id: UUID) -> None:
    from cats.regression.runner import run_regression_case

    async with session_scope() as session:
        verdict = await run_regression_case(session, case_id=case_id, triggered_by="manual_cli")
    typer.echo(f"case {case_id} → {verdict.status}")
    typer.echo(
        f"  gate 1 (deterministic): {verdict.gate_deterministic}\n"
        f"  gate 2 (judge locked):  {verdict.gate_judge}\n"
        f"  gate 3 (fingerprint):   {verdict.gate_fingerprint}"
    )
    typer.echo(f"reason: {verdict.reason}")


async def _run_sweep(project_id: UUID, *, version_tag: str) -> None:
    from cats.workers.regression_sweep import run_sweep

    async with session_scope() as session:
        sweep_id = await run_sweep(
            session,
            project_id=project_id,
            version_tag=version_tag,
            triggered_by="manual_cli",
        )
    typer.echo(f"sweep {sweep_id} completed")
