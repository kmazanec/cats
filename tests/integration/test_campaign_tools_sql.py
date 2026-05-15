"""Regression coverage for the Documentation Agent's data tools — the
SQL they fire has to actually run against Postgres, not just type-check.

Before this test, ``_per_run_rows`` built a correlated subquery without
LATERAL; Postgres rejected the join with ``UndefinedTableError`` and
aborted the report transaction, leaving every campaign report stuck at
``status='failed'`` with an empty transcript. Unit tests passed because
they stub the data tools out wholesale. This test runs them for real."""

from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import insert

from cats.agents.documentation import campaign_tools as ct
from cats.db.engine import session_scope
from cats.db.repositories.campaign_repo import create_campaign
from cats.db.repositories.project_repo import create_project
from cats.db.schema import attack_executions, attacks, project_versions, runs
from cats.security.crypto import encrypt

pytestmark = pytest.mark.integration


async def _make_campaign() -> tuple:
    async with session_scope() as session:
        project_id = await create_project(
            session,
            name=f"camptools-{uuid4()}",
            base_url="http://example.test",
            env="local",
            allow_run_against=True,
            target_kind="copilot_proxy",
            target_username="u",
            target_password_encrypted=encrypt("p"),
        )
        pv_id = uuid4()
        await session.execute(
            insert(project_versions).values(id=pv_id, project_id=project_id, label="x")
        )
        campaign_id, _ = await create_campaign(session, project_id=project_id, name="camptools")
        await session.commit()
    return campaign_id, pv_id


async def _add_run(*, campaign_id, pv_id, status: str, executions: list[dict]) -> None:
    run_id = uuid4()
    async with session_scope() as session:
        await session.execute(
            insert(runs).values(
                id=run_id,
                campaign_id=campaign_id,
                project_version_id=pv_id,
                status=status,
            )
        )
        for ex in executions:
            attack_id = uuid4()
            await session.execute(
                insert(attacks).values(
                    id=attack_id,
                    category=ex["category"],
                    title=ex["title"],
                    payload={"technique": ex["technique"]},
                    signature=f"sig-{attack_id}",
                    created_in_run_id=run_id,
                )
            )
            await session.execute(
                insert(attack_executions).values(
                    id=uuid4(),
                    run_id=run_id,
                    attack_id=attack_id,
                    project_version_id=pv_id,
                    seed_idx=ex["seed_idx"],
                    usd_estimate=ex.get("usd", 0.001),
                )
            )
        await session.commit()


async def test_per_run_rows_executes_against_postgres(client) -> None:
    """The query plan in _per_run_rows must be valid Postgres SQL.
    Regression for the correlated-subquery-without-LATERAL bug that
    aborted the entire report transaction."""
    _ = client
    campaign_id, pv_id = await _make_campaign()
    await _add_run(
        campaign_id=campaign_id,
        pv_id=pv_id,
        status="completed",
        executions=[
            {"category": "xss", "technique": "script_tag", "title": "T1", "seed_idx": 0},
            {"category": "xss", "technique": "script_tag", "title": "T2", "seed_idx": 1},
        ],
    )
    await _add_run(
        campaign_id=campaign_id,
        pv_id=pv_id,
        status="failed",
        executions=[],
    )

    async with session_scope() as session:
        rows = await ct._per_run_rows(session, campaign_id=campaign_id)

    assert len(rows) == 2
    completed = next(r for r in rows if r["run_status"] == "completed")
    # Scenario label comes from the first (lowest-seed_idx) execution.
    assert completed["category"] == "xss"
    assert completed["technique"] == "script_tag"
    assert completed["attack_title"] == "T1"
    # Run with no executions falls into the unjudged/run_failed bucket
    # instead of erroring or returning None category.
    failed = next(r for r in rows if r["run_status"] == "failed")
    assert failed["verdict"] == "run_failed"
    assert failed["category"] is None


async def test_data_run_outcomes_and_summary_succeed(client) -> None:
    """End-to-end: the two top-level tools the writer always calls."""
    _ = client
    campaign_id, pv_id = await _make_campaign()
    await _add_run(
        campaign_id=campaign_id,
        pv_id=pv_id,
        status="completed",
        executions=[
            {"category": "exfil", "technique": "indirect", "title": "T", "seed_idx": 0},
        ],
    )

    async with session_scope() as session:
        outcomes = await ct.data_run_outcomes(session, campaign_id=campaign_id)
        summary = await ct.data_campaign_summary(session, campaign_id=campaign_id)

    assert outcomes["count"] == 1
    assert summary["totals"]["runs"] == 1
    assert summary["totals"]["attacks_fired"] >= 0
