"""Regression: the run-detail page's "Turns fired" and "Spend" metrics
must derive from ``attack_executions`` rather than the denormed
``runs.attacks_fired`` / ``runs.budget_consumed_usd`` columns.

The denorm columns were unreliable: the R3 worker path hard-coded
``attacks_fired=1`` regardless of how many turns ran, and the R10
agent path sometimes wrote ``budget_consumed_usd=0`` even when the
agent had spent real money. ``list_runs_for_campaign`` already
derived both metrics from the execution rows; this test pins the
same contract for ``get_run_with_campaign``, which the run-detail
route uses.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import insert

from cats.db.engine import session_scope
from cats.db.repositories.campaign_repo import create_campaign, get_run_with_campaign
from cats.db.repositories.project_repo import create_project
from cats.db.repositories.run_repo import record_execution, upsert_attack
from cats.db.schema import project_versions, runs
from cats.security.crypto import encrypt

pytestmark = pytest.mark.integration


async def _make_scaffold() -> tuple[UUID, UUID, UUID]:
    """Project + project_version + campaign + run. Returns
    ``(campaign_id, run_id, project_version_id)``."""
    async with session_scope() as session:
        project_id = await create_project(
            session,
            name=f"run-metrics-{uuid4()}",
            base_url="http://example.test",
            env="local",
            allow_run_against=True,
            target_kind="copilot_proxy",
            target_username="u",
            target_password_encrypted=encrypt("p"),
        )
        pv_id = uuid4()
        await session.execute(
            insert(project_versions).values(id=pv_id, project_id=project_id, label="v0")
        )
        campaign_id, _ = await create_campaign(session, project_id=project_id, name="metrics-test")
        run_id = uuid4()
        # Deliberately seed the legacy denorm columns to 0 — the bug
        # we're regressing was that the route read these directly and
        # showed "0 turns / $0.00" even when executions had real data.
        await session.execute(
            insert(runs).values(
                id=run_id,
                campaign_id=campaign_id,
                project_version_id=pv_id,
                status="completed",
                attacks_fired=0,
                budget_consumed_usd=0.0,
            )
        )
        await session.commit()
    return campaign_id, run_id, pv_id


async def _seed_executions(
    *,
    run_id: UUID,
    project_version_id: UUID,
    rows: list[dict[str, Any]],
) -> None:
    """Insert one attacks row + N attack_executions rows for the run.
    Each entry in ``rows`` is ``{tokens_in, tokens_out, usd, role}``."""
    async with session_scope() as session:
        attack_id = await upsert_attack(
            session,
            category="injection",
            title="t",
            description="d",
            payload={"user_message": "x"},
            signature=f"sig-{uuid4()}",
            run_id=run_id,
        )
        for idx, r in enumerate(rows):
            await record_execution(
                session,
                run_id=run_id,
                attack_id=attack_id,
                project_version_id=project_version_id,
                target_response={"text": "ok"},
                target_status_code=200,
                target_latency_ms=10,
                output_filter_verdict="safe",
                output_filter_reason="",
                judge_verdict_id=None,
                model="m",
                agent_role=r["role"],
                tokens_in=r["tokens_in"],
                tokens_out=r["tokens_out"],
                usd_estimate=r["usd"],
                langsmith_trace_id=None,
                seed_idx=idx,
            )
        await session.commit()


async def test_get_run_with_campaign_derives_metrics_from_executions(client: Any) -> None:
    """The denormed ``runs.attacks_fired`` is 0 and
    ``runs.budget_consumed_usd`` is 0, but two execution rows carry
    non-zero tokens + USD. ``get_run_with_campaign`` must derive
    ``attacks_fired=2`` and ``budget_consumed_usd`` = sum of
    ``usd_estimate``, not return the stale denorm values."""
    _ = client  # fixture sets up the DB + per-test engine
    campaign_id, run_id, pv_id = await _make_scaffold()
    await _seed_executions(
        run_id=run_id,
        project_version_id=pv_id,
        rows=[
            {"role": "redteam_injection", "tokens_in": 120, "tokens_out": 40, "usd": 0.0123},
            {"role": "redteam_supervisor", "tokens_in": 50, "tokens_out": 10, "usd": 0.0070},
        ],
    )

    async with session_scope() as session:
        result = await get_run_with_campaign(session, run_id=run_id, campaign_id=campaign_id)

    assert result is not None
    assert result["attacks_fired"] == 2, "should count executions, not read denorm"
    assert result["budget_consumed_usd"] == pytest.approx(0.0193), (
        "should sum usd_estimate across executions, not read denorm"
    )


async def test_get_run_with_campaign_handles_run_with_no_executions(client: Any) -> None:
    """A run that completed without any execution rows (transport
    error before turn 1) must return 0/0 — no crash, no None."""
    _ = client
    campaign_id, run_id, _ = await _make_scaffold()
    # No executions seeded.

    async with session_scope() as session:
        result = await get_run_with_campaign(session, run_id=run_id, campaign_id=campaign_id)

    assert result is not None
    assert result["attacks_fired"] == 0
    assert result["budget_consumed_usd"] == 0.0
