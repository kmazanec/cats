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

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import insert

from cats.db.engine import session_scope
from cats.db.repositories.campaign_repo import (
    create_campaign,
    get_run_with_campaign,
    list_runs_for_campaign,
)
from cats.db.repositories.project_repo import create_project
from cats.db.repositories.run_repo import (
    record_execution,
    record_verdict,
    set_execution_verdict,
    upsert_attack,
)
from cats.db.schema import project_versions, runs
from cats.security.crypto import encrypt

pytestmark = pytest.mark.integration


async def _make_scaffold(
    *,
    started_at: datetime | None = None,
    ended_at: datetime | None = None,
) -> tuple[UUID, UUID, UUID]:
    """Project + project_version + campaign + run. Returns
    ``(campaign_id, run_id, project_version_id)``.

    Optional ``started_at`` / ``ended_at`` let tests pin wall-clock
    timing for the run, used by the elapsed-time assertion."""
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
        # Deliberately seed the denorm columns to 0 — the bug we're
        # regressing was that the route read these directly and showed
        # "0 turns / $0.00" even when executions had real data.
        run_values: dict[str, Any] = {
            "id": run_id,
            "campaign_id": campaign_id,
            "project_version_id": pv_id,
            "status": "completed",
            "attacks_fired": 0,
            "budget_consumed_usd": 0.0,
        }
        if started_at is not None:
            run_values["started_at"] = started_at
        if ended_at is not None:
            run_values["ended_at"] = ended_at
        await session.execute(insert(runs).values(**run_values))
        await session.commit()
    return campaign_id, run_id, pv_id


async def _seed_executions(
    *,
    run_id: UUID,
    project_version_id: UUID,
    rows: list[dict[str, Any]],
) -> list[UUID]:
    """Insert one attacks row + N attack_executions rows for the run.

    Each entry in ``rows`` is ``{tokens_in, tokens_out, usd, role}``
    and may optionally include ``latency_ms`` and ``verdict``. When
    ``verdict`` is set, a ``judge_verdicts`` row is created and linked
    to the execution. Returns the list of execution ids in seed order
    so the caller can assert against them."""
    exec_ids: list[UUID] = []
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
            eid = await record_execution(
                session,
                run_id=run_id,
                attack_id=attack_id,
                project_version_id=project_version_id,
                target_response={"text": "ok"},
                target_status_code=200,
                target_latency_ms=int(r.get("latency_ms", 10)),
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
            exec_ids.append(eid)
            verdict = r.get("verdict")
            if verdict:
                vid = await record_verdict(
                    session,
                    verdict=verdict,
                    is_deterministic=False,
                    rationale="test",
                    evidence={},
                    judge_model="test-judge",
                )
                await set_execution_verdict(session, attack_execution_id=eid, judge_verdict_id=vid)
        await session.commit()
    return exec_ids


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


# ---------------------------------------------------------------------------
# Campaign-detail run table: `list_runs_for_campaign` is the source for
# the Run-status panel. Asserts the new columns surface correctly:
# Judge verdict, average latency, elapsed wall-time, spend derived from
# executions.
# ---------------------------------------------------------------------------


async def test_list_runs_surfaces_judge_avg_elapsed_and_spend(client: Any) -> None:
    """One run with three executions of varying latency, two with a
    final-turn ``fail`` verdict and one with no verdict. Asserts:
      - ``judge_verdict`` reflects the latest execution's verdict.
      - ``avg_target_latency_ms`` is the mean, not the max.
      - ``elapsed_ms`` is ``ended_at - started_at``.
      - ``budget_consumed_usd`` is the sum of ``usd_estimate``.
      - ``attacks_fired`` is the count of executions.
    """
    _ = client
    started = datetime(2026, 5, 14, 16, 46, 50, tzinfo=UTC)
    ended = started + timedelta(seconds=42)
    campaign_id, run_id, pv_id = await _make_scaffold(started_at=started, ended_at=ended)
    # Latencies: 1000ms, 2000ms, 3000ms → avg 2000ms.
    # Spends: $0.01, $0.02, $0.03 → total $0.06.
    # Only the last execution gets a Judge verdict.
    await _seed_executions(
        run_id=run_id,
        project_version_id=pv_id,
        rows=[
            {
                "role": "redteam_injection",
                "tokens_in": 10,
                "tokens_out": 5,
                "usd": 0.01,
                "latency_ms": 1000,
            },
            {
                "role": "redteam_supervisor",
                "tokens_in": 20,
                "tokens_out": 5,
                "usd": 0.02,
                "latency_ms": 2000,
            },
            {
                "role": "redteam_supervisor",
                "tokens_in": 30,
                "tokens_out": 5,
                "usd": 0.03,
                "latency_ms": 3000,
                "verdict": "fail",
            },
        ],
    )

    async with session_scope() as session:
        rows = await list_runs_for_campaign(session, campaign_id=campaign_id)

    assert len(rows) == 1
    r = rows[0]
    assert r["attacks_fired"] == 3
    assert r["budget_consumed_usd"] == pytest.approx(0.06)
    assert r["avg_target_latency_ms"] == 2000, "should be mean, not max"
    assert r["elapsed_ms"] == 42_000, "should be ended_at - started_at in ms"
    assert r["judge_verdict"] == "fail", "should reflect the last execution's verdict"


async def test_list_runs_judge_verdict_picks_latest_when_multiple(client: Any) -> None:
    """If more than one execution has a verdict (shouldn't normally
    happen but the schema allows it), the latest wins — same selection
    rule the run-detail hero banner uses."""
    _ = client
    started = datetime(2026, 5, 14, 17, 0, 0, tzinfo=UTC)
    ended = started + timedelta(seconds=10)
    campaign_id, run_id, pv_id = await _make_scaffold(started_at=started, ended_at=ended)
    await _seed_executions(
        run_id=run_id,
        project_version_id=pv_id,
        rows=[
            {
                "role": "redteam_injection",
                "tokens_in": 1,
                "tokens_out": 1,
                "usd": 0.001,
                "latency_ms": 500,
                "verdict": "fail",
            },
            {
                "role": "redteam_supervisor",
                "tokens_in": 1,
                "tokens_out": 1,
                "usd": 0.001,
                "latency_ms": 500,
                "verdict": "pass",
            },
        ],
    )

    async with session_scope() as session:
        rows = await list_runs_for_campaign(session, campaign_id=campaign_id)

    assert len(rows) == 1
    assert rows[0]["judge_verdict"] == "pass", "latest by created_at wins"


async def test_list_runs_run_with_no_executions_returns_nulls(client: Any) -> None:
    """A run that never produced an execution row (transport error
    before turn 1) shouldn't crash the rollup; the numeric columns
    are 0 and ``judge_verdict`` is None."""
    _ = client
    campaign_id, run_id, _ = await _make_scaffold()
    _ = run_id

    async with session_scope() as session:
        rows = await list_runs_for_campaign(session, campaign_id=campaign_id)

    assert len(rows) == 1
    r = rows[0]
    assert r["attacks_fired"] == 0
    assert r["budget_consumed_usd"] == 0.0
    assert r["avg_target_latency_ms"] is None
    assert r["judge_verdict"] is None
