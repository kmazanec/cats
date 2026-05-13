"""``GET /campaigns/<id>/timeline`` returns the campaign's historical
events as a JSON list in the same envelope shape SSE emits. The
campaign-detail page fetches this on load to backfill the live event
log so it survives a page reload."""

from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import insert

from cats.db.engine import session_scope
from cats.db.repositories.campaign_repo import create_campaign
from cats.db.repositories.project_repo import create_project
from cats.db.repositories.run_repo import _utcnow
from cats.db.schema import (
    attack_executions,
    attacks,
    campaign_plans,
    findings,
    judge_verdicts,
    project_versions,
    runs,
)
from cats.security.crypto import encrypt
from tests.integration.conftest import csrf_post

pytestmark = pytest.mark.integration


async def _seed_campaign() -> tuple:
    async with session_scope() as session:
        project_id = await create_project(
            session,
            name=f"timeline-{uuid4()}",
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
        await session.commit()

        campaign_id, _ = await create_campaign(session, project_id=project_id, name="timeline-test")
        # A plan row: proposed + approved.
        plan_id = uuid4()
        await session.execute(
            insert(campaign_plans).values(
                id=plan_id,
                campaign_id=campaign_id,
                status="approved",
                proposed_plan={"attempts": [{"category": "injection"}]},
                rationale="r",
                approved_at=_utcnow(),
            )
        )
        # A run that completed, with one attack execution + judge verdict.
        run_id = uuid4()
        await session.execute(
            insert(runs).values(
                id=run_id,
                campaign_id=campaign_id,
                project_version_id=pv_id,
                status="completed",
                ended_at=_utcnow(),
                attacks_fired=1,
                budget_consumed_usd=0.01,
            )
        )
        attack_id = uuid4()
        await session.execute(
            insert(attacks).values(
                id=attack_id,
                created_in_run_id=run_id,
                category="injection",
                signature="sig-1",
                payload={"category": "injection", "technique": "ignore_previous"},
                title="t",
            )
        )
        verdict_id = uuid4()
        await session.execute(
            insert(judge_verdicts).values(
                id=verdict_id,
                verdict="pass",
                rationale="canary echoed",
            )
        )
        exec_id = uuid4()
        await session.execute(
            insert(attack_executions).values(
                id=exec_id,
                run_id=run_id,
                attack_id=attack_id,
                project_version_id=pv_id,
                target_status_code=200,
                target_latency_ms=42,
                output_filter_verdict="safe",
                judge_verdict_id=verdict_id,
            )
        )
        finding_id = uuid4()
        await session.execute(
            insert(findings).values(
                id=finding_id,
                run_id=run_id,
                category="injection",
                signature="sig-1",
                severity="high",
                title="canary echoed",
            )
        )
        await session.commit()
    return campaign_id, run_id


async def test_timeline_returns_history_oldest_first(client) -> None:
    campaign_id, run_id = await _seed_campaign()
    await csrf_post(
        client,
        "/login",
        data={"email": "admin@cats.test", "password": "admin-password-1234"},
    )
    r = await client.get(f"/campaigns/{campaign_id}/timeline")
    assert r.status_code == 200
    events = r.json()
    assert isinstance(events, list) and len(events) >= 5

    kinds = [e["kind"] for e in events]
    assert "plan_proposed" in kinds
    assert "plan_approved" in kinds
    assert "attack_executed" in kinds
    assert "judge_verdict_rendered" in kinds
    assert "run_completed" in kinds
    assert "finding_promoted" in kinds

    # Oldest-first ordering: the timestamps are monotonically
    # non-decreasing across the list.
    ats = [e["at"] for e in events]
    assert ats == sorted(ats)

    # Attack-executed payload carries the status_code + latency_ms +
    # category/technique that the frontend renderer needs.
    attack = next(e for e in events if e["kind"] == "attack_executed")
    assert attack["run_id"] == str(run_id)
    assert attack["payload"]["status_code"] == 200
    assert attack["payload"]["latency_ms"] == 42
    assert attack["payload"]["category"] == "injection"
    assert attack["payload"]["technique"] == "ignore_previous"


async def test_timeline_404_for_unknown_campaign(client) -> None:
    await csrf_post(
        client,
        "/login",
        data={"email": "admin@cats.test", "password": "admin-password-1234"},
    )
    r = await client.get(f"/campaigns/{uuid4()}/timeline")
    assert r.status_code == 404
