"""Sweep helper: ``sweep_orphaned_running_runs`` flips every Run still
stuck at ``status='running'`` to ``failed``. Called from the Red Team
worker's startup hook to clean up runs orphaned by a container restart
mid-dispatch (see ``RedTeamWorker.run``)."""

from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import insert, select

from cats.db.engine import session_scope
from cats.db.repositories.project_repo import create_project
from cats.db.repositories.run_repo import sweep_orphaned_running_runs
from cats.db.schema import project_versions, runs
from cats.security.crypto import encrypt

pytestmark = pytest.mark.integration


async def _make_project_version() -> tuple:
    async with session_scope() as session:
        project_id = await create_project(
            session,
            name=f"sweep-test-{uuid4()}",
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
    return project_id, pv_id


async def _make_campaign_with_run(*, status: str) -> tuple:
    from cats.db.repositories.campaign_repo import create_campaign

    project_id, pv_id = await _make_project_version()
    async with session_scope() as session:
        campaign_id, _ = await create_campaign(
            session, project_id=project_id, name=f"sweep-{status}"
        )
        run_id = uuid4()
        await session.execute(
            insert(runs).values(
                id=run_id,
                campaign_id=campaign_id,
                project_version_id=pv_id,
                status=status,
            )
        )
        await session.commit()
    return campaign_id, run_id


async def test_sweep_flips_running_to_failed(client) -> None:
    _ = client  # fixture sets up DB + per-test engine
    _, running_id = await _make_campaign_with_run(status="running")
    _, completed_id = await _make_campaign_with_run(status="completed")
    _, pending_id = await _make_campaign_with_run(status="pending")

    async with session_scope() as session:
        swept = await sweep_orphaned_running_runs(session)
        await session.commit()

    assert swept == [running_id]

    async with session_scope() as session:
        rows = (
            await session.execute(
                select(runs.c.id, runs.c.status, runs.c.ended_at).where(
                    runs.c.id.in_([running_id, completed_id, pending_id])
                )
            )
        ).all()
    by_id = {r.id: r for r in rows}
    assert by_id[running_id].status == "failed"
    assert by_id[running_id].ended_at is not None
    assert by_id[completed_id].status == "completed"
    assert by_id[pending_id].status == "pending"
    assert by_id[pending_id].ended_at is None


async def test_sweep_with_no_running_returns_empty(client) -> None:
    _ = client
    await _make_campaign_with_run(status="completed")

    async with session_scope() as session:
        swept = await sweep_orphaned_running_runs(session)
        await session.commit()
    assert swept == []
