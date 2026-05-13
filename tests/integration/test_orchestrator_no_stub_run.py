"""When ``CampaignRequested`` arrives without a ``campaign_id`` (the
``/plan/retry`` path, webhook + CLI triggers), the orchestrator
materializes a fresh ``campaigns`` row but NOT a placeholder ``runs``
row — the Red Team worker creates real runs as it walks the approved
plan. Pre-creating a stub run leaves it at ``status='pending'``
forever when planning fails, which is what shows up as ghost rows on
the campaigns list."""

from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import func, insert, select

from cats.db.engine import session_scope
from cats.db.repositories.project_repo import create_project
from cats.db.schema import project_versions, runs
from cats.messaging import CampaignRequestedPayload
from cats.security.crypto import encrypt
from cats.workers.orchestrator import OrchestratorWorker

pytestmark = pytest.mark.integration


async def test_ensure_campaign_creates_no_stub_run(client) -> None:
    _ = client
    async with session_scope() as session:
        project_id = await create_project(
            session,
            name=f"no-stub-run-{uuid4()}",
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

    worker = OrchestratorWorker()
    payload = CampaignRequestedPayload(
        project_id=project_id,
        project_version_id=pv_id,
        budget_usd=1.0,
        name="retry · whatever",
    )
    async with session_scope() as session:
        campaign_id = await worker._ensure_campaign_for_request(session, payload)
        await session.commit()

    async with session_scope() as session:
        run_count = (
            await session.execute(
                select(func.count()).select_from(runs).where(runs.c.campaign_id == campaign_id)
            )
        ).scalar_one()
    assert run_count == 0, (
        "orchestrator must not pre-create a stub run — the Red Team worker "
        "materializes real runs from the approved plan; a stub left here would "
        "sit at pending forever if planning fails"
    )
