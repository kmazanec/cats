"""Integration tests for the campaign-report HTTP surface.

The POST route enqueues a ``CampaignReportRequested`` envelope on the
bus and redirects immediately — it does NOT run the LLM tool loop in
the request. The GET ``/status`` endpoint is the JSON probe the page's
polling fallback hits when SSE drops. Both must work without a worker
process running (this test exercises the bus + route layer only).
"""

from __future__ import annotations

import time
from uuid import uuid4

import pytest
from sqlalchemy import insert, text

from cats.db.engine import session_scope
from cats.db.repositories.campaign_repo import create_campaign
from cats.db.repositories.project_repo import create_project
from cats.db.schema import project_versions
from cats.messaging.envelopes import MessageKind
from cats.security.crypto import encrypt
from tests.integration.conftest import csrf_post

pytestmark = pytest.mark.integration


async def _seed_campaign() -> str:
    async with session_scope() as session:
        project_id = await create_project(
            session,
            name=f"report-route-{uuid4()}",
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
        campaign_id, _ = await create_campaign(session, project_id=project_id, name="report-route")
        return str(campaign_id)


async def _login_admin(client) -> None:  # type: ignore[no-untyped-def]
    await csrf_post(
        client,
        "/login",
        data={"email": "admin@cats.test", "password": "admin-password-1234"},
    )


async def test_post_report_enqueues_message_and_redirects_quickly(client) -> None:  # type: ignore[no-untyped-def]
    """The manual (re)generate route MUST be async — it enqueues a
    bus message and returns 303 in well under a second, never running
    the LLM tool loop inline. If a regression makes the route
    synchronous again, this test catches the latency immediately."""
    campaign_id = await _seed_campaign()
    await _login_admin(client)

    started = time.perf_counter()
    resp = await csrf_post(client, f"/campaigns/{campaign_id}/report", data={})
    elapsed_ms = (time.perf_counter() - started) * 1000

    assert resp.status_code == 303
    assert resp.headers["location"].endswith(f"/campaigns/{campaign_id}/report")
    # The whole round trip should complete in <2s — no LLM call ever
    # happens in this request. Generous bound for CI noise; a
    # regression that runs the writer inline would blow past 5s+.
    assert elapsed_ms < 2000, (
        f"POST /report returned in {elapsed_ms:.0f}ms — synchronous regression?"
    )

    # Bus row should exist with the right kind + idempotency key shape.
    async with session_scope() as session:
        row = (
            await session.execute(
                text(
                    """
                    SELECT kind, to_agent, from_agent, idempotency_key
                    FROM agent_messages
                    WHERE campaign_id = :cid
                      AND kind = :kind
                    """
                ),
                {"cid": campaign_id, "kind": MessageKind.CAMPAIGN_REPORT_REQUESTED.value},
            )
        ).first()
    assert row is not None
    assert row.to_agent == "documentation"
    assert row.from_agent == "operator"
    assert row.idempotency_key.startswith(f"documentation:campaign_report:{campaign_id}:manual:")

    # The pending row was reserved up front so the page shows progress
    # immediately on the redirect.
    async with session_scope() as session:
        status_row = (
            await session.execute(
                text("SELECT status FROM campaign_reports WHERE campaign_id = :cid"),
                {"cid": campaign_id},
            )
        ).first()
    assert status_row is not None
    assert status_row.status == "generating"


async def test_report_status_endpoint_returns_none_before_any_request(client) -> None:  # type: ignore[no-untyped-def]
    """The JSON status probe handles the pre-row case so the polling
    fallback can start immediately on a freshly-loaded page."""
    campaign_id = await _seed_campaign()
    await _login_admin(client)

    resp = await client.get(f"/campaigns/{campaign_id}/report/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data == {"status": "none", "artifacts": 0, "generated_at": None}


async def test_report_status_endpoint_returns_generating_after_post(client) -> None:  # type: ignore[no-untyped-def]
    """After the operator hits POST, status flips to 'generating' even
    before any worker has picked the message up — the route reserves
    the row so the UI's banner shows immediately."""
    campaign_id = await _seed_campaign()
    await _login_admin(client)
    await csrf_post(client, f"/campaigns/{campaign_id}/report", data={})

    resp = await client.get(f"/campaigns/{campaign_id}/report/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "generating"


async def test_post_report_404_for_unknown_campaign(client) -> None:  # type: ignore[no-untyped-def]
    await _login_admin(client)
    resp = await csrf_post(client, f"/campaigns/{uuid4()}/report", data={})
    assert resp.status_code == 404
