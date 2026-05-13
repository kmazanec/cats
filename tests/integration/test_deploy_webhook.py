"""R8 — deploy webhook auth + audit behavior.

Covers the three states the webhook can be in:

1. ``deploy_webhook_secret`` empty → 503 + audit entry (platform owner
   has not opted in).
2. Secret configured + missing/invalid signature → 401 + audit entry.
3. Secret configured + valid HMAC over the raw body → 200 + audit
   entry naming the project.

The sweep itself is exercised end-to-end in
``test_regression_sweep_e2e.py``; this test only confirms the auth
gate.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import text

from cats.config import set_settings_for_test
from cats.db.engine import session_scope


def _sign(body: bytes, secret: str) -> str:
    return "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


async def _audit_count(action: str) -> int:
    async with session_scope() as session:
        row = (
            await session.execute(
                text("SELECT count(*) FROM audit_log WHERE action = :a"),
                {"a": action},
            )
        ).scalar_one()
    return int(row)


@pytest.mark.asyncio
async def test_webhook_without_secret_returns_503(client: AsyncClient) -> None:
    set_settings_for_test(deploy_webhook_secret="")
    resp = await client.post(
        "/webhooks/deploy",
        content=b'{"project_id": "00000000-0000-0000-0000-000000000000"}',
        headers={"X-CATS-Signature": "sha256=anything"},
    )
    assert resp.status_code == 503
    assert await _audit_count("regression.webhook.unconfigured") >= 1


@pytest.mark.asyncio
async def test_webhook_with_bad_signature_returns_401(client: AsyncClient) -> None:
    set_settings_for_test(deploy_webhook_secret="test-secret-r8")
    try:
        resp = await client.post(
            "/webhooks/deploy",
            content=b'{"project_id": "00000000-0000-0000-0000-000000000000"}',
            headers={"X-CATS-Signature": "sha256=deadbeef"},
        )
        assert resp.status_code == 401
        assert await _audit_count("regression.webhook.rejected") >= 1

        # Missing header is also rejected.
        resp2 = await client.post(
            "/webhooks/deploy",
            content=b'{"project_id": "00000000-0000-0000-0000-000000000000"}',
        )
        assert resp2.status_code == 401
    finally:
        set_settings_for_test(deploy_webhook_secret="")


@pytest.mark.asyncio
async def test_webhook_with_valid_signature_queues_sweep(client: AsyncClient) -> None:
    from cats.db.repositories.project_repo import create_project
    from cats.security.crypto import encrypt

    set_settings_for_test(deploy_webhook_secret="test-secret-r8")
    try:
        async with session_scope() as session:
            project_id = await create_project(
                session,
                name="Webhook Target",
                base_url="http://fake-openemr.test",
                env="local",
                allow_run_against=True,
                target_kind="copilot_proxy",
                target_username="admin",
                target_password_encrypted=encrypt("pass"),
            )

        body: dict[str, Any] = {
            "project_id": str(project_id),
            "version_tag": "deploy-abc123",
        }
        raw = json.dumps(body).encode("utf-8")
        sig = _sign(raw, "test-secret-r8")

        resp = await client.post(
            "/webhooks/deploy",
            content=raw,
            headers={"X-CATS-Signature": sig, "Content-Type": "application/json"},
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["status"] == "queued"
        assert data["project_id"] == str(project_id)
        assert data["version_tag"] == "deploy-abc123"
        assert data["sweep_id"]

        assert await _audit_count("regression.webhook.accepted") >= 1

        # Returned sweep_id must resolve to the actual row — the
        # webhook caller deep-links to /regressions and needs a real
        # id. Poll briefly: the background task may not have written
        # the row yet by the time the HTTP response lands.
        import asyncio

        from cats.db.repositories.regression_repo import get_sweep

        sweep_uuid_str = data["sweep_id"]
        from uuid import UUID

        sweep_uuid = UUID(sweep_uuid_str)
        for _ in range(20):
            async with session_scope() as session:
                row = await get_sweep(session, sweep_id=sweep_uuid)
            if row is not None:
                break
            await asyncio.sleep(0.1)
        assert row is not None, (
            f"sweep_id {sweep_uuid_str} returned by webhook did not "
            "resolve to a regression_sweeps row"
        )
    finally:
        set_settings_for_test(deploy_webhook_secret="")


@pytest.mark.asyncio
async def test_webhook_rejects_invalid_project_id(client: AsyncClient) -> None:
    set_settings_for_test(deploy_webhook_secret="test-secret-r8")
    try:
        raw = b'{"project_id": "not-a-uuid"}'
        sig = _sign(raw, "test-secret-r8")
        resp = await client.post(
            "/webhooks/deploy",
            content=raw,
            headers={"X-CATS-Signature": sig, "Content-Type": "application/json"},
        )
        assert resp.status_code == 400
    finally:
        set_settings_for_test(deploy_webhook_secret="")


@pytest.mark.asyncio
async def test_webhook_rejects_non_json_body_after_auth(client: AsyncClient) -> None:
    set_settings_for_test(deploy_webhook_secret="test-secret-r8")
    try:
        raw = b"<<<not json>>>"
        sig = _sign(raw, "test-secret-r8")
        resp = await client.post(
            "/webhooks/deploy",
            content=raw,
            headers={"X-CATS-Signature": sig},
        )
        assert resp.status_code == 400
    finally:
        set_settings_for_test(deploy_webhook_secret="")
