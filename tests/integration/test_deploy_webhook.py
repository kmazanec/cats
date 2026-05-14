"""R8 followup — deploy webhook auth + audit behavior (per-project secret).

Covers the four states the webhook can be in:

1. Project not found → 404 + audit entry.
2. Project found but no secret configured → 503 + audit entry
   (project hasn't opted into webhook-driven sweeps).
3. Secret configured + missing/invalid signature → 401 + audit entry.
4. Secret configured + valid HMAC over the raw body → 200 + audit
   entry + sweep enqueued.

The sweep itself is exercised end-to-end in
``test_regression_sweep_e2e.py``; this test only confirms the auth
gate and the URL contract.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any
from uuid import UUID, uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy import text, update

from cats.db.engine import session_scope
from cats.db.schema import projects


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


async def _seed_project_with_secret(secret: str | None) -> UUID:
    """Create a project; optionally attach an encrypted webhook secret."""
    from cats.db.repositories.project_repo import create_project
    from cats.security.crypto import encrypt

    async with session_scope() as session:
        project_id = await create_project(
            session,
            name=f"Webhook Target {uuid4().hex[:8]}",
            base_url="http://fake-openemr.test",
            env="local",
            allow_run_against=True,
            target_kind="copilot_proxy",
            target_username="admin",
            target_password_encrypted=encrypt("pass"),
        )
        if secret is not None:
            await session.execute(
                update(projects)
                .where(projects.c.id == project_id)
                .values(deploy_webhook_secret_encrypted=encrypt(secret))
            )
    return project_id


@pytest.mark.asyncio
async def test_webhook_unknown_project_returns_404(client: AsyncClient) -> None:
    bogus = uuid4()
    resp = await client.post(
        f"/webhooks/deploy/{bogus}",
        content=b"{}",
        headers={"X-CATS-Signature": "sha256=anything"},
    )
    assert resp.status_code == 404
    assert await _audit_count("regression.webhook.unknown_project") >= 1


@pytest.mark.asyncio
async def test_webhook_project_without_secret_returns_503(client: AsyncClient) -> None:
    project_id = await _seed_project_with_secret(None)
    resp = await client.post(
        f"/webhooks/deploy/{project_id}",
        content=b"{}",
        headers={"X-CATS-Signature": "sha256=anything"},
    )
    assert resp.status_code == 503
    assert await _audit_count("regression.webhook.unconfigured") >= 1


@pytest.mark.asyncio
async def test_webhook_with_bad_signature_returns_401(client: AsyncClient) -> None:
    project_id = await _seed_project_with_secret("test-secret-r8")
    resp = await client.post(
        f"/webhooks/deploy/{project_id}",
        content=b"{}",
        headers={"X-CATS-Signature": "sha256=deadbeef"},
    )
    assert resp.status_code == 401
    assert await _audit_count("regression.webhook.rejected") >= 1

    # Missing header is also rejected.
    resp2 = await client.post(
        f"/webhooks/deploy/{project_id}",
        content=b"{}",
    )
    assert resp2.status_code == 401


@pytest.mark.asyncio
async def test_webhook_with_valid_signature_queues_sweep(client: AsyncClient) -> None:
    project_id = await _seed_project_with_secret("test-secret-r8")

    body: dict[str, Any] = {"version_tag": "deploy-abc123"}
    raw = json.dumps(body).encode("utf-8")
    sig = _sign(raw, "test-secret-r8")

    resp = await client.post(
        f"/webhooks/deploy/{project_id}",
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

    # Returned sweep_id must resolve to the actual row.
    import asyncio

    from cats.db.repositories.regression_repo import get_sweep

    sweep_uuid = UUID(data["sweep_id"])
    for _ in range(20):
        async with session_scope() as session:
            row = await get_sweep(session, sweep_id=sweep_uuid)
        if row is not None:
            break
        await asyncio.sleep(0.1)
    assert row is not None, (
        f"sweep_id {sweep_uuid} returned by webhook did not resolve to a regression_sweeps row"
    )


@pytest.mark.asyncio
async def test_webhook_per_project_secret_isolation(client: AsyncClient) -> None:
    """A signature valid for project A must NOT authenticate to project B.
    Pins the multi-project use case the followup exists to enable."""
    project_a = await _seed_project_with_secret("secret-a")
    project_b = await _seed_project_with_secret("secret-b")

    body = b'{"version_tag":"deploy"}'
    sig_for_a = _sign(body, "secret-a")

    # Valid for A.
    resp_a = await client.post(
        f"/webhooks/deploy/{project_a}",
        content=body,
        headers={"X-CATS-Signature": sig_for_a},
    )
    assert resp_a.status_code == 200

    # Same signature, posted to B → rejected (B's secret is different).
    resp_b = await client.post(
        f"/webhooks/deploy/{project_b}",
        content=body,
        headers={"X-CATS-Signature": sig_for_a},
    )
    assert resp_b.status_code == 401


@pytest.mark.asyncio
async def test_webhook_rejects_non_json_body_after_auth(client: AsyncClient) -> None:
    project_id = await _seed_project_with_secret("test-secret-r8")
    raw = b"<<<not json>>>"
    sig = _sign(raw, "test-secret-r8")
    resp = await client.post(
        f"/webhooks/deploy/{project_id}",
        content=raw,
        headers={"X-CATS-Signature": sig},
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_webhook_empty_body_is_accepted_with_valid_signature(
    client: AsyncClient,
) -> None:
    """An empty body is valid: HMAC over empty bytes still verifies. The
    body's contents are optional metadata; the project_id is the URL."""
    project_id = await _seed_project_with_secret("test-secret-r8")
    sig = _sign(b"", "test-secret-r8")
    resp = await client.post(
        f"/webhooks/deploy/{project_id}",
        content=b"",
        headers={"X-CATS-Signature": sig},
    )
    assert resp.status_code == 200
    assert resp.json()["project_id"] == str(project_id)
