"""R8 followup — UI flow for per-project deploy webhook secret.

End-to-end through the HTTP UI:

1. Operator creates a project; the edit form shows "not configured".
2. Operator POSTs to /webhook-secret/generate; response page renders
   the plaintext secret exactly once, and the DB row carries an
   encrypted column.
3. Re-visiting the edit form shows "configured".
4. The actual deploy webhook now accepts a signed payload built
   from the generated secret — proving the encrypt/decrypt round
   trip works against the live route.
5. Revoking clears the column; the webhook returns 503 again.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from uuid import UUID

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from cats.db.engine import session_scope
from cats.db.schema import projects
from cats.security.crypto import decrypt
from tests.integration.conftest import csrf_post


async def _login_admin(client: AsyncClient) -> None:
    await csrf_post(
        client,
        "/login",
        data={"email": "admin@cats.test", "password": "admin-password-1234"},
    )


async def _create_project(client: AsyncClient) -> UUID:
    await csrf_post(
        client,
        "/projects",
        data={
            "name": "Webhook UI Target",
            "base_url": "https://webhook-ui.test",
            "env": "local",
            "description": "fixture",
        },
    )
    async with session_scope() as session:
        pid = (
            await session.execute(
                select(projects.c.id).where(projects.c.name == "Webhook UI Target")
            )
        ).scalar_one()
    return UUID(str(pid))


@pytest.mark.asyncio
async def test_generate_rotate_revoke_flow(client: AsyncClient) -> None:
    await _login_admin(client)
    project_id = await _create_project(client)

    # Initial edit form: "not configured" + "generate" button.
    edit = await client.get(f"/projects/{project_id}/edit")
    assert edit.status_code == 200
    assert b"not configured" in edit.content
    assert b"generate secret" in edit.content

    # Generate. Response should render the plaintext exactly once.
    gen = await csrf_post(client, f"/projects/{project_id}/webhook-secret/generate")
    assert gen.status_code == 200
    body = gen.text
    assert "Capture this secret now" in body
    # The plaintext is 32-byte hex = 64 chars; pull it out.
    m = re.search(r"CATS_WEBHOOK_SECRET=([0-9a-f]{64})", body)
    assert m is not None, "expected the secret to be rendered for one-time copy"
    plain_secret = m.group(1)

    # DB now has the encrypted column populated, and decrypts to the
    # same plaintext we just showed the user.
    async with session_scope() as session:
        stored = (
            await session.execute(
                select(projects.c.deploy_webhook_secret_encrypted).where(
                    projects.c.id == project_id
                )
            )
        ).scalar_one()
    assert stored is not None
    assert decrypt(stored) == plain_secret

    # Edit form now reports "configured" + offers rotate/revoke.
    edit_after = await client.get(f"/projects/{project_id}/edit")
    assert b"configured" in edit_after.content
    assert b"rotate secret" in edit_after.content
    assert b"revoke" in edit_after.content

    # The live webhook accepts a payload signed with that secret.
    raw = b'{"version_tag":"ui-test"}'
    sig = "sha256=" + hmac.new(plain_secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()
    hook = await client.post(
        f"/webhooks/deploy/{project_id}",
        content=raw,
        headers={"X-CATS-Signature": sig},
    )
    assert hook.status_code == 200, hook.text

    # Rotate: a new secret replaces the old one; the old signature
    # should no longer authenticate.
    rotate = await csrf_post(client, f"/projects/{project_id}/webhook-secret/generate")
    assert rotate.status_code == 200
    m2 = re.search(r"CATS_WEBHOOK_SECRET=([0-9a-f]{64})", rotate.text)
    assert m2 is not None
    new_secret = m2.group(1)
    assert new_secret != plain_secret

    stale = await client.post(
        f"/webhooks/deploy/{project_id}",
        content=raw,
        headers={"X-CATS-Signature": sig},  # signed with the old secret
    )
    assert stale.status_code == 401

    # Revoke: column cleared, webhook reverts to 503.
    revoke = await csrf_post(client, f"/projects/{project_id}/webhook-secret/revoke")
    assert revoke.status_code == 303
    async with session_scope() as session:
        cleared = (
            await session.execute(
                select(projects.c.deploy_webhook_secret_encrypted).where(
                    projects.c.id == project_id
                )
            )
        ).scalar_one()
    assert cleared is None

    after_revoke = await client.post(
        f"/webhooks/deploy/{project_id}",
        content=raw,
        headers={
            "X-CATS-Signature": "sha256="
            + hmac.new(new_secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()
        },
    )
    assert after_revoke.status_code == 503


@pytest.mark.asyncio
async def test_generate_requires_csrf(client: AsyncClient) -> None:
    """Plain POST (no csrf_token) must 403 — symmetric with the rest
    of the project mutation surface."""
    await _login_admin(client)
    project_id = await _create_project(client)

    # Bypass csrf_post helper — post without the token field.
    resp = await client.post(f"/projects/{project_id}/webhook-secret/generate")
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_generate_unknown_project_404s(client: AsyncClient) -> None:
    await _login_admin(client)
    from uuid import uuid4

    bogus = uuid4()
    resp = await csrf_post(client, f"/projects/{bogus}/webhook-secret/generate")
    assert resp.status_code == 404
