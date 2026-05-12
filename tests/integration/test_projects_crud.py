"""Project CRUD + role gating + audit-log writes."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy import select, text

pytestmark = pytest.mark.integration


async def _login_admin(client: AsyncClient) -> None:
    await client.post(
        "/login",
        data={"email": "admin@cats.test", "password": "admin-password-1234"},
        follow_redirects=False,
    )


async def _create_user_as_admin(
    client: AsyncClient, *, email: str, password: str, role: str
) -> None:
    await client.post(
        "/users",
        data={"email": email, "password": password, "role": role},
        follow_redirects=False,
    )


async def _login_as(client: AsyncClient, email: str, password: str) -> None:
    await client.post(
        "/login",
        data={"email": email, "password": password},
        follow_redirects=False,
    )


@pytest.mark.asyncio
async def test_operator_can_create_project_admin_can_delete(
    client: AsyncClient,
) -> None:
    await _login_admin(client)
    await _create_user_as_admin(
        client, email="op@cats.test", password="oppassword!", role="operator"
    )
    # Admin creates a viewer to verify the role gate later.
    await _create_user_as_admin(client, email="v@cats.test", password="vpassword!", role="viewer")
    # Admin signs out, operator signs in.
    await client.post("/logout", follow_redirects=False)
    await _login_as(client, "op@cats.test", "oppassword!")

    r = await client.post(
        "/projects",
        data={
            "name": "Co-Pilot prod",
            "base_url": "https://copilot.biograph.dev",
            "env": "prod",
            "description": "live target",
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    list_r = await client.get("/projects", headers={"accept": "text/html"})
    assert list_r.status_code == 200
    assert "Co-Pilot prod" in list_r.text

    # Operator cannot delete — needs admin.
    # Find the project_id from the page.
    # Simpler: query the DB through the test engine.
    from cats.db.engine import session_scope
    from cats.db.schema import projects

    async with session_scope() as session:
        rows = (await session.execute(select(projects.c.id, projects.c.name))).all()
    project_id = next(r.id for r in rows if r.name == "Co-Pilot prod")

    del_as_op = await client.post(
        f"/projects/{project_id}/delete",
        follow_redirects=False,
        headers={"accept": "text/html"},
    )
    assert del_as_op.status_code == 403

    # Sign back in as admin and delete.
    await client.post("/logout", follow_redirects=False)
    await _login_admin(client)
    del_r = await client.post(f"/projects/{project_id}/delete", follow_redirects=False)
    assert del_r.status_code == 303


@pytest.mark.asyncio
async def test_viewer_cannot_create_project(client: AsyncClient) -> None:
    await _login_admin(client)
    await _create_user_as_admin(client, email="v@cats.test", password="vpassword!", role="viewer")
    await client.post("/logout", follow_redirects=False)
    await _login_as(client, "v@cats.test", "vpassword!")

    r = await client.post(
        "/projects",
        data={
            "name": "Should fail",
            "base_url": "https://example.test",
            "env": "local",
        },
        follow_redirects=False,
        headers={"accept": "text/html"},
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_invalid_base_url_rejected(client: AsyncClient) -> None:
    await _login_admin(client)
    r = await client.post(
        "/projects",
        data={"name": "x", "base_url": "not-a-url", "env": "local"},
        follow_redirects=False,
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_invalid_env_rejected(client: AsyncClient) -> None:
    await _login_admin(client)
    r = await client.post(
        "/projects",
        data={"name": "x", "base_url": "https://x.test", "env": "bogus"},
        follow_redirects=False,
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_each_mutation_writes_audit_entry(client: AsyncClient) -> None:
    await _login_admin(client)
    await client.post(
        "/projects",
        data={"name": "Audited", "base_url": "https://a.test", "env": "local"},
        follow_redirects=False,
    )
    from cats.db.engine import session_scope

    async with session_scope() as session:
        rows = (
            await session.execute(text("SELECT action, actor FROM audit_log ORDER BY at"))
        ).all()
    actions = [r.action for r in rows]
    # auth.login + project.create (at least).
    assert "auth.login" in actions
    assert "project.create" in actions
