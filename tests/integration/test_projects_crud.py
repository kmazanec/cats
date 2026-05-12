"""Project CRUD + role gating + audit-log writes."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy import select, text

from tests.integration.conftest import csrf_post

pytestmark = pytest.mark.integration


async def _login_admin(client: AsyncClient) -> None:
    await csrf_post(
        client,
        "/login",
        data={"email": "admin@cats.test", "password": "admin-password-1234"},
    )


async def _create_user_as_admin(
    client: AsyncClient, *, email: str, password: str, role: str
) -> None:
    await csrf_post(
        client,
        "/users",
        data={"email": email, "password": password, "role": role},
    )


async def _login_as(client: AsyncClient, email: str, password: str) -> None:
    await csrf_post(client, "/login", data={"email": email, "password": password})


@pytest.mark.asyncio
async def test_operator_can_create_project_admin_can_delete(
    client: AsyncClient,
) -> None:
    await _login_admin(client)
    await _create_user_as_admin(
        client, email="op@cats.test", password="oppassword!", role="operator"
    )
    await _create_user_as_admin(client, email="v@cats.test", password="vpassword!", role="viewer")
    await csrf_post(client, "/logout")
    await _login_as(client, "op@cats.test", "oppassword!")

    r = await csrf_post(
        client,
        "/projects",
        data={
            "name": "Co-Pilot prod",
            "base_url": "https://copilot.biograph.dev",
            "env": "prod",
            "description": "live target",
        },
    )
    assert r.status_code == 303
    list_r = await client.get("/projects", headers={"accept": "text/html"})
    assert list_r.status_code == 200
    assert "Co-Pilot prod" in list_r.text

    from cats.db.engine import session_scope
    from cats.db.schema import projects

    async with session_scope() as session:
        rows = (await session.execute(select(projects.c.id, projects.c.name))).all()
    project_id = next(r.id for r in rows if r.name == "Co-Pilot prod")

    del_as_op = await csrf_post(
        client,
        f"/projects/{project_id}/delete",
        headers={"accept": "text/html"},
    )
    assert del_as_op.status_code == 403

    await csrf_post(client, "/logout")
    await _login_admin(client)
    del_r = await csrf_post(client, f"/projects/{project_id}/delete")
    assert del_r.status_code == 303


@pytest.mark.asyncio
async def test_viewer_cannot_create_project(client: AsyncClient) -> None:
    await _login_admin(client)
    await _create_user_as_admin(client, email="v@cats.test", password="vpassword!", role="viewer")
    await csrf_post(client, "/logout")
    await _login_as(client, "v@cats.test", "vpassword!")

    r = await csrf_post(
        client,
        "/projects",
        data={
            "name": "Should fail",
            "base_url": "https://example.test",
            "env": "local",
        },
        headers={"accept": "text/html"},
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_invalid_base_url_rejected(client: AsyncClient) -> None:
    await _login_admin(client)
    r = await csrf_post(
        client,
        "/projects",
        data={"name": "x", "base_url": "not-a-url", "env": "local"},
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_invalid_env_rejected(client: AsyncClient) -> None:
    await _login_admin(client)
    r = await csrf_post(
        client,
        "/projects",
        data={"name": "x", "base_url": "https://x.test", "env": "bogus"},
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_each_mutation_writes_audit_entry(client: AsyncClient) -> None:
    await _login_admin(client)
    await csrf_post(
        client,
        "/projects",
        data={"name": "Audited", "base_url": "https://a.test", "env": "local"},
    )
    from cats.db.engine import session_scope

    async with session_scope() as session:
        rows = (
            await session.execute(text("SELECT action, actor FROM audit_log ORDER BY at"))
        ).all()
    actions = [r.action for r in rows]
    assert "auth.login" in actions
    assert "project.create" in actions
