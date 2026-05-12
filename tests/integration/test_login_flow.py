"""Login + session cookie + role gating against a real Postgres."""

from __future__ import annotations

import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_unauthenticated_redirects_to_login(client: AsyncClient) -> None:
    r = await client.get("/", follow_redirects=False, headers={"accept": "text/html"})
    assert r.status_code == 302
    assert r.headers["location"] == "/login"


@pytest.mark.asyncio
async def test_login_with_seeded_admin(client: AsyncClient) -> None:
    r = await client.post(
        "/login",
        data={"email": "admin@cats.test", "password": "admin-password-1234"},
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert "cats_session" in r.cookies
    # Cookie session should now load the overview.
    overview = await client.get("/", follow_redirects=False, headers={"accept": "text/html"})
    assert overview.status_code == 200


@pytest.mark.asyncio
async def test_login_rejects_wrong_password(client: AsyncClient) -> None:
    r = await client.post(
        "/login",
        data={"email": "admin@cats.test", "password": "wrong"},
        follow_redirects=False,
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_logout_clears_session(client: AsyncClient) -> None:
    await client.post(
        "/login",
        data={"email": "admin@cats.test", "password": "admin-password-1234"},
        follow_redirects=False,
    )
    r = await client.post("/logout", follow_redirects=False)
    assert r.status_code == 302
    # Session cookie should be cleared.
    overview = await client.get("/", follow_redirects=False, headers={"accept": "text/html"})
    assert overview.status_code == 302
    assert overview.headers["location"] == "/login"
