"""Login + session cookie + role gating against a real Postgres."""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from tests.integration.conftest import csrf_post

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_unauthenticated_redirects_to_login(client: AsyncClient) -> None:
    r = await client.get("/", follow_redirects=False, headers={"accept": "text/html"})
    assert r.status_code == 302
    assert r.headers["location"] == "/login"


@pytest.mark.asyncio
async def test_login_with_seeded_admin(client: AsyncClient) -> None:
    r = await csrf_post(
        client,
        "/login",
        data={"email": "admin@cats.test", "password": "admin-password-1234"},
    )
    assert r.status_code == 302
    assert "cats_session" in r.cookies
    overview = await client.get("/", follow_redirects=False, headers={"accept": "text/html"})
    assert overview.status_code == 200


@pytest.mark.asyncio
async def test_login_rejects_wrong_password(client: AsyncClient) -> None:
    r = await csrf_post(
        client,
        "/login",
        data={"email": "admin@cats.test", "password": "wrong"},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_logout_clears_session(client: AsyncClient) -> None:
    await csrf_post(
        client,
        "/login",
        data={"email": "admin@cats.test", "password": "admin-password-1234"},
    )
    r = await csrf_post(client, "/logout")
    assert r.status_code == 302
    overview = await client.get("/", follow_redirects=False, headers={"accept": "text/html"})
    assert overview.status_code == 302
    assert overview.headers["location"] == "/login"


@pytest.mark.asyncio
async def test_post_without_csrf_token_blocked(client: AsyncClient) -> None:
    """R2 closes the R1 CSRF gap. Direct POST without a token must be
    rejected with 403, even on /login (where there's no session yet)."""
    # Skip the helper — issue a raw POST. We still need the cookie because
    # require_csrf checks both sides; without the cookie we get the cookie
    # error first.
    await client.get("/healthz")
    r = await client.post(
        "/login",
        data={"email": "admin@cats.test", "password": "admin-password-1234"},
        follow_redirects=False,
    )
    assert r.status_code == 403
    detail = r.json()["detail"]
    assert "csrf" in detail.lower()
