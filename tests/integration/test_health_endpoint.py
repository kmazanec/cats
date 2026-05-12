"""Health endpoint exercises the real Postgres + Redis paths and stubs the
network checks."""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from tests.integration.conftest import csrf_post

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_healthz_basic(client: AsyncClient) -> None:
    r = await client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"ok": True}


@pytest.mark.asyncio
async def test_full_health_requires_auth(client: AsyncClient) -> None:
    r = await client.get(
        "/health/full", follow_redirects=False, headers={"accept": "application/json"}
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_full_health_after_login(client: AsyncClient) -> None:
    await csrf_post(
        client,
        "/login",
        data={"email": "admin@cats.test", "password": "admin-password-1234"},
    )
    r = await client.get("/health/full")
    # 200 if all configured deps green, 503 if any configured dep failed.
    assert r.status_code in (200, 503)
    body = r.json()
    assert "checks" in body
    names = {c["name"] for c in body["checks"]}
    assert names == {"postgres", "redis", "openrouter", "langsmith"}
    by_name = {c["name"]: c for c in body["checks"]}
    assert by_name["postgres"]["status"] == "ok"
    assert by_name["redis"]["status"] == "ok"
