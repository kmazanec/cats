"""Integration test fixtures. Assumes Postgres + Redis are running locally
on the compose-mapped ports (5433 / 6380). Each test gets a fresh DB state
and a freshly-built engine (so it lives on the test's own event loop)."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

# Test isolation: keep env separate from any local .env values. These have to
# be set before cats.config is imported.
os.environ.setdefault("CATS_ADMIN_EMAIL", "admin@cats.test")
os.environ.setdefault("CATS_ADMIN_PASSWORD", "admin-password-1234")
os.environ.setdefault("CATS_SESSION_SECRET", "test-secret-not-for-prod")
os.environ.setdefault(
    "DATABASE_URL",
    "postgresql+asyncpg://cats:cats@localhost:5433/cats",
)
os.environ.setdefault("REDIS_URL", "redis://localhost:6380/0")


# Reset the lru_cached settings so the env vars above take effect even if some
# other test imported cats.config first.
from cats.config import _load

_load.cache_clear()


_TABLES_TO_TRUNCATE = [
    "audit_log",
    "users",
    "finding_executions",
    "findings",
    "attack_executions",
    "judge_verdicts",
    "rubric_versions",
    "attacks",
    "runs",
    "campaigns",
    "project_versions",
    "projects",
]


@pytest_asyncio.fixture
async def client() -> AsyncIterator[AsyncClient]:
    """Per-test app + DB engine, both bound to this test's event loop."""
    # Reset the cats.db engine module so it builds a fresh engine on this loop.
    from cats.db import engine as cats_engine

    cats_engine._engine = None
    cats_engine._session_factory = None

    # Truncate via a temporary engine on this loop.
    truncate_engine = create_async_engine(os.environ["DATABASE_URL"])
    try:
        async with truncate_engine.begin() as conn:
            await conn.execute(
                text(f"TRUNCATE TABLE {', '.join(_TABLES_TO_TRUNCATE)} RESTART IDENTITY CASCADE")
            )
    finally:
        await truncate_engine.dispose()

    from cats.api.app import create_app

    app = create_app()
    transport = ASGITransport(app=app)
    async with (
        AsyncClient(transport=transport, base_url="http://test") as ac,
        app.router.lifespan_context(app),
    ):
        yield ac

    # Tear down the cats.db engine on the same loop that created it.
    if cats_engine._engine is not None:
        await cats_engine._engine.dispose()
        cats_engine._engine = None
        cats_engine._session_factory = None
