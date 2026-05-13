"""Integration test fixtures. Assumes Postgres + Redis are running locally
on the compose-mapped ports (5433 / 6380). Each test gets a fresh DB state
and a freshly-built engine (so it lives on the test's own event loop).

Helpers:
- `csrf_post(client, url, data=...)`: warms the CSRF cookie via a GET if
  needed, then POSTs with the matching `csrf_token` form field.
- See `tests/README.md` for the full pattern.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

import pytest_asyncio
from httpx import ASGITransport, AsyncClient, Response
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

# Resolved at module-import time so the async `_ensure_test_database_exists`
# doesn't do filesystem work on the event loop (ASYNC240).
_REPO_ROOT = Path(__file__).resolve().parents[2]

# Test isolation: keep env separate from any local .env values. These have to
# be set before cats.config is imported.
os.environ.setdefault("CATS_ADMIN_EMAIL", "admin@cats.test")
os.environ.setdefault("CATS_ADMIN_PASSWORD", "admin-password-1234")
os.environ.setdefault("CATS_SESSION_SECRET", "test-secret-not-for-prod")
os.environ.setdefault("CATS_DATA_SECRET", "test-data-secret-not-for-prod")
os.environ.setdefault("REDIS_URL", "redis://localhost:6380/0")


# Force the test suite onto a dedicated database. Truncating user/project/etc.
# tables on every test makes this catastrophic against a dev DB, so we
# unconditionally rewrite DATABASE_URL to `<name>_test` and refuse to run if
# the resulting database name doesn't end in `_test`. The dev DATABASE_URL
# from `.env` is intentionally ignored.
def _derive_test_db_url(source: str | None) -> str:
    base = source or "postgresql+asyncpg://cats:cats@localhost:5433/cats"
    parsed = urlparse(base)
    dev_name = (parsed.path or "/cats").lstrip("/") or "cats"
    test_name = dev_name if dev_name.endswith("_test") else f"{dev_name}_test"
    return urlunparse(parsed._replace(path=f"/{test_name}"))


_TEST_DATABASE_URL = _derive_test_db_url(os.environ.get("DATABASE_URL"))
_TEST_DB_NAME = urlparse(_TEST_DATABASE_URL).path.lstrip("/")
if not _TEST_DB_NAME.endswith("_test"):
    raise RuntimeError(
        f"Refusing to run integration tests against database {_TEST_DB_NAME!r}: "
        "name must end in '_test'."
    )
os.environ["DATABASE_URL"] = _TEST_DATABASE_URL


# Reset the lru_cached settings so the env vars above take effect even if some
# other test imported cats.config first. The import has to live below the
# `os.environ.setdefault` block above — moving it up would let `cats.config`
# read the host's .env values before the test isolation overrides land.
from cats.config import reset_settings_cache  # noqa: E402

reset_settings_cache()


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


async def _create_test_db_if_missing() -> None:
    """CREATE DATABASE can't run inside a transaction, so we use asyncpg
    directly against the default `postgres` database with autocommit."""
    import asyncpg

    parsed = urlparse(_TEST_DATABASE_URL.replace("+asyncpg", ""))
    server_dsn = urlunparse(parsed._replace(scheme="postgres", path="/postgres"))
    conn = await asyncpg.connect(server_dsn)
    try:
        exists = await conn.fetchval("SELECT 1 FROM pg_database WHERE datname = $1", _TEST_DB_NAME)
        if not exists:
            await conn.execute(f'CREATE DATABASE "{_TEST_DB_NAME}"')
    finally:
        await conn.close()


async def _ensure_test_database_exists() -> None:
    """Create the test database if it's missing, then run alembic against it.
    Idempotent and cached after the first invocation per process."""
    if getattr(_ensure_test_database_exists, "_done", False):
        return
    await _create_test_db_if_missing()

    proc = await asyncio.create_subprocess_exec(
        "alembic",
        "upgrade",
        "head",
        cwd=str(_REPO_ROOT),
        env={**os.environ, "DATABASE_URL": _TEST_DATABASE_URL},
    )
    rc = await proc.wait()
    if rc != 0:
        raise RuntimeError(f"alembic upgrade head failed with exit code {rc}")
    _ensure_test_database_exists._done = True  # type: ignore[attr-defined]


@pytest_asyncio.fixture
async def client() -> AsyncIterator[AsyncClient]:
    """Per-test app + DB engine, both bound to this test's event loop."""
    await _ensure_test_database_exists()

    # Reset the cats.db engine module so it builds a fresh engine on this loop.
    from cats.db import engine as cats_engine

    cats_engine._engine = None
    cats_engine._session_factory = None

    # Defense in depth: refuse to truncate unless the connected DB name ends
    # in `_test`. The setdefault dance above should already guarantee this,
    # but a runtime check costs nothing and would have prevented the dev-DB
    # clobber that motivated this guard.
    truncate_engine = create_async_engine(os.environ["DATABASE_URL"])
    try:
        async with truncate_engine.begin() as conn:
            db_name = (await conn.execute(text("SELECT current_database()"))).scalar_one()
            if not str(db_name).endswith("_test"):
                raise RuntimeError(
                    f"Refusing to TRUNCATE: connected database {db_name!r} is not a test DB."
                )
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


async def csrf_post(
    client: AsyncClient,
    url: str,
    *,
    data: dict[str, Any] | None = None,
    follow_redirects: bool = False,
    headers: dict[str, str] | None = None,
) -> Response:
    """POST with a valid CSRF token. Warms the cookie via a no-op GET on
    `/healthz` if the client doesn't yet have one — the CsrfMiddleware
    sets it on every request."""
    token = client.cookies.get("cats_csrf")
    if not token:
        await client.get("/healthz")
        token = client.cookies.get("cats_csrf") or ""
    body = dict(data or {})
    body["csrf_token"] = token
    return await client.post(url, data=body, follow_redirects=follow_redirects, headers=headers)
