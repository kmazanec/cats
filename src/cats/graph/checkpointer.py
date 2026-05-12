"""LangGraph checkpointer factory. Postgres-backed; **never SQLite**
(CVE-2025-67644). `langgraph-checkpoint>=4.0.0` is pinned in
pyproject.toml to dodge CVE-2026-27794 (pickle RCE).

R2 ships `AsyncPostgresSaver` so a Run that crashes mid-graph resumes
from the last completed node when the worker reconnects with the same
`thread_id` (we use `thread_id = str(run_id)`). For the in-memory
smoke path the legacy InMemorySaver is still available.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from cats.config import settings


def _psycopg_dsn() -> str:
    """LangGraph's PostgresSaver uses psycopg, not SQLAlchemy/asyncpg.
    Translate our `postgresql+asyncpg://...` URL into a plain
    `postgresql://...` DSN."""
    url = settings.database_url
    if url.startswith("postgresql+asyncpg://"):
        return "postgresql://" + url[len("postgresql+asyncpg://") :]
    if url.startswith("postgresql+psycopg://"):
        return "postgresql://" + url[len("postgresql+psycopg://") :]
    return url


def get_inmemory_checkpointer() -> Any:
    """In-memory fallback for the smoke path. Never use in prod — a
    process restart loses everything."""
    from langgraph.checkpoint.memory import InMemorySaver

    return InMemorySaver()


@asynccontextmanager
async def postgres_checkpointer() -> Any:
    """Async context manager that yields a configured `AsyncPostgresSaver`.

    Lifecycle: the saver opens a psycopg connection pool, runs its own
    schema migration on first use (`saver.setup()`), and is closed when
    the context exits. Use one per worker run.
    """
    from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

    async with AsyncPostgresSaver.from_conn_string(_psycopg_dsn()) as saver:
        await saver.setup()
        yield saver


def get_checkpointer() -> Any:
    """Synchronous accessor — returns the InMemorySaver. The graph's
    real persistence path is via `postgres_checkpointer()` (async ctx
    manager) used by the worker. We keep this synchronous helper so the
    existing smoke path keeps building a graph without async ceremony."""
    return get_inmemory_checkpointer()
