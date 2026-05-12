"""LangGraph checkpointer factory. Postgres-backed; **never SQLite**
(CVE-2025-67644). `langgraph-checkpoint>=4.0.0` is pinned in pyproject.toml
to dodge CVE-2026-27794 (pickle RCE).

The real checkpointer is wired here once a node lands that needs replay.
For scaffold/smoke we run in-memory.
"""

from __future__ import annotations

from typing import Any


def get_checkpointer() -> Any:
    """Return an in-memory checkpointer for scaffold. Swap to the Postgres
    backend once we have a persistent unit-of-work story for the graph."""
    from langgraph.checkpoint.memory import InMemorySaver

    return InMemorySaver()
