"""Test fixtures. Integration tests assume postgres + redis are up via
`docker compose up -d`; unit tests do not."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _no_real_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make absolutely sure no real provider key leaks into a unit test run."""
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key-not-real")
    monkeypatch.setenv("LANGSMITH_TRACING", "false")
