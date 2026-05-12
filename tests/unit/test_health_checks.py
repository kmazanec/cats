"""Unit tests for the health check module — branch coverage for ok / fail /
not_configured paths. Network calls are stubbed."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from cats.health.checks import (
    HealthCheckResult,
    HealthReport,
    check_langsmith,
    check_openrouter,
)


def test_health_report_overall_ok_when_all_ok_or_not_configured() -> None:
    report = HealthReport(
        checks=(
            HealthCheckResult("postgres", "ok"),
            HealthCheckResult("redis", "ok"),
            HealthCheckResult("openrouter", "not_configured"),
            HealthCheckResult("langsmith", "not_configured"),
        )
    )
    assert report.overall_ok is True


def test_health_report_overall_blocked_on_a_fail() -> None:
    report = HealthReport(
        checks=(
            HealthCheckResult("postgres", "ok"),
            HealthCheckResult("redis", "fail", "connection refused"),
        )
    )
    assert report.overall_ok is False


def test_health_check_result_is_blocking() -> None:
    assert HealthCheckResult("x", "fail").is_blocking is True
    assert HealthCheckResult("x", "ok").is_blocking is False
    assert HealthCheckResult("x", "not_configured").is_blocking is False


@pytest.mark.asyncio
async def test_check_openrouter_not_configured_when_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from cats.health import checks as checks_mod

    monkeypatch.setattr(checks_mod.settings, "openrouter_api_key", "test-key-not-real")
    result = await check_openrouter()
    assert result.status == "not_configured"


@pytest.mark.asyncio
async def test_check_openrouter_ok_on_200(monkeypatch: pytest.MonkeyPatch) -> None:
    from cats.health import checks as checks_mod

    monkeypatch.setattr(checks_mod.settings, "openrouter_api_key", "sk-or-real-looking")

    class _R:
        status_code = 200

    class _Client:
        async def __aenter__(self) -> _Client:
            return self

        async def __aexit__(self, *a: Any) -> None:
            pass

        async def get(self, *_a: Any, **_k: Any) -> _R:
            return _R()

    with patch("cats.health.checks.httpx.AsyncClient", lambda *a, **k: _Client()):
        result = await check_openrouter()
    assert result.status == "ok"


@pytest.mark.asyncio
async def test_check_openrouter_fail_on_403(monkeypatch: pytest.MonkeyPatch) -> None:
    from cats.health import checks as checks_mod

    monkeypatch.setattr(checks_mod.settings, "openrouter_api_key", "sk-or-bogus")

    class _R:
        status_code = 403

    class _Client:
        async def __aenter__(self) -> _Client:
            return self

        async def __aexit__(self, *a: Any) -> None:
            pass

        async def get(self, *_a: Any, **_k: Any) -> _R:
            return _R()

    with patch("cats.health.checks.httpx.AsyncClient", lambda *a, **k: _Client()):
        result = await check_openrouter()
    assert result.status == "fail"
    assert "403" in result.detail


@pytest.mark.asyncio
async def test_check_langsmith_not_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    from cats.health import checks as checks_mod

    monkeypatch.setattr(checks_mod.settings, "langsmith_api_key", "")
    result = await check_langsmith()
    assert result.status == "not_configured"


@pytest.mark.asyncio
async def test_check_langsmith_handles_network_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from cats.health import checks as checks_mod

    monkeypatch.setattr(checks_mod.settings, "langsmith_api_key", "ls-key")

    boom = AsyncMock(side_effect=RuntimeError("dns not reachable"))

    class _Client:
        async def __aenter__(self) -> _Client:
            return self

        async def __aexit__(self, *a: Any) -> None:
            pass

        async def get(self, *a: Any, **k: Any) -> Any:
            return await boom(*a, **k)

    with patch("cats.health.checks.httpx.AsyncClient", lambda *a, **k: _Client()):
        result = await check_langsmith()
    assert result.status == "fail"
    assert "RuntimeError" in result.detail
