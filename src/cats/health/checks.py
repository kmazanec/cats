"""Reachability checks against every external dependency CATS uses.

Each check returns a `HealthCheckResult` with a clear status:
    - "ok" — dependency is configured and responded successfully
    - "fail" — dependency is configured but the call did not succeed
    - "not_configured" — no key/credential set; not red, not green

The `cats health` CLI and `/healthz/full` endpoint both consume this module.
A failing check never raises out of `run_all_checks`; the report contains
each check's outcome individually.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass
from typing import Literal

import httpx
import redis.asyncio as redis_async
from sqlalchemy import text

from cats.config import settings
from cats.db.engine import get_engine

CheckStatus = Literal["ok", "fail", "not_configured"]

_REQUEST_TIMEOUT_SECONDS = 5.0


@dataclass(frozen=True)
class HealthCheckResult:
    name: str
    status: CheckStatus
    detail: str = ""

    @property
    def is_blocking(self) -> bool:
        """A 'fail' on a configured dependency blocks green; 'not_configured'
        is neutral."""
        return self.status == "fail"


@dataclass(frozen=True)
class HealthReport:
    checks: tuple[HealthCheckResult, ...]

    @property
    def overall_ok(self) -> bool:
        return not any(c.is_blocking for c in self.checks)


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------


async def check_postgres() -> HealthCheckResult:
    try:
        engine = get_engine()
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return HealthCheckResult("postgres", "ok", "SELECT 1 returned")
    except Exception as exc:
        return HealthCheckResult("postgres", "fail", f"{type(exc).__name__}: {exc}")


async def check_redis() -> HealthCheckResult:
    client = redis_async.from_url(settings.redis_url)
    try:
        pong = await asyncio.wait_for(client.ping(), timeout=_REQUEST_TIMEOUT_SECONDS)
        if pong:
            return HealthCheckResult("redis", "ok", "PING -> PONG")
        return HealthCheckResult("redis", "fail", f"unexpected reply: {pong!r}")
    except Exception as exc:
        return HealthCheckResult("redis", "fail", f"{type(exc).__name__}: {exc}")
    finally:
        with contextlib.suppress(Exception):
            # redis 5.x: prefer aclose() over close(); types-redis lags.
            await client.aclose()  # type: ignore[attr-defined]


async def check_openrouter() -> HealthCheckResult:
    if not settings.openrouter_api_key or settings.openrouter_api_key.startswith("test-"):
        return HealthCheckResult("openrouter", "not_configured", "OPENROUTER_API_KEY unset")
    url = f"{settings.openrouter_base_url.rstrip('/')}/models"
    headers = {"Authorization": f"Bearer {settings.openrouter_api_key}"}
    try:
        async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT_SECONDS) as client:
            r = await client.get(url, headers=headers)
        if r.status_code == 200:
            return HealthCheckResult("openrouter", "ok", "GET /models -> 200")
        return HealthCheckResult("openrouter", "fail", f"GET /models -> HTTP {r.status_code}")
    except Exception as exc:
        return HealthCheckResult("openrouter", "fail", f"{type(exc).__name__}: {exc}")


async def check_langsmith() -> HealthCheckResult:
    if not settings.langsmith_api_key:
        return HealthCheckResult("langsmith", "not_configured", "LANGSMITH_API_KEY unset")
    url = "https://api.smith.langchain.com/info"
    headers = {"x-api-key": settings.langsmith_api_key}
    try:
        async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT_SECONDS) as client:
            r = await client.get(url, headers=headers)
        if r.status_code == 200:
            return HealthCheckResult("langsmith", "ok", "GET /info -> 200")
        return HealthCheckResult("langsmith", "fail", f"GET /info -> HTTP {r.status_code}")
    except Exception as exc:
        return HealthCheckResult("langsmith", "fail", f"{type(exc).__name__}: {exc}")


# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------


async def run_all_checks() -> HealthReport:
    results = await asyncio.gather(
        check_postgres(),
        check_redis(),
        check_openrouter(),
        check_langsmith(),
    )
    return HealthReport(checks=tuple(results))
