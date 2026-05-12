"""Async HTTP client that fires attack payloads at a target's base_url.

This is the only path through which adversarial content reaches the live
system. Every call is wrapped in a structured log line; downstream code
writes the (request, response) pair into an AttackExecution row.
"""

from __future__ import annotations

import time

import httpx

from cats.target.contracts import CopilotRequest, CopilotResponse


class TargetClient:
    def __init__(self, base_url: str, *, default_timeout: float = 30.0) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout = default_timeout

    async def call(self, request: CopilotRequest) -> CopilotResponse:
        url = f"{self._base_url}{request.endpoint}"
        started = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.request(
                    request.method,
                    url,
                    json=request.payload or None,
                    headers=request.headers or None,
                )
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            try:
                body: dict[str, object] | str = resp.json()
            except ValueError:
                body = resp.text
            return CopilotResponse(
                status_code=resp.status_code,
                headers=dict(resp.headers),
                body=body,
                latency_ms=elapsed_ms,
            )
        except httpx.HTTPError as e:
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            return CopilotResponse(
                status_code=0,
                latency_ms=elapsed_ms,
                error=str(e),
            )
