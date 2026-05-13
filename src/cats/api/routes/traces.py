"""LangSmith trace redirect.

The execution-detail UI links to ``/traces/{trace_id}`` — this route looks
the run up via the LangSmith API and 302s to the canonical UI URL
(``/o/{tenant}/projects/p/{session}/r/{run}?poll=true``).

We do the lookup at click time rather than baking the URL into the
``attack_executions`` row: building the URL needs the tenant + session
ids, which aren't on the recorded id alone, and LangSmith's own client
already knows how to assemble it. The route is auth-gated; an unset
LANGSMITH_API_KEY returns 404 rather than leaking a half-built URL.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import RedirectResponse

from cats.api.auth import Principal, require_user
from cats.config import settings
from cats.logging import get_logger

log = get_logger(__name__)
router = APIRouter()


@router.get("/{trace_id}")
async def trace_redirect(
    trace_id: UUID,
    principal: Principal = Depends(require_user),
) -> Any:
    _ = principal
    if not settings.langsmith_api_key:
        raise HTTPException(status_code=404, detail="LangSmith is not configured")

    try:
        from langsmith import Client
    except ImportError as exc:
        log.warning("traces.langsmith_import_failed", error=repr(exc))
        raise HTTPException(status_code=503, detail="langsmith client unavailable") from exc

    client = Client(
        api_url="https://api.smith.langchain.com",
        api_key=settings.langsmith_api_key,
    )
    try:
        run = await _read_run(client, trace_id)
        url = client.get_run_url(run=run)
    except Exception as exc:
        log.warning("traces.lookup_failed", trace_id=str(trace_id), error=repr(exc))
        raise HTTPException(status_code=404, detail="trace not found") from exc

    return RedirectResponse(url=url, status_code=302)


async def _read_run(client: Any, trace_id: UUID) -> Any:
    """LangSmith's Client is sync-only; run the read in a thread so we
    don't block the event loop on the outbound HTTP."""
    import anyio

    return await anyio.to_thread.run_sync(lambda: client.read_run(str(trace_id)))
