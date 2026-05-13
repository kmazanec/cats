"""SSE endpoints backed by Redis pub/sub.

Two streams:

- ``/events/global`` fans in every campaign channel (``campaign:*``)
  plus the bare ``global`` channel, so the dashboard sees activity
  platform-wide without selecting a run.
- ``/events/{campaign_id}`` is the per-campaign stream the campaign
  detail page subscribes to.

The route order matters: ``/global`` is registered before the
``/{campaign_id}`` variable route so FastAPI doesn't treat "global"
as a campaign id.

Events are emitted as the default ``message`` kind (no ``event:`` line)
so the consumer can use ``EventSource.onmessage`` / HTMX
``sse-swap="message"`` with a single handler. The event kind stays
inside the JSON payload.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from fastapi import APIRouter
from sse_starlette.sse import EventSourceResponse

from cats.events.bus import EventBus

router = APIRouter()


@router.get("/global")
async def stream_global() -> EventSourceResponse:
    bus = EventBus()

    async def gen() -> AsyncIterator[dict[str, str]]:
        try:
            async for env in bus.psubscribe("campaign:*"):
                yield {"data": env.model_dump_json()}
        finally:
            await bus.close()

    return EventSourceResponse(gen())


@router.get("/{campaign_id}")
async def stream(campaign_id: str) -> EventSourceResponse:
    bus = EventBus()

    async def gen() -> AsyncIterator[dict[str, str]]:
        try:
            async for env in bus.subscribe(f"campaign:{campaign_id}"):
                yield {"data": env.model_dump_json()}
        finally:
            await bus.close()

    return EventSourceResponse(gen())
