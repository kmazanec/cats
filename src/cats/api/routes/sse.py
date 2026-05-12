"""SSE endpoint backed by Redis pub/sub."""

from __future__ import annotations

from collections.abc import AsyncIterator

from fastapi import APIRouter
from sse_starlette.sse import EventSourceResponse

from cats.events.bus import EventBus

router = APIRouter()


@router.get("/{campaign_id}")
async def stream(campaign_id: str) -> EventSourceResponse:
    bus = EventBus()

    async def gen() -> AsyncIterator[dict[str, str]]:
        try:
            async for env in bus.subscribe(f"campaign:{campaign_id}"):
                yield {"event": env.kind, "data": env.model_dump_json()}
        finally:
            await bus.close()

    return EventSourceResponse(gen())
