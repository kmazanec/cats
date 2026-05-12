"""Redis pub/sub wrapper. One process-wide client; publish is async."""

from __future__ import annotations

from collections.abc import AsyncIterator

import redis.asyncio as redis_async

from cats.config import settings
from cats.events.types import EventEnvelope


class EventBus:
    def __init__(self, url: str | None = None) -> None:
        self._client: redis_async.Redis[str] = redis_async.from_url(
            url or settings.redis_url, decode_responses=True
        )

    async def publish(self, event: EventEnvelope) -> int:
        return int(await self._client.publish(event.channel(), event.model_dump_json()))

    async def subscribe(self, channel: str) -> AsyncIterator[EventEnvelope]:
        pubsub = self._client.pubsub()
        await pubsub.subscribe(channel)
        try:
            async for msg in pubsub.listen():
                if msg.get("type") != "message":
                    continue
                data = msg.get("data")
                if isinstance(data, bytes):
                    data = data.decode()
                if not isinstance(data, str):
                    continue
                yield EventEnvelope.model_validate_json(data)
        finally:
            await pubsub.unsubscribe(channel)
            await pubsub.close()

    async def close(self) -> None:
        await self._client.close()
