"""Best-effort event publishing from graph nodes.

If Redis is unreachable the campaign continues — events are observability,
not durable state. Durable state lives in Postgres.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from cats.events.bus import EventBus
from cats.events.types import EventEnvelope, EventKind
from cats.logging import get_logger

log = get_logger(__name__)


async def publish(
    *,
    kind: EventKind,
    campaign_id: UUID | None,
    run_id: UUID | None,
    payload: dict[str, Any],
) -> None:
    import contextlib

    bus = EventBus()
    try:
        await bus.publish(
            EventEnvelope(kind=kind, campaign_id=campaign_id, run_id=run_id, payload=payload)
        )
    except Exception as e:
        log.warning("events.publish_failed", kind=kind, error=repr(e))
    finally:
        with contextlib.suppress(Exception):
            await bus.close()
