"""Postgres-backed message bus client.

The dispatch-to-one-consumer guarantee comes from
``SELECT ... FOR UPDATE SKIP LOCKED``: multiple workers polling the
same inbox don't collide because Postgres hands each requester a
different row. LISTEN/NOTIFY wakes idle workers when an emit occurs;
the worker still polls on a slower cadence as a safety net for missed
NOTIFY frames.

``emit`` is idempotent on ``idempotency_key`` — a unique constraint
on the table swallows duplicates at insert time without raising. The
caller doesn't have to think about whether a retry already landed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from cats.db.engine import session_scope
from cats.db.schema import agent_dead_letters
from cats.logging import get_logger
from cats.messaging.envelopes import Envelope, MessageKind, payload_model_for

log = get_logger(__name__)


def _channel_for(agent: str) -> str:
    """Postgres LISTEN/NOTIFY channel name for an agent's inbox."""
    return f"cats_bus_{agent}"


@dataclass(frozen=True)
class ClaimedMessage:
    """A row pulled off the bus by a worker, parsed and ready to handle.

    The worker calls :meth:`Bus.ack`, :meth:`Bus.nack`, or
    :meth:`Bus.dead_letter` to finalize. If the worker process exits
    without doing any of those, the row's ``visible_after`` deadline
    expires and another worker re-claims."""

    message_id: UUID
    kind: MessageKind
    from_agent: str
    to_agent: str
    payload_json: dict[str, Any]
    trace_id: str
    campaign_id: UUID | None
    attack_id: UUID | None
    idempotency_key: str
    attempts: int


class Bus:
    """Bus operations: emit, claim, ack/nack/dead-letter.

    All methods are async. Sessions are passed in by the caller (the
    worker base owns its session) so a single transaction can both
    consume a message and write its side effects."""

    async def emit(
        self,
        session: AsyncSession,
        envelope: Envelope[Any],
    ) -> UUID | None:
        """Insert an envelope as a row. Returns the new ``id``, or
        ``None`` if the ``idempotency_key`` already exists (the row
        was already inserted by a prior emit).

        Postgres' ``ON CONFLICT DO NOTHING`` makes the dedup
        transactional — there's no race between two concurrent
        producers that both retry the same logical event.
        """
        # asyncpg wants jsonb as a string and casts it explicitly.
        payload_json_str = json.dumps(envelope.payload.model_dump(mode="json"))
        params = {
            "from_agent": envelope.from_agent,
            "to_agent": envelope.to_agent,
            "kind": envelope.kind.value,
            "payload_json": payload_json_str,
            "trace_id": envelope.trace_id,
            "campaign_id": envelope.campaign_id,
            "attack_id": envelope.attack_id,
            "idempotency_key": envelope.idempotency_key,
            "visible_after": envelope.visible_after,
        }
        # ``visible_after`` defaults to now() at the column level when
        # the param is NULL; we don't override unless the caller asked.
        row = (
            await session.execute(
                text(
                    """
                    INSERT INTO agent_messages
                      (from_agent, to_agent, kind, payload_json, trace_id,
                       campaign_id, attack_id, idempotency_key,
                       visible_after)
                    VALUES
                      (:from_agent, :to_agent, :kind,
                       CAST(:payload_json AS jsonb), :trace_id,
                       :campaign_id, :attack_id, :idempotency_key,
                       COALESCE(:visible_after, now()))
                    ON CONFLICT (idempotency_key) DO NOTHING
                    RETURNING id
                    """
                ),
                params,
            )
        ).first()
        if row is None:
            log.debug(
                "bus.emit.duplicate",
                kind=envelope.kind.value,
                idempotency_key=envelope.idempotency_key,
            )
            return None
        # NOTIFY outside the row insert is fine — it fires on COMMIT.
        await session.execute(
            text(f"NOTIFY {_channel_for(envelope.to_agent)}"),
        )
        log.info(
            "bus.emit",
            kind=envelope.kind.value,
            to_agent=envelope.to_agent,
            campaign_id=str(envelope.campaign_id) if envelope.campaign_id else None,
            attack_id=str(envelope.attack_id) if envelope.attack_id else None,
        )
        return cast(UUID, row.id)

    async def claim_next(
        self,
        session: AsyncSession,
        *,
        to_agent: str,
        visibility_timeout_seconds: int,
        worker_id: str,
    ) -> ClaimedMessage | None:
        """Claim one ready message for ``to_agent``. Returns ``None``
        if nothing is available. The claimed row's ``visible_after``
        is pushed out by ``visibility_timeout_seconds`` so a parallel
        worker won't double-claim while this handler runs."""
        new_visible = datetime.now(UTC) + timedelta(seconds=visibility_timeout_seconds)
        row = (
            await session.execute(
                text(
                    """
                    WITH claimed AS (
                        SELECT id
                        FROM agent_messages
                        WHERE to_agent = :to_agent
                          AND consumed_at IS NULL
                          AND visible_after <= now()
                        ORDER BY created_at
                        FOR UPDATE SKIP LOCKED
                        LIMIT 1
                    )
                    UPDATE agent_messages am
                    SET visible_after = :new_visible,
                        consumed_by = :worker_id,
                        attempts = am.attempts + 1
                    FROM claimed
                    WHERE am.id = claimed.id
                    RETURNING am.id, am.kind, am.from_agent, am.to_agent,
                              am.payload_json, am.trace_id, am.campaign_id,
                              am.attack_id, am.idempotency_key, am.attempts
                    """
                ),
                {
                    "to_agent": to_agent,
                    "new_visible": new_visible,
                    "worker_id": worker_id,
                },
            )
        ).first()
        if row is None:
            return None
        try:
            kind = MessageKind(row.kind)
        except ValueError:
            log.error("bus.claim.unknown_kind", kind=row.kind, message_id=str(row.id))
            raise
        # Validate the payload eagerly; a malformed payload is a
        # contract violation, not a handler problem.
        payload_model_for(kind).model_validate(row.payload_json)
        return ClaimedMessage(
            message_id=row.id,
            kind=kind,
            from_agent=row.from_agent,
            to_agent=row.to_agent,
            payload_json=row.payload_json,
            trace_id=row.trace_id,
            campaign_id=row.campaign_id,
            attack_id=row.attack_id,
            idempotency_key=row.idempotency_key,
            attempts=row.attempts,
        )

    async def ack(self, session: AsyncSession, message_id: UUID) -> None:
        """Mark a message as successfully handled."""
        await session.execute(
            text(
                """
                UPDATE agent_messages
                SET consumed_at = now()
                WHERE id = :id
                """
            ),
            {"id": message_id},
        )

    async def nack(
        self,
        session: AsyncSession,
        message_id: UUID,
        *,
        last_error: str,
        backoff_seconds: int,
    ) -> None:
        """Hand the message back to the inbox with a delay before it
        becomes claimable again."""
        await session.execute(
            text(
                """
                UPDATE agent_messages
                SET visible_after = now() + (:backoff || ' seconds')::interval,
                    last_error = :last_error
                WHERE id = :id
                """
            ),
            {
                "id": message_id,
                "backoff": str(backoff_seconds),
                "last_error": last_error[:8192],
            },
        )

    async def touch_claim(
        self,
        session: AsyncSession,
        message_id: UUID,
        *,
        worker_id: str,
        extend_seconds: int,
    ) -> bool:
        """Extend ``visible_after`` for a message this worker currently
        owns. Used by long-running handlers (e.g. the campaign-report
        writer running an LLM tool loop) to keep their claim alive
        without bumping the worker-class-wide ``visibility_timeout``.

        The UPDATE filters on ``consumed_by = :worker_id`` so a touch
        from a worker that has already lost the claim (e.g. the bus
        redelivered the message because ``visible_after`` elapsed and
        another worker picked it up) is a no-op. Returns ``True`` if
        the touch landed, ``False`` if the claim was lost — the
        handler should treat that as a signal to abort, since another
        worker is now processing the same message and acking/nacking
        from this side would corrupt the inbox state.

        Idempotent and safe to call on any cadence (every LLM turn,
        every N seconds via a background task, etc).
        """
        new_visible = datetime.now(UTC) + timedelta(seconds=extend_seconds)
        row = (
            await session.execute(
                text(
                    """
                    UPDATE agent_messages
                    SET visible_after = :new_visible
                    WHERE id = :id
                      AND consumed_by = :worker_id
                      AND consumed_at IS NULL
                    RETURNING id
                    """
                ),
                {
                    "id": message_id,
                    "worker_id": worker_id,
                    "new_visible": new_visible,
                },
            )
        ).first()
        if row is None:
            log.warning(
                "bus.touch_claim.lost",
                message_id=str(message_id),
                worker_id=worker_id,
            )
            return False
        return True

    async def dead_letter(
        self,
        session: AsyncSession,
        message_id: UUID,
        *,
        to_agent: str,
        kind: str,
        last_error: str,
    ) -> None:
        """Move a message to the dead-letter pool. The original row
        stays in ``agent_messages`` (with ``visible_after`` far in
        the future) so the FK to ``agent_dead_letters`` is stable
        and we keep the audit trail."""
        far_future = datetime.now(UTC) + timedelta(days=365 * 10)
        await session.execute(
            text(
                """
                UPDATE agent_messages
                SET visible_after = :far,
                    last_error = :err
                WHERE id = :id
                """
            ),
            {"far": far_future, "err": last_error[:8192], "id": message_id},
        )
        await session.execute(
            agent_dead_letters.insert().values(
                message_id=message_id,
                to_agent=to_agent,
                kind=kind,
                last_error=last_error[:8192],
            ),
        )
        log.warning(
            "bus.dead_letter",
            message_id=str(message_id),
            to_agent=to_agent,
            kind=kind,
        )

    async def requeue_dead_letter(
        self,
        session: AsyncSession,
        dead_letter_id: UUID,
        *,
        operator: str,
    ) -> UUID | None:
        """Operator-triggered: bring a dead-lettered message back to
        the inbox with attempts reset. Returns the message id, or
        ``None`` if the dead letter wasn't found / already requeued."""
        row = (
            await session.execute(
                text(
                    """
                    UPDATE agent_dead_letters
                    SET requeued_at = now(),
                        requeued_by = :operator
                    WHERE id = :dl_id AND requeued_at IS NULL
                    RETURNING message_id, to_agent
                    """
                ),
                {"dl_id": dead_letter_id, "operator": operator},
            )
        ).first()
        if row is None:
            return None
        message_id = cast(UUID, row.message_id)
        to_agent = row.to_agent
        await session.execute(
            text(
                """
                UPDATE agent_messages
                SET visible_after = now(),
                    consumed_at = NULL,
                    attempts = 0,
                    last_error = NULL
                WHERE id = :id
                """
            ),
            {"id": message_id},
        )
        await session.execute(
            text(f"NOTIFY {_channel_for(to_agent)}"),
        )
        return message_id

    async def inbox_depth(self, session: AsyncSession, agent: str) -> int:
        """How many ready-to-claim messages are waiting for ``agent``.

        The /bus dashboard polls this per-agent."""
        row = (
            await session.execute(
                text(
                    """
                    SELECT count(*) AS n
                    FROM agent_messages
                    WHERE to_agent = :agent
                      AND consumed_at IS NULL
                      AND visible_after <= now()
                    """
                ),
                {"agent": agent},
            )
        ).first()
        return int(row.n) if row else 0


async def emit_with_session(envelope: Envelope[Any]) -> UUID | None:
    """Convenience: open a session, emit, commit, return id.

    Tests and outside-the-worker producers (the API plan-approval
    route, for instance) use this rather than holding open a worker
    session."""
    bus = Bus()
    async with session_scope() as session:
        msg_id = await bus.emit(session, envelope)
        await session.commit()
    return msg_id
