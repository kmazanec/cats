"""Integration tests for ``cats.messaging.bus`` against a real Postgres.

These tests exercise the SQL-level guarantees the bus relies on:
  * ``ON CONFLICT (idempotency_key) DO NOTHING`` for insert-time dedup,
  * ``SELECT ... FOR UPDATE SKIP LOCKED`` for dispatch-to-one,
  * ``visible_after`` reclaim for un-acked claims,
  * the dead-letter / requeue lifecycle.

Every test deletes the rows it inserted by ``idempotency_key LIKE 'test:%'``
so the suite stays self-contained even though the integration ``client``
fixture doesn't TRUNCATE ``agent_messages``.
"""

from __future__ import annotations

import asyncio
from uuid import UUID, uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy import text

from cats.db.engine import session_scope
from cats.messaging.bus import Bus
from cats.messaging.envelopes import (
    CampaignRequestedPayload,
    Envelope,
    MessageKind,
)

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_campaign_requested_envelope(
    *,
    idempotency_key: str,
    to_agent: str = "orchestrator",
) -> Envelope[CampaignRequestedPayload]:
    return Envelope[CampaignRequestedPayload](
        kind=MessageKind.CAMPAIGN_REQUESTED,
        from_agent="trigger",
        to_agent=to_agent,
        payload=CampaignRequestedPayload(
            project_id=uuid4(),
            project_version_id=uuid4(),
            budget_usd=1.0,
            name="r4-bus-test",
        ),
        trace_id="test-trace",
        idempotency_key=idempotency_key,
    )


async def _cleanup_test_rows() -> None:
    """Remove any rows this suite inserted. Idempotent."""
    async with session_scope() as session:
        # agent_dead_letters cascades via FK ON DELETE CASCADE.
        await session.execute(
            text("DELETE FROM agent_messages WHERE idempotency_key LIKE 'test:%'")
        )


@pytest.fixture(autouse=True)
async def _cleanup_around_each_test(client: AsyncClient) -> object:
    """Ensure a clean inbox both before and after each test in this
    file. The ``client`` fixture is requested only to trigger the per-
    test engine reset + lifespan."""
    _ = client  # the fixture wires the per-test engine onto this loop
    await _cleanup_test_rows()
    yield None
    await _cleanup_test_rows()


# ---------------------------------------------------------------------------
# emit + claim_next round trip
# ---------------------------------------------------------------------------


async def test_emit_then_claim_round_trip() -> None:
    bus = Bus()
    key = f"test:rt:{uuid4()}"
    env = _make_campaign_requested_envelope(idempotency_key=key)

    async with session_scope() as session:
        msg_id = await bus.emit(session, env)
        await session.commit()
    assert msg_id is not None
    assert isinstance(msg_id, UUID)

    async with session_scope() as session:
        claimed = await bus.claim_next(
            session,
            to_agent="orchestrator",
            visibility_timeout_seconds=60,
            worker_id="test-worker",
        )
        await session.commit()

    assert claimed is not None
    assert claimed.message_id == msg_id
    assert claimed.kind is MessageKind.CAMPAIGN_REQUESTED
    assert claimed.payload_json["name"] == "r4-bus-test"
    assert claimed.attempts == 1

    async with session_scope() as session:
        await bus.ack(session, msg_id)
        await session.commit()

    # A second claim_next must see nothing — the message is acked.
    async with session_scope() as session:
        again = await bus.claim_next(
            session,
            to_agent="orchestrator",
            visibility_timeout_seconds=60,
            worker_id="test-worker",
        )
        await session.commit()
    assert again is None


# ---------------------------------------------------------------------------
# Idempotency-key dedup
# ---------------------------------------------------------------------------


async def test_idempotency_key_collapses_duplicate_emits() -> None:
    bus = Bus()
    key = f"test:idem:{uuid4()}"
    env = _make_campaign_requested_envelope(idempotency_key=key)

    async with session_scope() as session:
        first = await bus.emit(session, env)
        await session.commit()
    async with session_scope() as session:
        # Same key, different payload contents — the ON CONFLICT must
        # still collapse it.
        env2 = _make_campaign_requested_envelope(idempotency_key=key)
        second = await bus.emit(session, env2)
        await session.commit()

    assert first is not None
    assert second is None

    async with session_scope() as session:
        n = (
            await session.execute(
                text("SELECT count(*) AS n FROM agent_messages WHERE idempotency_key = :k"),
                {"k": key},
            )
        ).scalar_one()
    assert n == 1


# ---------------------------------------------------------------------------
# FOR UPDATE SKIP LOCKED dispatch-to-one
# ---------------------------------------------------------------------------


async def test_parallel_claim_next_dispatches_to_exactly_one_worker() -> None:
    bus = Bus()
    key = f"test:skiplock:{uuid4()}"
    env = _make_campaign_requested_envelope(idempotency_key=key)
    async with session_scope() as session:
        await bus.emit(session, env)
        await session.commit()

    async def _try_claim(worker_id: str) -> UUID | None:
        async with session_scope() as session:
            claimed = await bus.claim_next(
                session,
                to_agent="orchestrator",
                visibility_timeout_seconds=60,
                worker_id=worker_id,
            )
            await session.commit()
        return claimed.message_id if claimed else None

    results = await asyncio.gather(_try_claim("w-A"), _try_claim("w-B"))
    winners = [r for r in results if r is not None]
    losers = [r for r in results if r is None]
    assert len(winners) == 1, f"expected exactly one claimer, got {results!r}"
    assert len(losers) == 1


# ---------------------------------------------------------------------------
# Visibility-timeout reclaim
# ---------------------------------------------------------------------------


async def test_visibility_timeout_lets_another_worker_reclaim() -> None:
    bus = Bus()
    key = f"test:vt:{uuid4()}"
    env = _make_campaign_requested_envelope(idempotency_key=key)
    async with session_scope() as session:
        await bus.emit(session, env)
        await session.commit()

    # Worker A claims with a 1-second visibility timeout, then never acks.
    async with session_scope() as session:
        claim_a = await bus.claim_next(
            session,
            to_agent="orchestrator",
            visibility_timeout_seconds=1,
            worker_id="worker-A",
        )
        await session.commit()
    assert claim_a is not None
    assert claim_a.attempts == 1

    # Wait past the visibility deadline, then Worker B reclaims.
    await asyncio.sleep(1.5)

    async with session_scope() as session:
        claim_b = await bus.claim_next(
            session,
            to_agent="orchestrator",
            visibility_timeout_seconds=60,
            worker_id="worker-B",
        )
        await session.commit()
    assert claim_b is not None
    assert claim_b.message_id == claim_a.message_id
    assert claim_b.attempts == 2


# ---------------------------------------------------------------------------
# Dead-letter
# ---------------------------------------------------------------------------


async def test_dead_letter_pushes_visible_after_and_creates_dl_row() -> None:
    bus = Bus()
    key = f"test:dl:{uuid4()}"
    env = _make_campaign_requested_envelope(idempotency_key=key)
    async with session_scope() as session:
        msg_id = await bus.emit(session, env)
        await session.commit()
    assert msg_id is not None

    async with session_scope() as session:
        await bus.dead_letter(
            session,
            msg_id,
            to_agent="orchestrator",
            kind=MessageKind.CAMPAIGN_REQUESTED.value,
            last_error="boom",
        )
        await session.commit()

    async with session_scope() as session:
        # The agent_messages row stays around — visible_after is pushed
        # far into the future so claim_next won't pick it up.
        row = (
            await session.execute(
                text("SELECT visible_after, last_error FROM agent_messages WHERE id = :id"),
                {"id": msg_id},
            )
        ).first()
        assert row is not None
        # "Far future" = +10 years, so well past any sane test runtime.
        assert (
            await session.execute(
                text(
                    "SELECT visible_after > now() + interval '5 years' "
                    "FROM agent_messages WHERE id = :id"
                ),
                {"id": msg_id},
            )
        ).scalar_one() is True
        assert row.last_error == "boom"

        dl_count = (
            await session.execute(
                text("SELECT count(*) AS n FROM agent_dead_letters WHERE message_id = :id"),
                {"id": msg_id},
            )
        ).scalar_one()
        assert dl_count == 1

        # And a regular claim_next must not see it.
        claim = await bus.claim_next(
            session,
            to_agent="orchestrator",
            visibility_timeout_seconds=60,
            worker_id="post-dl",
        )
        assert claim is None


# ---------------------------------------------------------------------------
# requeue_dead_letter
# ---------------------------------------------------------------------------


async def test_requeue_dead_letter_brings_message_back_to_inbox() -> None:
    bus = Bus()
    key = f"test:requeue:{uuid4()}"
    env = _make_campaign_requested_envelope(idempotency_key=key)

    async with session_scope() as session:
        msg_id = await bus.emit(session, env)
        await session.commit()
    assert msg_id is not None

    async with session_scope() as session:
        await bus.dead_letter(
            session,
            msg_id,
            to_agent="orchestrator",
            kind=MessageKind.CAMPAIGN_REQUESTED.value,
            last_error="transient outage",
        )
        await session.commit()

    async with session_scope() as session:
        dl_id = (
            await session.execute(
                text("SELECT id FROM agent_dead_letters WHERE message_id = :id"),
                {"id": msg_id},
            )
        ).scalar_one()

    async with session_scope() as session:
        requeued = await bus.requeue_dead_letter(session, dl_id, operator="test-op")
        await session.commit()
    assert requeued == msg_id

    # The agent_messages row is now claimable again with attempts reset.
    async with session_scope() as session:
        am_row = (
            await session.execute(
                text(
                    "SELECT attempts, consumed_at, last_error, "
                    "       visible_after <= now() AS is_visible "
                    "FROM agent_messages WHERE id = :id"
                ),
                {"id": msg_id},
            )
        ).first()
        assert am_row is not None
        assert am_row.attempts == 0
        assert am_row.consumed_at is None
        assert am_row.last_error is None
        assert am_row.is_visible is True

        dl_row = (
            await session.execute(
                text("SELECT requeued_at, requeued_by FROM agent_dead_letters WHERE id = :id"),
                {"id": dl_id},
            )
        ).first()
        assert dl_row is not None
        assert dl_row.requeued_at is not None
        assert dl_row.requeued_by == "test-op"

        # And it really is claimable.
        claim = await bus.claim_next(
            session,
            to_agent="orchestrator",
            visibility_timeout_seconds=60,
            worker_id="post-requeue",
        )
        assert claim is not None
        assert claim.message_id == msg_id


# ---------------------------------------------------------------------------
# inbox_depth
# ---------------------------------------------------------------------------


async def test_inbox_depth_counts_only_ready_unconsumed_messages() -> None:
    bus = Bus()
    keys = [f"test:depth:{i}:{uuid4()}" for i in range(3)]

    async with session_scope() as session:
        for k in keys:
            env = _make_campaign_requested_envelope(idempotency_key=k, to_agent="judge")
            await bus.emit(session, env)
        await session.commit()

    async with session_scope() as session:
        depth = await bus.inbox_depth(session, "judge")
    assert depth == 3

    # Claim one — the inbox depth should drop by 1.
    async with session_scope() as session:
        claimed = await bus.claim_next(
            session,
            to_agent="judge",
            visibility_timeout_seconds=60,
            worker_id="depth-worker",
        )
        await session.commit()
    assert claimed is not None

    async with session_scope() as session:
        depth_after = await bus.inbox_depth(session, "judge")
    assert depth_after == 2


# ---------------------------------------------------------------------------
# touch_claim — long-running handlers extend their bus claim mid-flight.
# ---------------------------------------------------------------------------


async def test_touch_claim_extends_visible_after_for_current_owner() -> None:
    """A handler that owns the claim can push ``visible_after`` further
    into the future without re-entering claim_next. After the touch,
    another worker still can't claim the row."""
    bus = Bus()
    key = f"test:touch:{uuid4()}"
    env = _make_campaign_requested_envelope(idempotency_key=key, to_agent="judge")

    async with session_scope() as session:
        await bus.emit(session, env)
        await session.commit()

    async with session_scope() as session:
        claimed = await bus.claim_next(
            session,
            to_agent="judge",
            visibility_timeout_seconds=2,  # short for the test
            worker_id="touch-owner",
        )
        await session.commit()
    assert claimed is not None

    # Read visible_after right after the claim.
    async with session_scope() as session:
        before_row = (
            await session.execute(
                text("SELECT visible_after FROM agent_messages WHERE id = :id"),
                {"id": claimed.message_id},
            )
        ).first()
    assert before_row is not None
    before_visible = before_row.visible_after

    # Touch with an extension well past the original 2s.
    async with session_scope() as session:
        ok = await bus.touch_claim(
            session,
            claimed.message_id,
            worker_id="touch-owner",
            extend_seconds=300,
        )
        await session.commit()
    assert ok is True

    async with session_scope() as session:
        after_row = (
            await session.execute(
                text("SELECT visible_after FROM agent_messages WHERE id = :id"),
                {"id": claimed.message_id},
            )
        ).first()
    assert after_row is not None
    assert after_row.visible_after > before_visible

    # A different worker cannot claim it right now (visible_after pushed
    # 5 min out by the touch).
    async with session_scope() as session:
        intruder = await bus.claim_next(
            session,
            to_agent="judge",
            visibility_timeout_seconds=60,
            worker_id="intruder",
        )
        await session.commit()
    assert intruder is None


async def test_touch_claim_returns_false_when_claim_was_lost() -> None:
    """If a worker's claim has been re-delivered to another worker
    (visible_after elapsed, second worker claimed), the original
    owner's touch returns False and is a no-op. This is the signal
    the handler uses to abort safely without acking work the other
    worker is now redoing."""
    bus = Bus()
    key = f"test:touch_lost:{uuid4()}"
    env = _make_campaign_requested_envelope(idempotency_key=key, to_agent="judge")

    async with session_scope() as session:
        await bus.emit(session, env)
        await session.commit()

    # Worker A claims with a 1s visibility timeout.
    async with session_scope() as session:
        a_claim = await bus.claim_next(
            session,
            to_agent="judge",
            visibility_timeout_seconds=1,
            worker_id="worker-a",
        )
        await session.commit()
    assert a_claim is not None

    # Let the visibility timeout elapse + worker B claims.
    await asyncio.sleep(1.5)
    async with session_scope() as session:
        b_claim = await bus.claim_next(
            session,
            to_agent="judge",
            visibility_timeout_seconds=60,
            worker_id="worker-b",
        )
        await session.commit()
    assert b_claim is not None
    assert b_claim.message_id == a_claim.message_id

    # Worker A's touch now fails — B owns it.
    async with session_scope() as session:
        ok = await bus.touch_claim(
            session,
            a_claim.message_id,
            worker_id="worker-a",
            extend_seconds=300,
        )
        await session.commit()
    assert ok is False


async def test_touch_claim_is_a_no_op_after_ack() -> None:
    """Touching an already-acked message returns False — once consumed,
    the row is terminal and shouldn't be extended."""
    bus = Bus()
    key = f"test:touch_acked:{uuid4()}"
    env = _make_campaign_requested_envelope(idempotency_key=key, to_agent="judge")

    async with session_scope() as session:
        await bus.emit(session, env)
        await session.commit()

    async with session_scope() as session:
        claimed = await bus.claim_next(
            session,
            to_agent="judge",
            visibility_timeout_seconds=60,
            worker_id="touch-acked",
        )
        assert claimed is not None
        await bus.ack(session, claimed.message_id)
        await session.commit()

    async with session_scope() as session:
        ok = await bus.touch_claim(
            session,
            claimed.message_id,
            worker_id="touch-acked",
            extend_seconds=300,
        )
        await session.commit()
    assert ok is False
