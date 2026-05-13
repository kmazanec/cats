"""Worker base class.

Every agent's process-mode entry point inherits from :class:`Worker`.
The base owns:

- the LISTEN/NOTIFY wake-up loop with a slow-poll safety net,
- visibility-timeout-driven claim / ack / nack semantics,
- exponential-backoff retry up to ``MAX_ATTEMPTS_BEFORE_DEAD_LETTER``,
- the per-worker heartbeat row,
- graceful shutdown on SIGTERM / SIGINT.

Subclasses implement :meth:`handle` for one claimed message. They do
NOT manage sessions, retries, or NOTIFY — those are the base's job.
"""

from __future__ import annotations

import abc
import asyncio
import contextlib
import os
import platform
import signal
import socket
from collections.abc import AsyncIterator
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from cats.db.engine import get_engine, session_scope
from cats.db.schema import worker_heartbeats
from cats.logging import get_logger
from cats.messaging.bus import Bus, ClaimedMessage

MAX_ATTEMPTS_BEFORE_DEAD_LETTER: int = 5
POLL_INTERVAL_SECONDS: float = 1.0
LISTEN_WAIT_SECONDS: float = 30.0
HEARTBEAT_INTERVAL_SECONDS: float = 5.0


def _worker_id() -> str:
    """Stable identifier for forensics — host + pid."""
    host = socket.gethostname()
    return f"{host}:{os.getpid()}"


def _backoff_for(attempt: int) -> int:
    """Exponential backoff capped at 60s. ``attempt`` is 1-indexed
    (the value already incremented by ``claim_next``)."""
    return int(min(60, 2 ** max(0, attempt - 1)))


class Worker(abc.ABC):
    """Subclass for each of the four agents.

    The handler returns normally to ack, raises to nack-with-backoff,
    or raises :class:`PermanentHandlerError` to dead-letter immediately
    without further retries.
    """

    #: Name used as ``to_agent`` for the inbox. Concrete subclasses
    #: override.
    agent_name: str = ""

    #: Visibility timeout in seconds. Defaults to ARCHITECTURE.md §2.7:
    #: 60s for Judge / Documentation, 300s for the LLM-driven agents
    #: (Orchestrator + Red Team).
    visibility_timeout_seconds: int = 60

    def __init__(self) -> None:
        if not self.agent_name:
            raise RuntimeError(f"{type(self).__name__} must set agent_name (e.g. 'judge')")
        self._stop_event = asyncio.Event()
        self._bus = Bus()
        self._worker_id = _worker_id()
        self._log = get_logger(f"cats.workers.{self.agent_name}")

    # ------------------------------------------------------------------
    # Subclass hook
    # ------------------------------------------------------------------

    @abc.abstractmethod
    async def handle(self, session: AsyncSession, message: ClaimedMessage) -> None:
        """Process one claimed message. Side effects + any new
        envelopes to emit happen in ``session``; the base commits on
        return and rolls back on exception."""

    async def touch_claim(self, message_id: UUID, *, extend_seconds: int | None = None) -> bool:
        """Extend the visibility timeout on the message this handler
        is processing. Use it from a long-running handler (e.g. an LLM
        tool loop) to keep your claim alive without raising the
        worker class's static ``visibility_timeout_seconds``.

        Returns ``True`` if the touch landed; ``False`` if another
        worker already stole the claim (handler should abort and let
        the other worker finish).

        Runs in a *separate* short-lived session because the handler's
        long-running session has an open transaction — the UPDATE
        needs to commit immediately so a parallel ``claim_next``
        sees the new ``visible_after``."""
        extend = extend_seconds if extend_seconds is not None else self.visibility_timeout_seconds
        async with session_scope() as touch_session:
            ok = await self._bus.touch_claim(
                touch_session,
                message_id,
                worker_id=self._worker_id,
                extend_seconds=extend,
            )
            await touch_session.commit()
            return ok

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def request_stop(self) -> None:
        """External shutdown trigger. The run loop exits at the next
        wake without claiming new work."""
        self._stop_event.set()

    async def run(self) -> None:
        """Main loop. Polls + listens until stop is requested."""
        self._install_signal_handlers()
        self._log.info("worker.start", worker_id=self._worker_id)
        heartbeat = asyncio.create_task(self._heartbeat_loop(), name=f"hb-{self.agent_name}")
        notify_task = asyncio.create_task(self._notify_listener(), name=f"notify-{self.agent_name}")
        try:
            while not self._stop_event.is_set():
                claimed = await self._claim_and_handle_one()
                if not claimed:
                    # Idle — wait for NOTIFY or poll interval.
                    with contextlib.suppress(TimeoutError):
                        await asyncio.wait_for(
                            self._stop_event.wait(),
                            timeout=POLL_INTERVAL_SECONDS,
                        )
        finally:
            heartbeat.cancel()
            notify_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await heartbeat
            with contextlib.suppress(asyncio.CancelledError):
                await notify_task
            self._log.info("worker.stop", worker_id=self._worker_id)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _claim_and_handle_one(self) -> bool:
        """Pull one message, run :meth:`handle`. Returns True if we
        actually processed one (so the caller skips the idle wait)."""
        async with session_scope() as session:
            claimed = await self._bus.claim_next(
                session,
                to_agent=self.agent_name,
                visibility_timeout_seconds=self.visibility_timeout_seconds,
                worker_id=self._worker_id,
            )
            if claimed is None:
                await session.commit()
                return False
            # Hold the claim open for the whole handler — same
            # transaction, so the side effects + ack are atomic.
            try:
                await self.handle(session, claimed)
            except PermanentHandlerError as exc:
                self._log.exception(
                    "worker.permanent_failure",
                    message_id=str(claimed.message_id),
                    kind=claimed.kind.value,
                    error=repr(exc),
                )
                await session.rollback()
                # Dead-letter writes need their own session because the
                # claim's session has been rolled back.
                await self._dead_letter(claimed, repr(exc))
                return True
            except Exception as exc:
                self._log.exception(
                    "worker.handle_failed",
                    message_id=str(claimed.message_id),
                    kind=claimed.kind.value,
                    attempts=claimed.attempts,
                    error=repr(exc),
                )
                await session.rollback()
                # If we just hit the cap, dead-letter; otherwise nack
                # with backoff.
                if claimed.attempts >= MAX_ATTEMPTS_BEFORE_DEAD_LETTER:
                    await self._dead_letter(claimed, repr(exc))
                else:
                    await self._nack(claimed, repr(exc))
                return True
            else:
                await self._bus.ack(session, claimed.message_id)
                await session.commit()
                return True

    async def _nack(self, claimed: ClaimedMessage, err: str) -> None:
        async with session_scope() as session:
            await self._bus.nack(
                session,
                claimed.message_id,
                last_error=err,
                backoff_seconds=_backoff_for(claimed.attempts),
            )
            await session.commit()

    async def _dead_letter(self, claimed: ClaimedMessage, err: str) -> None:
        async with session_scope() as session:
            await self._bus.dead_letter(
                session,
                claimed.message_id,
                to_agent=claimed.to_agent,
                kind=claimed.kind.value,
                last_error=err,
            )
            await session.commit()

    async def _heartbeat_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                async with session_scope() as session:
                    await self._write_heartbeat(session)
                    await session.commit()
            except Exception as exc:
                self._log.warning("worker.heartbeat_failed", error=repr(exc))
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._stop_event.wait(), timeout=HEARTBEAT_INTERVAL_SECONDS)

    async def _write_heartbeat(self, session: AsyncSession) -> None:
        # UPSERT keyed by (worker_name, host_pid).
        await session.execute(
            text(
                """
                INSERT INTO worker_heartbeats (worker_name, host_pid, last_beat_at)
                VALUES (:name, :pid, now())
                ON CONFLICT (worker_name, host_pid)
                DO UPDATE SET last_beat_at = now()
                """
            ),
            {"name": self.agent_name, "pid": self._worker_id},
        )

    async def _notify_listener(self) -> None:
        """Subscribe to LISTEN on this agent's channel so an emit
        wakes us instantly rather than waiting for the poll interval.

        Uses asyncpg directly because SQLAlchemy's async engine does
        not surface notification streams. A dropped connection is
        non-fatal: the polling loop is the safety net.
        """
        channel = f"cats_bus_{self.agent_name}"
        while not self._stop_event.is_set():
            try:
                async for _ in self._listen_iter(channel):
                    if self._stop_event.is_set():
                        return
            except Exception as exc:  # connection died, etc.
                self._log.debug("worker.listen_loop_error", error=repr(exc))
                # back off briefly so a flapping DB doesn't tight-loop.
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(self._stop_event.wait(), timeout=1.0)

    async def _listen_iter(self, channel: str) -> AsyncIterator[Any]:
        """Yield once per NOTIFY received (or once per poll interval).

        Implemented via the engine's raw asyncpg connection. The
        actual wake-up signal is fed back through the main loop's
        poll cycle — we just need *something* to break the wait early.
        """
        engine = get_engine()
        raw_conn = await engine.raw_connection()
        try:
            asyncpg_conn = raw_conn.driver_connection
            if asyncpg_conn is None:  # pragma: no cover
                return
            queue: asyncio.Queue[None] = asyncio.Queue()

            def _on_notify(*_: Any) -> None:
                with contextlib.suppress(asyncio.QueueFull):  # pragma: no cover
                    queue.put_nowait(None)

            await asyncpg_conn.add_listener(channel, _on_notify)
            try:
                while not self._stop_event.is_set():
                    try:
                        await asyncio.wait_for(queue.get(), timeout=LISTEN_WAIT_SECONDS)
                    except TimeoutError:
                        continue
                    # Drain any backlog without yielding for each so the
                    # main loop sees one wake per batch.
                    while not queue.empty():
                        queue.get_nowait()
                    yield None
            finally:
                with contextlib.suppress(Exception):
                    await asyncpg_conn.remove_listener(channel, _on_notify)
        finally:
            with contextlib.suppress(Exception):
                # PoolProxiedConnection.close() is sync and returns None.
                raw_conn.close()

    # ------------------------------------------------------------------
    # Signal handling
    # ------------------------------------------------------------------

    def _install_signal_handlers(self) -> None:
        if platform.system() == "Windows":
            return  # pragma: no cover
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            with contextlib.suppress(NotImplementedError):
                loop.add_signal_handler(sig, self.request_stop)


class PermanentHandlerError(Exception):
    """Raise from :meth:`Worker.handle` to dead-letter immediately
    without further retries. Use for contract violations the handler
    cannot recover from no matter how many times we retry — unknown
    rubric version, malformed payload that passed schema validation
    but is semantically broken, etc.
    """


# Helper for the heartbeat-aware healthz check.
worker_heartbeats_table = worker_heartbeats
