"""Per-agent worker liveness derived from the `worker_heartbeats` table.

Each long-running worker (orchestrator / red_team / judge / documentation)
UPSERTs a row into `worker_heartbeats` every ``HEARTBEAT_INTERVAL_SECONDS``
(see ``cats.messaging.worker``). A worker is considered healthy if its most
recent heartbeat is newer than ``2 * visibility_timeout_seconds`` for that
agent — the factor of two gives one full visibility-timeout window of slack
before we declare a worker stale.

Thresholds are intentionally hardcoded here rather than imported from the
worker classes — reaching into ``cats.agents.*`` from the health module
creates a circular import. Keep these in sync with ARCHITECTURE.md §2.7.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from cats.db.engine import session_scope
from cats.db.schema import worker_heartbeats

# Worker name → stale-after threshold in seconds.
# Tracks ARCHITECTURE.md §2.7 (2 * visibility_timeout_seconds).
#   orchestrator / red_team: visibility_timeout=300s  → stale after 600s
#   judge / documentation:   visibility_timeout=60s   → stale after 120s
WORKER_STALE_AFTER_SECONDS: dict[str, int] = {
    "orchestrator": 600,
    "red_team": 600,
    "judge": 120,
    "documentation": 120,
}


@dataclass(frozen=True)
class WorkerHealth:
    name: str
    healthy: bool
    last_beat_at: datetime | None
    host_pid: str | None
    stale_seconds: int | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "healthy": self.healthy,
            "last_beat_at": (
                self.last_beat_at.astimezone(UTC).isoformat().replace("+00:00", "Z")
                if self.last_beat_at is not None
                else None
            ),
            "host_pid": self.host_pid,
            "stale_seconds": self.stale_seconds,
        }


async def check_workers(*, now: datetime | None = None) -> dict[str, WorkerHealth]:
    """Read the most recent heartbeat per worker_name and decide health.

    When multiple ``host_pid`` rows exist for one ``worker_name`` (e.g. a
    rolling deploy left an old replica around), we report the freshest row.
    """
    current = now if now is not None else datetime.now(UTC)
    # Fetch every known worker's most-recent row in a single round trip.
    stmt = select(
        worker_heartbeats.c.worker_name,
        worker_heartbeats.c.host_pid,
        worker_heartbeats.c.last_beat_at,
    ).where(worker_heartbeats.c.worker_name.in_(list(WORKER_STALE_AFTER_SECONDS)))
    async with session_scope() as session:
        rows = (await session.execute(stmt)).all()

    # Pick the freshest row per worker_name.
    freshest: dict[str, tuple[str, datetime]] = {}
    for worker_name, host_pid, last_beat_at in rows:
        existing = freshest.get(worker_name)
        if existing is None or last_beat_at > existing[1]:
            freshest[worker_name] = (host_pid, last_beat_at)

    out: dict[str, WorkerHealth] = {}
    for name, threshold in WORKER_STALE_AFTER_SECONDS.items():
        row = freshest.get(name)
        if row is None:
            out[name] = WorkerHealth(
                name=name,
                healthy=False,
                last_beat_at=None,
                host_pid=None,
                stale_seconds=None,
            )
            continue
        host_pid, last_beat_at = row
        # Normalize naive datetimes to UTC (Postgres returns tz-aware via
        # the schema; this is just defensive).
        if last_beat_at.tzinfo is None:
            last_beat_at = last_beat_at.replace(tzinfo=UTC)
        stale = int((current - last_beat_at).total_seconds())
        out[name] = WorkerHealth(
            name=name,
            healthy=stale <= threshold,
            last_beat_at=last_beat_at,
            host_pid=host_pid,
            stale_seconds=max(stale, 0),
        )
    return out


def workers_all_healthy(workers: dict[str, WorkerHealth]) -> bool:
    """True iff every known worker has a fresh heartbeat."""
    return all(w.healthy for w in workers.values())
