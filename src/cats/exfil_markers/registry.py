"""In-process registry of planted markers.

Each :class:`MarkerRecord` answers the four questions a leak investigation
needs to resolve:

- *what* token was planted (``value``)
- *where* it was planted (``patient_id``, ``location`` — chart note,
  problem-list entry, etc.)
- *who* planted it (``run_id``, ``attack_id``)
- *when* (``planted_at``)

The registry is process-local. R6's manual-run flow and unit tests do not
require durability; if a future round needs cross-process planting (e.g.
regression harness re-plants between releases), the same shape lifts to a
Postgres table with no API change.
"""

from __future__ import annotations

import threading
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID


@dataclass(frozen=True)
class MarkerRecord:
    value: str
    patient_id: str
    location: str
    run_id: UUID | None = None
    attack_id: UUID | None = None
    planted_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    notes: str = ""


class MarkerRegistry:
    """Thread-safe in-memory store of planted markers."""

    def __init__(self) -> None:
        self._by_value: dict[str, MarkerRecord] = {}
        self._lock = threading.Lock()

    def plant(self, record: MarkerRecord) -> None:
        """Record that ``record.value`` was planted. Overwrites a prior entry
        for the same value (replanting is legitimate; the latest plant wins)."""
        with self._lock:
            self._by_value[record.value] = record

    def get(self, value: str) -> MarkerRecord | None:
        with self._lock:
            return self._by_value.get(value)

    def all(self) -> list[MarkerRecord]:
        with self._lock:
            return list(self._by_value.values())

    def for_patient(self, patient_id: str) -> list[MarkerRecord]:
        with self._lock:
            return [r for r in self._by_value.values() if r.patient_id == patient_id]

    def values(self) -> Iterable[str]:
        with self._lock:
            return list(self._by_value.keys())

    def clear(self) -> None:
        with self._lock:
            self._by_value.clear()


_default = MarkerRegistry()


def get_default_registry() -> MarkerRegistry:
    """Process-wide default registry. Tests should call ``.clear()`` between
    cases or construct their own :class:`MarkerRegistry`."""
    return _default
