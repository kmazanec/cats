from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class AuditLogEntry(BaseModel):
    """Append-only at the DB layer (revoke UPDATE/DELETE + deny trigger).

    Every campaign start, every authorization decision, every
    critical-severity approval, every white-hat source read lands here.
    """

    id: UUID = Field(default_factory=uuid4)
    actor: str
    action: str
    target_kind: str  # "project" | "campaign" | "run" | "finding" | "report" | ...
    target_id: UUID | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    trace_id: str | None = None
    at: datetime = Field(default_factory=lambda: datetime.now(UTC))
