from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class VulnerabilityReport(BaseModel):
    """The Documentation Agent's human-readable artifact. One per Run.

    Critical-severity reports pause for human approval before they leave
    `draft` status (see §2.4)."""

    id: UUID = Field(default_factory=uuid4)
    run_id: UUID  # 1:1 with Run; unique constraint at the DB layer
    title: str
    body_markdown: str
    requires_approval: bool = False
    approved_by: str | None = None
    approved_at: datetime | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
