from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

RunStatus = Literal["pending", "running", "completed", "failed", "halted"]


class Run(BaseModel):
    """One concrete execution of a Campaign against one ProjectVersion."""

    id: UUID = Field(default_factory=uuid4)
    campaign_id: UUID
    project_version_id: UUID
    status: RunStatus = "pending"
    started_at: datetime | None = None
    ended_at: datetime | None = None
    budget_consumed_usd: float = 0.0
    attacks_fired: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
