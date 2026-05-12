from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class ProjectVersion(BaseModel):
    """The version of the target a particular AttackExecution ran against.

    Lets the same Attack template be re-fired against later deploys for
    regression purposes."""

    id: UUID = Field(default_factory=uuid4)
    project_id: UUID
    git_sha: str | None = None
    label: str = ""
    deployed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
