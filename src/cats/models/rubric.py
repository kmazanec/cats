from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class RubricVersion(BaseModel):
    """A locked rubric prompt for a category. Bumping a rubric is a new row;
    old verdicts keep pointing at the version that produced them, so the
    standard doesn't shift under us."""

    id: UUID = Field(default_factory=uuid4)
    category: str
    version: int = 1
    prompt_text: str
    locked_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
