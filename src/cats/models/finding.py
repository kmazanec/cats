from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high", "critical"]
Status = Literal["open", "triaged", "fixed", "regressed", "wont_fix"]


class Finding(BaseModel):
    """A vulnerability discovered within a Run. Aggregates one or more
    AttackExecutions that share a category+signature (e.g. mutator
    variants of the same root cause).

    Unique constraint at the DB layer: (run_id, category, signature)."""

    id: UUID = Field(default_factory=uuid4)
    run_id: UUID
    category: str
    signature: str
    severity: Severity = "medium"
    status: Status = "open"
    title: str
    summary: str = ""
    atlas_technique_id: str | None = None
    owasp_llm_id: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
