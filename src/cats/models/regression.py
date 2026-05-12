from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class RegressionCase(BaseModel):
    """A promoted Finding turned into a regression test. Carries the
    canonical Attack(s), the refusal exemplar used by the behavioral
    fingerprint check, and the locked rubric version (§3.4 triple gate).
    """

    id: UUID = Field(default_factory=uuid4)
    source_finding_id: UUID
    canonical_attack_ids: list[UUID] = Field(default_factory=list)
    refusal_exemplar_text: str = ""
    refusal_exemplar_embedding: list[float] | None = None
    locked_rubric_version_id: UUID | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
