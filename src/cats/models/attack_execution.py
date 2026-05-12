from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

OutputFilterVerdict = Literal["safe", "attack_payload", "dangerous"]


class AttackExecution(BaseModel):
    """One firing of an Attack against a specific ProjectVersion inside a
    specific Run. The Attack template is reusable; this record is the audit
    trail of *that* firing.
    """

    id: UUID = Field(default_factory=uuid4)
    run_id: UUID
    attack_id: UUID
    project_version_id: UUID

    target_response: dict[str, Any] = Field(default_factory=dict)
    target_latency_ms: int | None = None
    target_status_code: int | None = None

    output_filter_verdict: OutputFilterVerdict = "safe"
    output_filter_reason: str = ""

    judge_verdict_id: UUID | None = None

    tokens_in: int = 0
    tokens_out: int = 0
    model: str = ""
    usd_estimate: float = 0.0

    langsmith_trace_id: str | None = None
    error: str | None = None

    started_at: datetime | None = None
    ended_at: datetime | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
