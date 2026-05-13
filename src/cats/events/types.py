from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field

EventKind = Literal[
    "campaign_started",
    "run_started",
    "attack_proposed",
    "attack_executed",
    "judge_verdict_rendered",
    "finding_promoted",
    "run_completed",
    "campaign_halted",
    # R4 — Orchestrator plan lifecycle. The campaign-detail page
    # listens on these to flip the "Plan: Pending Approval" pill and
    # surface the "plan ready" CTA without a manual refresh.
    "campaign_requested",
    "plan_proposed",
    "plan_approved",
    "plan_failed",
]


class EventEnvelope(BaseModel):
    kind: EventKind
    campaign_id: UUID | None = None
    run_id: UUID | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def channel(self) -> str:
        if self.campaign_id:
            return f"campaign:{self.campaign_id}"
        return "global"
