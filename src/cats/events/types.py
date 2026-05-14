from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field

EventKind = Literal[
    "campaign_started",
    "run_started",
    "attack_proposed",
    # Transient: emitted just before the Red Team fires the target so
    # the UI can show "attacking…" instead of a 30s blank stretch.
    # Not persisted; the campaign timeline only replays attack_executed.
    "attack_starting",
    # R10-follow-up — emitted by the Red Team worker when it starts a
    # new PlanAttempt inside an already-running agent session (one run
    # row, N attempts inside). Lets the UI flip the per-attempt header
    # without waiting for the first attack_executed event.
    "attempt_started",
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
    # End-of-campaign rollup report from the Documentation Agent. The
    # campaign-detail page subscribes to flip the "Report: pending"
    # pill to a deep-link as soon as the writer finishes.
    "campaign_report_generated",
    # R8 — regression-verification sweep lifecycle. The /regressions
    # page listens for these to flip per-case rows from "running" to
    # the gate-by-gate verdict without a manual refresh.
    "regression_sweep_started",
    "regression_case_finished",
    "regression_sweep_finished",
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
