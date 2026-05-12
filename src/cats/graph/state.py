"""Typed graph state. Pydantic so we get validation; LangGraph also accepts
TypedDict, but pydantic is the same shape we use everywhere else."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class CampaignState(BaseModel):
    """State carried between LangGraph nodes for one Run."""

    run_id: UUID
    campaign_id: UUID
    project_version_id: UUID

    # Inner-loop scratch
    selected_category: str | None = None
    pending_attack_id: UUID | None = None
    pending_attack_payload: dict[str, Any] = Field(default_factory=dict)
    pending_attack_title: str = ""
    pending_attack_signature: str = ""

    last_target_response: dict[str, Any] = Field(default_factory=dict)
    last_verdict_id: UUID | None = None
    last_verdict: str | None = None

    output_filter_verdict: str = "safe"
    output_filter_reason: str = ""

    # Bookkeeping
    attacks_fired: int = 0
    budget_consumed_usd: float = 0.0
    consecutive_fail_count: int = 0
    halted_reason: str | None = None

    # For testability — the smoke path sets this so node stubs don't have to
    # call into the real LLM client / target.
    smoke_mode: bool = False
