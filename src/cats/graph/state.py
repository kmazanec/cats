"""Typed graph state. Pydantic so we get validation; LangGraph also
accepts TypedDict, but pydantic matches the shape we use everywhere else.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class AgentCostEntry(BaseModel):
    """Per-agent cost line for the campaign view. Each LLM-using node
    appends one of these when it makes a call."""

    model_config = ConfigDict(frozen=True)

    role: str
    model: str
    tokens_in: int = 0
    tokens_out: int = 0
    usd: float = 0.0


class CampaignState(BaseModel):
    """State carried between LangGraph nodes for one Run."""

    run_id: UUID
    campaign_id: UUID
    project_version_id: UUID
    project_id: UUID | None = None

    # Target config — set by the worker at run start so nodes don't have
    # to hit the DB again.
    target_base_url: str = ""
    target_kind: str = "copilot_proxy"
    target_username: str = ""
    target_password: str = ""
    target_bearer_token: str = ""

    # Inner-loop scratch
    selected_category: str = "injection"
    selected_technique: str = ""
    pending_attack_id: UUID | None = None
    pending_attack_payload: dict[str, Any] = Field(default_factory=dict)
    pending_attack_title: str = ""
    pending_attack_description: str = ""
    pending_attack_signature: str = ""
    pending_canary: str = ""

    last_target_response: dict[str, Any] = Field(default_factory=dict)
    last_target_text: str = ""
    last_target_status_code: int = 0
    last_target_latency_ms: int = 0

    last_verdict_id: UUID | None = None
    last_verdict: str | None = None
    last_verdict_rationale: str = ""
    last_verdict_evidence: dict[str, Any] = Field(default_factory=dict)
    last_verdict_is_deterministic: bool = False
    last_verdict_model: str = ""
    last_rubric_version_id: UUID | None = None

    output_filter_verdict: str = "safe"
    output_filter_reason: str = ""

    # Bookkeeping
    attacks_fired: int = 0
    budget_consumed_usd: float = 0.0
    consecutive_fail_count: int = 0
    halted_reason: str | None = None
    per_agent_costs: list[AgentCostEntry] = Field(default_factory=list)
    finding_id: UUID | None = None
    report_id: UUID | None = None
    last_trace_id: str = ""

    # Test hooks — the smoke path sets these so nodes know to take the
    # canned paths.
    smoke_mode: bool = False
