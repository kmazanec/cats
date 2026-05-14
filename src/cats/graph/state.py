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
    # OpenEMR patient (pid) this run attacks against. Chosen per-run by
    # ``red_team.patient_selection.choose_pid_for_run`` so attacks vary
    # chart contents across runs in a campaign. Zero means "fall back to
    # TargetClient's default" (legacy paths that haven't been threaded
    # through patient selection yet).
    target_pid: int = 0

    # Briefing kickoff — fired once per Run before any attack. The
    # Co-Pilot's `default_briefing` task discards the user `question`,
    # so the kickoff harvests the server-minted conversationId that
    # every subsequent `follow_up` attack rides against. Empty until
    # the kickoff node runs (smoke mode skips it).
    kickoff_conversation_id: str = ""

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

    # R3 — multi-technique inner loop bookkeeping.
    # ``techniques_attempted`` accumulates the keys the dispatcher has
    # picked so far this campaign; the outer loop drives until this
    # reaches ``MIN_TECHNIQUES_PER_CAMPAIGN`` (or the budget runs out).
    # ``consecutive_partial_count`` is incremented by the mutator when
    # the judge rules ``partial`` and reset whenever the verdict changes
    # — bounds the partial→mutate cycle at ``MAX_CONSECUTIVE_PARTIALS``.
    techniques_attempted: list[str] = Field(default_factory=list)
    consecutive_partial_count: int = 0
    current_outer_iteration: int = 0

    # Test hooks — the smoke path sets these so nodes know to take the
    # canned paths.
    smoke_mode: bool = False
