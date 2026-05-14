"""Typed envelope + the six payload kinds.

Each cross-agent handoff is one of the six :class:`MessageKind`
values. ``Envelope[T]`` carries the producer-supplied identifying
fields (idempotency key, trace id, campaign / attack ids) and the
typed payload. Schema changes go through a ``payload_version`` bump
plus a migration on existing rows.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Generic, Literal, TypeVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class MessageKind(StrEnum):
    """The cross-agent message kinds the bus carries."""

    CAMPAIGN_REQUESTED = "CampaignRequested"
    CAMPAIGN_PLAN_PROPOSED = "CampaignPlanProposed"
    CAMPAIGN_PLAN_APPROVED = "CampaignPlanApproved"
    ATTACK_EVENT = "AttackEvent"
    VERDICT_RENDERED = "VerdictRendered"
    FINDING_PROMOTED = "FindingPromoted"
    # Operator or platform asks Documentation to (re)render the
    # campaign-level rollup report. Producer is the Documentation
    # worker itself (auto-trigger when every run is terminal) or
    # the POST /campaigns/{id}/report route (manual regenerate).
    CAMPAIGN_REPORT_REQUESTED = "CampaignReportRequested"


AgentName = Literal[
    "trigger",
    "orchestrator",
    "red_team",
    "judge",
    "documentation",
    "operator",
    "system",
]


# ---------------------------------------------------------------------------
# Plan shape (CampaignPlan)
# ---------------------------------------------------------------------------


class PlanAttempt(BaseModel):
    """One attempt in the Orchestrator's plan. The Red Team walks
    attempts in order; each row supplies the specialist + per-attempt
    budget the executor uses.

    ``seeds_per_attempt`` is K — the number of distinct seed attacks
    the Red Team fires for this technique before moving on. Each seed
    re-calls the specialist with an elevated temperature and the
    prior seeds' user_messages threaded into the prompt, producing K
    materially different angles on the same technique. Default 5;
    bounded at 10 to keep blast radius predictable."""

    model_config = ConfigDict(extra="forbid")

    category: str
    technique: str
    per_attempt_budget_usd: float = Field(default=0.50, ge=0.0)
    max_consecutive_partials: int = Field(default=2, ge=0, le=10)
    seeds_per_attempt: int = Field(default=5, ge=1, le=10)


class PlannedCampaign(BaseModel):
    """The structured campaign plan the Orchestrator emits and the
    operator approves. Halt conditions are enforced by the Red Team
    executor; the rationale is shown to the operator at approval."""

    model_config = ConfigDict(extra="forbid")

    payload_version: int = 1
    attempts: list[PlanAttempt]
    rationale: str = ""
    confidence: str = ""
    halt_on_consecutive_fails: int = Field(default=3, ge=1, le=20)
    halt_on_judge_errors: int = Field(default=2, ge=1, le=10)
    budget_usd_cap: float = Field(default=5.0, ge=0.0)


# ---------------------------------------------------------------------------
# Per-kind payload schemas
# ---------------------------------------------------------------------------


class CampaignRequestedPayload(BaseModel):
    """trigger → Orchestrator. A new campaign asks for a plan.

    ``campaign_id`` is optional for backward compat — when omitted, the
    Orchestrator creates a new campaign row. When present (the API's
    flow), the Orchestrator uses the existing campaign rather than
    creating a duplicate. Trigger sources that don't already own a
    campaign row (e.g. a future webhook trigger) can still omit it.
    """

    model_config = ConfigDict(extra="forbid")

    payload_version: int = 1
    project_id: UUID
    project_version_id: UUID
    budget_usd: float = Field(ge=0.0)
    operator_user_id: UUID | None = None
    name: str = ""
    campaign_id: UUID | None = None


class CampaignPlanProposedPayload(BaseModel):
    """Orchestrator → operator (UI). The operator approves, edits, or
    rejects in the dashboard before any attack fires."""

    model_config = ConfigDict(extra="forbid")

    payload_version: int = 1
    campaign_id: UUID
    plan: PlannedCampaign
    tool_transcript: list[dict[str, object]] = Field(default_factory=list)
    plan_id: UUID


class CampaignPlanApprovedPayload(BaseModel):
    """operator (UI) → Red Team. The operator-approved (possibly
    edited) plan; the dispatch shell runs *this* plan, not the
    proposed one."""

    model_config = ConfigDict(extra="forbid")

    payload_version: int = 1
    campaign_id: UUID
    plan: PlannedCampaign
    proposed_plan: PlannedCampaign
    diff_summary: dict[str, object] = Field(default_factory=dict)
    approver_user_id: UUID | None = None
    plan_id: UUID
    project_version_id: UUID


class ConversationTurnPayload(BaseModel):
    """R10 — one turn of a multi-turn attack conversation. Bundled into
    :class:`AttackEventPayload.transcript` so the Judge sees the full
    conversation, not just the latest turn.

    ``attack_execution_id`` is the per-turn execution row; on a
    multi-turn finding the Judge can use it to attribute the decisive
    turn back to the precise execution the operator inspects."""

    model_config = ConfigDict(extra="forbid")

    seed_idx: int
    user_message: str
    target_response: str
    attack_execution_id: UUID
    target_status_code: int = 0
    target_error: str | None = None
    target_latency_ms: int = 0


class AttackEventPayload(BaseModel):
    """Red Team → Judge. One conversation against the live target.

    R10 — what used to be one envelope per (attack, response) pair is
    now one envelope per *conversation*. ``transcript`` carries every
    turn the Red Team chose to fire; the Judge rules over the whole
    transcript and returns a decisive turn index. The legacy
    ``payload`` / ``target_response`` / ``canary`` fields mirror the
    *last* turn (the one whose response triggered the conversation
    stop) so single-turn-aware consumers keep working.

    ``seed_idx`` distinguishes the K seeds the Red Team fires per plan
    attempt; ``iteration`` distinguishes Mutator variants of a single
    seed when the Judge keeps returning ``partial``. Together they
    namespace the idempotency key so retries dedupe correctly."""

    model_config = ConfigDict(extra="forbid")

    payload_version: int = 2  # R10 — added `transcript`.
    campaign_id: UUID
    run_id: UUID
    attack_id: UUID
    attack_execution_id: UUID
    category: str
    technique: str
    payload: str
    target_response: str
    canary: str = ""
    iteration: int = 0
    seed_idx: int = 0
    rubric_version_id: UUID | None = None
    # Target call outcome — lets the Judge short-circuit when the
    # target refused (HTTP 4xx/5xx, transport error). Without these the
    # Judge LLM sees an empty/error body and produces a generic `error`
    # verdict that the operator can't distinguish from a real "can't
    # decide" case. Both fields default so older queued envelopes still
    # decode after a worker upgrade.
    target_status_code: int = 0
    target_error: str | None = None
    # Wall-clock the target took to respond. Lets the Judge flag
    # cost-amplification / DoS signals (see W3_THREAT_RESEARCH §3.5,
    # §8.1-8.7) on its `evidence` payload without inventing a new
    # verdict tier. A full DoS attack family lives in a future round.
    target_latency_ms: int = 0
    # R10 — the full conversation the Red Team fired. Single-turn
    # callers leave this empty (the Judge falls back to the legacy
    # ``payload``/``target_response``/``canary`` triple). Multi-turn
    # callers populate every turn the Red Team chose to send.
    transcript: list[ConversationTurnPayload] = Field(default_factory=list)
    # R10 — stop reason from the Red Team's escalation decision:
    # ``cap_reached`` (seeds_per_attempt cap), ``stop`` (strategist said
    # stop), ``declare_landed`` (strategist said the vulnerability
    # landed), ``error`` (transport failure short-circuited the loop).
    # Surfaced on the campaign-detail UI; not load-bearing for the
    # Judge's verdict.
    conversation_stop_reason: str = ""


VerdictKind = Literal["pass", "fail", "partial", "error"]


class VerdictRenderedPayload(BaseModel):
    """Judge → Red Team (partial) and Judge → Documentation (pass/fail).
    The same envelope shape on both inbox routes; the consumer decides
    what to do with it.

    ``seed_idx`` is carried through from the incoming ``AttackEvent``
    so the Red Team's partial-loop handler can produce the next
    Mutator variant in the same seed lane (preserving the
    one-seed-many-variants topology)."""

    model_config = ConfigDict(extra="forbid")

    payload_version: int = 2  # R10 — added decisive_seed_idx + total_seeds.
    campaign_id: UUID
    run_id: UUID
    attack_id: UUID
    attack_execution_id: UUID
    judge_verdict_id: UUID
    verdict: VerdictKind
    rationale: str = ""
    evidence: dict[str, object] = Field(default_factory=dict)
    rubric_version_id: UUID | None = None
    is_deterministic: bool = False
    iteration: int = 0
    seed_idx: int = 0
    # R10 — when the Judge ruled over a multi-turn conversation, this
    # names the turn it judged decisive. ``None`` for single-turn
    # findings and multi-turn fails. ``total_seeds`` is the
    # conversation length the Judge weighed (always >= 1).
    decisive_seed_idx: int | None = None
    total_seeds: int = 1


class CampaignReportRequestedPayload(BaseModel):
    """Ask the Documentation worker to (re)render the campaign-level
    rollup report. Producer is one of:

    - The Documentation worker itself, when handling the last
      ``VerdictRendered`` of a campaign (auto-trigger).
    - The POST ``/campaigns/{id}/report`` route (operator-driven
      regeneration).

    The handler is bounded by the writer's tool-loop turn budget; it
    extends its bus claim via ``touch_claim`` between LLM turns so a
    slow LLM doesn't trigger a false redelivery."""

    model_config = ConfigDict(extra="forbid")

    payload_version: int = 1
    campaign_id: UUID
    # Short string describing why the report was requested, surfaced
    # in the audit log: ``"auto_terminal"`` (every run reached a
    # terminal state), ``"manual_regenerate"`` (operator clicked),
    # etc. Free-form so callers can add new triggers without a schema
    # bump.
    reason: str = "auto_terminal"
    # Operator who requested the regeneration. ``None`` for the
    # auto-trigger path.
    requested_by: UUID | None = None


class FindingPromotedPayload(BaseModel):
    """Documentation → downstream. Critical-severity findings carry
    ``awaiting_approval=True`` for the R9 human gate; R4 just records
    the state so the gate has somewhere to live."""

    model_config = ConfigDict(extra="forbid")

    payload_version: int = 1
    campaign_id: UUID
    run_id: UUID
    finding_id: UUID
    report_id: UUID | None = None
    severity: str
    atlas_technique_id: str | None = None
    owasp_llm_id: str | None = None
    awaiting_approval: bool = False


# ---------------------------------------------------------------------------
# Envelope wrapper
# ---------------------------------------------------------------------------


PayloadT = TypeVar(
    "PayloadT",
    CampaignRequestedPayload,
    CampaignPlanProposedPayload,
    CampaignPlanApprovedPayload,
    AttackEventPayload,
    VerdictRenderedPayload,
    FindingPromotedPayload,
    CampaignReportRequestedPayload,
)


class Envelope(BaseModel, Generic[PayloadT]):  # noqa: UP046
    """Envelope around a typed payload. The bus persists the envelope
    fields directly into ``agent_messages`` columns; ``payload`` is
    serialized to ``payload_json``.

    ``idempotency_key`` is producer-supplied (e.g.
    ``judge:verdict:{attack_id}:{iteration}``) and uniquely indexed
    in the table — a retry emitting the same key collapses at insert
    time."""

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    kind: MessageKind
    from_agent: AgentName
    to_agent: AgentName
    payload: PayloadT
    trace_id: str = ""
    campaign_id: UUID | None = None
    attack_id: UUID | None = None
    idempotency_key: str
    visible_after: datetime | None = None


# Convenience type aliases for callers that want concrete envelopes.
CampaignRequestedEnvelope = Envelope[CampaignRequestedPayload]
CampaignPlanProposedEnvelope = Envelope[CampaignPlanProposedPayload]
CampaignPlanApprovedEnvelope = Envelope[CampaignPlanApprovedPayload]
AttackEventEnvelope = Envelope[AttackEventPayload]
VerdictRenderedEnvelope = Envelope[VerdictRenderedPayload]
FindingPromotedEnvelope = Envelope[FindingPromotedPayload]
CampaignReportRequestedEnvelope = Envelope[CampaignReportRequestedPayload]


# ---------------------------------------------------------------------------
# Payload dispatch — kind → model
# ---------------------------------------------------------------------------


PAYLOAD_FOR_KIND: dict[MessageKind, type[BaseModel]] = {
    MessageKind.CAMPAIGN_REQUESTED: CampaignRequestedPayload,
    MessageKind.CAMPAIGN_PLAN_PROPOSED: CampaignPlanProposedPayload,
    MessageKind.CAMPAIGN_PLAN_APPROVED: CampaignPlanApprovedPayload,
    MessageKind.ATTACK_EVENT: AttackEventPayload,
    MessageKind.VERDICT_RENDERED: VerdictRenderedPayload,
    MessageKind.FINDING_PROMOTED: FindingPromotedPayload,
    MessageKind.CAMPAIGN_REPORT_REQUESTED: CampaignReportRequestedPayload,
}


def payload_model_for(kind: MessageKind) -> type[BaseModel]:
    return PAYLOAD_FOR_KIND[kind]
