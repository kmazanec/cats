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
    """The six cross-agent message kinds the bus carries."""

    CAMPAIGN_REQUESTED = "CampaignRequested"
    CAMPAIGN_PLAN_PROPOSED = "CampaignPlanProposed"
    CAMPAIGN_PLAN_APPROVED = "CampaignPlanApproved"
    ATTACK_EVENT = "AttackEvent"
    VERDICT_RENDERED = "VerdictRendered"
    FINDING_PROMOTED = "FindingPromoted"


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


class AttackEventPayload(BaseModel):
    """Red Team → Judge. One attempted attack against the live target.

    ``seed_idx`` distinguishes the K seeds the Red Team fires per plan
    attempt; ``iteration`` distinguishes Mutator variants of a single
    seed when the Judge keeps returning ``partial``. Together they
    namespace the idempotency key so retries dedupe correctly."""

    model_config = ConfigDict(extra="forbid")

    payload_version: int = 1
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

    payload_version: int = 1
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
}


def payload_model_for(kind: MessageKind) -> type[BaseModel]:
    return PAYLOAD_FOR_KIND[kind]
