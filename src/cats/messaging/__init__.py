"""R4 — typed Postgres-backed message bus.

The four CATS agents (Orchestrator, Red Team, Judge, Documentation)
communicate exclusively through durable typed envelopes on the
``agent_messages`` table. This package owns the contract:

- :mod:`cats.messaging.envelopes` — Pydantic ``Envelope[T]`` generic
  plus the six payload kinds (see ARCHITECTURE.md §2.3).
- :mod:`cats.messaging.bus` — emit / claim_next / ack / nack /
  dead_letter using ``FOR UPDATE SKIP LOCKED`` + LISTEN/NOTIFY wake.
- :mod:`cats.messaging.worker` — :class:`Worker` base class. Owns the
  visibility-timeout loop, retry-with-backoff, dead-letter at 5
  failures, heartbeat row.

Producers serialize via ``model_dump()``; consumers validate via
``Envelope[T].model_validate(row.payload_json)``. Adding a new
handoff means adding a new payload type and bumping the kind set.
"""

from cats.messaging.bus import Bus, ClaimedMessage
from cats.messaging.envelopes import (
    AttackEventPayload,
    CampaignPlanApprovedPayload,
    CampaignPlanProposedPayload,
    CampaignReportRequestedPayload,
    CampaignRequestedPayload,
    Envelope,
    FindingPromotedPayload,
    MessageKind,
    PlanAttempt,
    PlannedCampaign,
    VerdictRenderedPayload,
)
from cats.messaging.worker import Worker

__all__ = [
    "AttackEventPayload",
    "Bus",
    "CampaignPlanApprovedPayload",
    "CampaignPlanProposedPayload",
    "CampaignReportRequestedPayload",
    "CampaignRequestedPayload",
    "ClaimedMessage",
    "Envelope",
    "FindingPromotedPayload",
    "MessageKind",
    "PlanAttempt",
    "PlannedCampaign",
    "VerdictRenderedPayload",
    "Worker",
]
