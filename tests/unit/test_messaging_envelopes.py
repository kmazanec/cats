"""Unit tests for the typed envelope schemas in ``cats.messaging.envelopes``.

These run with no external dependencies. They prove:
  * every ``MessageKind`` round-trips through JSON cleanly,
  * ``payload_model_for`` dispatches to the right concrete model,
  * validators on numeric ranges (e.g. ``per_attempt_budget_usd >= 0``)
    are honored,
  * ``Envelope.idempotency_key`` is mandatory — the bus relies on the
    unique index so a missing key would silently break dedup.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest
from pydantic import BaseModel, ValidationError

from cats.messaging.envelopes import (
    PAYLOAD_FOR_KIND,
    AttackEventPayload,
    CampaignPlanApprovedPayload,
    CampaignPlanProposedPayload,
    CampaignRequestedPayload,
    Envelope,
    FindingPromotedPayload,
    MessageKind,
    PlanAttempt,
    PlannedCampaign,
    VerdictRenderedPayload,
    payload_model_for,
)


def _sample_plan() -> PlannedCampaign:
    return PlannedCampaign(
        attempts=[PlanAttempt(category="injection", technique="ignore_previous")],
        rationale="probe direct-injection baseline",
        confidence="medium",
    )


def _sample_payload_for(kind: MessageKind) -> BaseModel:
    """Construct a minimal valid payload for each kind."""
    cid = uuid4()
    rid = uuid4()
    aid = uuid4()
    aexec = uuid4()
    if kind is MessageKind.CAMPAIGN_REQUESTED:
        return CampaignRequestedPayload(
            project_id=uuid4(),
            project_version_id=uuid4(),
            budget_usd=2.5,
            name="r4-smoke",
        )
    if kind is MessageKind.CAMPAIGN_PLAN_PROPOSED:
        return CampaignPlanProposedPayload(
            campaign_id=cid,
            plan=_sample_plan(),
            plan_id=uuid4(),
        )
    if kind is MessageKind.CAMPAIGN_PLAN_APPROVED:
        return CampaignPlanApprovedPayload(
            campaign_id=cid,
            plan=_sample_plan(),
            proposed_plan=_sample_plan(),
            plan_id=uuid4(),
            project_version_id=uuid4(),
        )
    if kind is MessageKind.ATTACK_EVENT:
        return AttackEventPayload(
            campaign_id=cid,
            run_id=rid,
            attack_id=aid,
            attack_execution_id=aexec,
            category="injection",
            technique="ignore_previous",
            payload="echo {{CANARY}}",
            target_response="Sure, here you go: CATS_TOKEN_42",
            canary="CATS_TOKEN_42",
            iteration=1,
        )
    if kind is MessageKind.VERDICT_RENDERED:
        return VerdictRenderedPayload(
            campaign_id=cid,
            run_id=rid,
            attack_id=aid,
            attack_execution_id=aexec,
            judge_verdict_id=uuid4(),
            verdict="pass",
            rationale="canary echoed verbatim",
            evidence={"canary_index": 18},
            is_deterministic=True,
        )
    if kind is MessageKind.FINDING_PROMOTED:
        return FindingPromotedPayload(
            campaign_id=cid,
            run_id=rid,
            finding_id=uuid4(),
            severity="high",
            atlas_technique_id="AML.T0051.000",
            owasp_llm_id="LLM01",
        )
    raise AssertionError(f"unhandled kind {kind!r}")


# ---------------------------------------------------------------------------
# Round-trip
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", list(MessageKind))
def test_every_payload_roundtrips_through_json(kind: MessageKind) -> None:
    """Build → dump → validate_json → equal. Catches schema drift between
    producer and consumer (the same model is on both sides, but JSON
    serialization can lose floats, datetimes, UUID stringification, etc.)."""
    payload = _sample_payload_for(kind)
    raw = payload.model_dump_json()
    model = payload_model_for(kind)
    restored = model.model_validate_json(raw)
    assert restored == payload


@pytest.mark.parametrize("kind", list(MessageKind))
def test_envelope_roundtrips_through_json(kind: MessageKind) -> None:
    """Envelopes themselves must round-trip — the bus pulls envelope
    fields out of columns but downstream callers serialize the whole
    envelope when handing off to client code."""
    payload = _sample_payload_for(kind)
    # Envelope is generic over PayloadT (one of the six concrete payload
    # models); mypy can't narrow the runtime kind, so we construct via the
    # un-parametrized Envelope and accept the resulting Any-typed payload.
    env: Envelope[Any] = Envelope(
        kind=kind,
        from_agent="orchestrator",
        to_agent="red_team",
        payload=payload,
        trace_id="trace-abc",
        idempotency_key=f"test:{kind.value}:{uuid4()}",
    )
    raw = env.model_dump_json()
    # Validate the payload through the kind-specific model first, then
    # re-wrap — Envelope[T] is generic over the payload type at runtime
    # only through ``arbitrary_types_allowed``.
    restored = Envelope.model_validate_json(raw)
    assert restored.kind == kind
    assert restored.idempotency_key == env.idempotency_key
    # Payload comparison via the concrete model (Envelope's payload
    # comes back as the generic body so we rebuild for equality).
    concrete = payload_model_for(kind).model_validate(restored.payload)
    assert concrete == payload


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


def test_payload_model_for_dispatches_each_kind() -> None:
    """Every MessageKind has exactly one model; no fallthrough, no
    duplicates."""
    expected: dict[MessageKind, type[BaseModel]] = {
        MessageKind.CAMPAIGN_REQUESTED: CampaignRequestedPayload,
        MessageKind.CAMPAIGN_PLAN_PROPOSED: CampaignPlanProposedPayload,
        MessageKind.CAMPAIGN_PLAN_APPROVED: CampaignPlanApprovedPayload,
        MessageKind.ATTACK_EVENT: AttackEventPayload,
        MessageKind.VERDICT_RENDERED: VerdictRenderedPayload,
        MessageKind.FINDING_PROMOTED: FindingPromotedPayload,
    }
    assert expected == PAYLOAD_FOR_KIND
    for kind, model in expected.items():
        assert payload_model_for(kind) is model


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def test_plan_attempt_rejects_negative_budget() -> None:
    """``per_attempt_budget_usd < 0`` is meaningless and would let the
    Red Team executor "earn" budget. The Field constraint must trip."""
    with pytest.raises(ValidationError):
        PlanAttempt(
            category="injection",
            technique="ignore_previous",
            per_attempt_budget_usd=-0.01,
        )


def test_planned_campaign_rejects_negative_per_attempt_budget() -> None:
    """Nested validation: the PlanAttempt validator must also fire when
    PlannedCampaign builds its ``attempts`` list from raw dicts (the
    JSON deserialization path the bus uses)."""
    with pytest.raises(ValidationError):
        PlannedCampaign.model_validate(
            {
                "attempts": [
                    {
                        "category": "injection",
                        "technique": "ignore_previous",
                        "per_attempt_budget_usd": -1.0,
                    }
                ],
            }
        )


def test_envelope_requires_idempotency_key() -> None:
    """The bus' insert-time dedup hinges on the unique index; without
    a key the producer would lose at-least-once semantics."""
    payload = _sample_payload_for(MessageKind.CAMPAIGN_REQUESTED)
    with pytest.raises(ValidationError) as excinfo:
        Envelope.model_validate(
            {
                "kind": MessageKind.CAMPAIGN_REQUESTED.value,
                "from_agent": "trigger",
                "to_agent": "orchestrator",
                "payload": payload.model_dump(mode="json"),
            }
        )
    # Pydantic v2 surfaces missing-field errors with ``type='missing'``.
    errors = excinfo.value.errors()
    assert any(e["loc"] == ("idempotency_key",) for e in errors)
