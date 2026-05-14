"""R10-follow-up — Red Team agent tool implementations (unit).

Each tool is a small async function over the shared :class:`AgentContext`.
The dispatcher (``tools_mod.dispatch``) is the integration seam; these
tests exercise each tool in isolation with stubbed downstream callers.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any
from uuid import UUID, uuid4

import pytest

from cats.agents.red_team import tools as tools_mod
from cats.agents.red_team.executor import AttemptResult
from cats.agents.red_team.tools import (
    AgentContext,
    TurnRecord,
    dispatch,
    transcript_payload,
)
from cats.llm.client import FakeLLMClient


@pytest.fixture
def fire_calls(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    async def _fake(*_a: Any, **kwargs: Any) -> AttemptResult:
        idx = len(calls)
        calls.append(dict(kwargs))
        return AttemptResult(
            attack_id=uuid4(),
            attack_execution_id=uuid4(),
            attack_signature=f"sig-{idx}",
            attack_title="t",
            payload_user_message=kwargs["user_message"],
            canary=kwargs["canary"],
            target_response_text=f"resp-{idx}",
            target_status_code=200,
            target_latency_ms=5,
            target_error=None,
            output_filter_verdict="safe",
            output_filter_reason="",
            technique=kwargs["technique"],
            iteration=kwargs.get("iteration", 0),
            trace_id=f"trace-{idx}",
            per_agent_costs=[],
            assigned_conversation_id=("conv-fixed" if idx == 0 else None),
        )

    monkeypatch.setattr(tools_mod, "fire_prepared_attack", _fake)
    return calls


@pytest.fixture
def fake_propose(monkeypatch: pytest.MonkeyPatch) -> None:
    from cats.agents.red_team.executor import _NormalizedProposal
    from cats.llm.client import LLMResult
    from cats.target.contracts import AttackEnvelope

    async def _fake_propose(
        *,
        category: str,
        technique: str,
        seed_idx: int = 0,
        prior_user_messages: list[str] | None = None,
        prior_target_responses: list[str] | None = None,
    ) -> _NormalizedProposal:
        _ = (seed_idx, prior_user_messages, prior_target_responses)
        return _NormalizedProposal(
            title=f"{category}/{technique} opener",
            description="unit",
            user_message="hello {{canary}}",
            canary="CATS-CANARY-XYZ",
            technique=technique,
            payload_extras={},
            envelope=AttackEnvelope(user_message="hello {{canary}}", canary="CATS-CANARY-XYZ"),
            cost_role="redteam_injection",
            llm_result=LLMResult(
                text="{}",
                model="fake",
                tokens_in=1,
                tokens_out=1,
                usd_estimate=0.0,
                trace_id="t",
            ),
        )

    monkeypatch.setattr(tools_mod, "_propose_attack", _fake_propose)


@pytest.fixture
def fake_mutator(monkeypatch: pytest.MonkeyPatch) -> None:
    from cats.agents.mutator.strategies import MutatorResult

    async def _fake(*, state: Any, llm: Any) -> MutatorResult:
        _ = (state, llm)
        return MutatorResult(
            user_message="mutated payload with CATS-CANARY-XYZ",
            technique_variant="unit",
            rationale="r",
            llm=None,
        )

    monkeypatch.setattr(tools_mod, "generate_variant", _fake)


@pytest.fixture(autouse=True)
def _silence_publish(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[dict[str, Any]]]:
    """``publish`` writes to a Redis pub/sub channel — replace with a
    recorder."""
    sent: list[dict[str, Any]] = []

    async def _record_publish(*_a: Any, **kwargs: Any) -> None:
        sent.append(dict(kwargs))

    monkeypatch.setattr(tools_mod, "publish", _record_publish)
    yield sent


def _ctx(**overrides: Any) -> AgentContext:
    base: dict[str, Any] = {
        "session": _DummySession(),
        "campaign_id": uuid4(),
        "run_id": uuid4(),
        "project_version_id": uuid4(),
        "category": "injection",
        "technique": "ignore_previous",
        "seeds_per_attempt": 4,
        "max_consecutive_partials": 2,
        "trace_id": "unit-trace",
        "shares_conversation": True,
    }
    base.update(overrides)
    return AgentContext(**base)


class _DummySession:
    async def execute(self, *_a: Any, **_k: Any) -> Any:
        return None

    async def commit(self) -> None:
        return None


@pytest.mark.asyncio
async def test_propose_attack_fills_pending(fake_propose: None) -> None:
    _ = fake_propose
    ctx = _ctx()
    outcome = await tools_mod.run_propose_attack(
        ctx,
        args={
            "category": "injection",
            "technique": "ignore_previous",
            "rationale": "open",
        },
    )
    assert outcome.terminal is False
    assert ctx.pending_user_message == "hello {{canary}}"
    assert ctx.pending_canary == "CATS-CANARY-XYZ"
    assert ctx.propose_called is True
    assert "user_message" in outcome.payload


@pytest.mark.asyncio
async def test_propose_attack_rejects_second_call(fake_propose: None) -> None:
    _ = fake_propose
    ctx = _ctx()
    await tools_mod.run_propose_attack(
        ctx, args={"category": "injection", "technique": "ignore_previous", "rationale": "1"}
    )
    second = await tools_mod.run_propose_attack(
        ctx, args={"category": "injection", "technique": "ignore_previous", "rationale": "2"}
    )
    assert "error" in second.payload


@pytest.mark.asyncio
async def test_mutate_without_prior_turn_returns_error() -> None:
    ctx = _ctx()
    outcome = await tools_mod.run_mutate_attack(
        ctx, args={"rationale": "no signal yet"}, llm=FakeLLMClient()
    )
    assert "error" in outcome.payload


@pytest.mark.asyncio
async def test_mutate_after_a_turn_rewrites_pending(fake_mutator: None) -> None:
    _ = fake_mutator
    ctx = _ctx()
    ctx.turns.append(
        TurnRecord(
            seed_idx=0,
            user_message="old",
            canary="CATS-CANARY-XYZ",
            target_response="I cannot help.",
            target_status_code=200,
            target_error=None,
            target_latency_ms=1,
            attack_execution_id=uuid4(),
            attack_id=uuid4(),
        )
    )
    outcome = await tools_mod.run_mutate_attack(
        ctx, args={"rationale": "push"}, llm=FakeLLMClient()
    )
    assert outcome.terminal is False
    assert ctx.pending_user_message is not None
    assert "mutated" in ctx.pending_user_message
    assert ctx.pending_canary == "CATS-CANARY-XYZ"


@pytest.mark.asyncio
async def test_fire_without_pending_returns_error() -> None:
    ctx = _ctx()
    outcome = await tools_mod.run_fire_at_target(ctx, args={})
    assert "error" in outcome.payload


@pytest.mark.asyncio
async def test_fire_records_turn_and_captures_conversation_id(
    fake_propose: None, fire_calls: list[dict[str, Any]]
) -> None:
    _ = fake_propose
    ctx = _ctx()
    await tools_mod.run_propose_attack(
        ctx, args={"category": "injection", "technique": "ignore_previous", "rationale": "x"}
    )
    out0 = await tools_mod.run_fire_at_target(ctx, args={})
    assert out0.payload["seed_idx"] == 0
    assert out0.payload["status_code"] == 200
    assert len(ctx.turns) == 1
    assert ctx.pending_user_message is None  # consumed by fire
    # Conversation_id captured from the first fire.
    assert ctx.conversation_id == "conv-fixed"
    # Fire was called with task=default_briefing on turn 0.
    assert fire_calls[0]["task"] == "default_briefing"
    assert fire_calls[0]["conversation_id"] is None


@pytest.mark.asyncio
async def test_subsequent_fire_uses_follow_up_task_and_shared_conv(
    fake_propose: None, fake_mutator: None, fire_calls: list[dict[str, Any]]
) -> None:
    _ = (fake_propose, fake_mutator)
    ctx = _ctx()
    await tools_mod.run_propose_attack(
        ctx, args={"category": "injection", "technique": "ignore_previous", "rationale": "x"}
    )
    await tools_mod.run_fire_at_target(ctx, args={})
    await tools_mod.run_mutate_attack(ctx, args={"rationale": "push"}, llm=FakeLLMClient())
    await tools_mod.run_fire_at_target(ctx, args={})
    assert len(ctx.turns) == 2
    assert fire_calls[1]["task"] == "follow_up"
    assert fire_calls[1]["conversation_id"] == "conv-fixed"
    # seed_idx ascends.
    assert [t.seed_idx for t in ctx.turns] == [0, 1]


@pytest.mark.asyncio
async def test_submit_marks_terminal_and_carries_verdict() -> None:
    ctx = _ctx()
    out = await tools_mod.run_submit_for_judgment(
        ctx,
        args={"rationale": "done", "expected_verdict": "pass"},
    )
    assert out.terminal is True
    assert ctx.submitted is True
    assert ctx.expected_verdict == "pass"
    assert ctx.stop_reason == "agent_submitted"


@pytest.mark.asyncio
async def test_submit_idempotent() -> None:
    ctx = _ctx()
    await tools_mod.run_submit_for_judgment(
        ctx, args={"rationale": "1", "expected_verdict": "pass"}
    )
    out2 = await tools_mod.run_submit_for_judgment(
        ctx, args={"rationale": "2", "expected_verdict": "fail"}
    )
    assert out2.terminal is True
    assert ctx.expected_verdict == "pass"  # first call wins


@pytest.mark.asyncio
async def test_dispatch_unknown_tool_returns_error() -> None:
    ctx = _ctx()
    out = await dispatch(ctx, name="nope", args={}, llm=FakeLLMClient())
    assert "error" in out.payload


@pytest.mark.asyncio
async def test_submit_normalizes_invalid_expected_verdict() -> None:
    ctx = _ctx()
    out = await tools_mod.run_submit_for_judgment(
        ctx, args={"rationale": "x", "expected_verdict": "not-a-thing"}
    )
    assert out.payload["expected_verdict"] == "partial"


def test_transcript_payload_mirrors_turn_log() -> None:
    ctx = _ctx()
    eid: UUID = uuid4()
    ctx.turns.append(
        TurnRecord(
            seed_idx=0,
            user_message="hi",
            canary="C",
            target_response="hello",
            target_status_code=200,
            target_error=None,
            target_latency_ms=2,
            attack_execution_id=eid,
            attack_id=uuid4(),
        )
    )
    payloads = transcript_payload(ctx)
    assert len(payloads) == 1
    assert payloads[0].seed_idx == 0
    assert payloads[0].attack_execution_id == eid
    assert payloads[0].user_message == "hi"
    assert payloads[0].target_response == "hello"
