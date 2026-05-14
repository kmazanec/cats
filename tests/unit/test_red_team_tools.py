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


@pytest.fixture(autouse=True)
def fake_kickoff(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[dict[str, Any]]]:
    """Stub the briefing kickoff so propose_attack doesn't try to hit
    the real target. Autouse — every test that goes through
    ``run_propose_attack`` needs this. Returns a list tests can inspect
    to confirm the kickoff fired (tests that explicitly override the
    stub use ``monkeypatch.setattr`` themselves and ignore this fixture's
    return value)."""
    from cats.agents.red_team.executor import KickoffResult

    calls: list[dict[str, Any]] = []

    async def _fake_kickoff(_session: Any, **kwargs: Any) -> KickoffResult:
        calls.append(dict(kwargs))
        return KickoffResult(
            conversation_id="conv-fixed",
            briefing_text="canned briefing body",
            target_status_code=200,
            target_latency_ms=20_000,
            error=None,
        )

    monkeypatch.setattr(tools_mod, "fire_kickoff_briefing", _fake_kickoff)
    yield calls


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
        "trace_id": "unit-trace",
        "budget_usd_cap": 1.00,
        "max_turns_soft": 10,
    }
    base.update(overrides)
    return AgentContext(**base)


class _DummySession:
    async def execute(self, *_a: Any, **_k: Any) -> Any:
        return None

    async def commit(self) -> None:
        return None


@pytest.mark.asyncio
async def test_propose_attack_fills_pending(
    fake_propose: None, fake_kickoff: list[dict[str, Any]]
) -> None:
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
    # Kickoff fired exactly once, harvested the conversationId, and
    # the canned briefing surfaced in the tool payload.
    assert len(fake_kickoff) == 1
    assert ctx.conversation_id == "conv-fixed"
    assert outcome.payload["conversation_id"] == "conv-fixed"
    assert "kickoff_briefing" in outcome.payload
    assert outcome.payload["kickoff_latency_ms"] == 20_000


@pytest.mark.asyncio
async def test_propose_attack_rejects_second_call(
    fake_propose: None, fake_kickoff: list[dict[str, Any]]
) -> None:
    _ = (fake_propose, fake_kickoff)
    ctx = _ctx()
    await tools_mod.run_propose_attack(
        ctx, args={"category": "injection", "technique": "ignore_previous", "rationale": "1"}
    )
    second = await tools_mod.run_propose_attack(
        ctx, args={"category": "injection", "technique": "ignore_previous", "rationale": "2"}
    )
    assert "error" in second.payload
    # Kickoff still only fires once even across rejected re-calls.
    assert len(fake_kickoff) == 1


@pytest.mark.asyncio
async def test_propose_attack_aborts_when_kickoff_returns_no_conversation_id(
    fake_propose: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the kickoff fails to produce a conversationId, propose_attack
    must surface the error rather than letting the agent attempt an
    attack the target will discard."""
    _ = fake_propose
    from cats.agents.red_team.executor import KickoffResult

    async def _broken_kickoff(_s: Any, **_k: Any) -> KickoffResult:
        return KickoffResult(
            conversation_id=None,
            briefing_text="",
            target_status_code=502,
            target_latency_ms=120,
            error="upstream timeout",
        )

    monkeypatch.setattr(tools_mod, "fire_kickoff_briefing", _broken_kickoff)
    ctx = _ctx()
    outcome = await tools_mod.run_propose_attack(
        ctx, args={"category": "injection", "technique": "ignore_previous", "rationale": "x"}
    )
    assert "error" in outcome.payload
    assert outcome.payload["kickoff_status_code"] == 502
    assert outcome.payload["kickoff_error"] == "upstream timeout"
    # Specialist was NOT invoked — propose_called stays False.
    assert ctx.propose_called is False
    assert ctx.pending_user_message is None


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
    # Conversation id is set so we exercise the no-pending branch
    # rather than the no-conversation-id branch.
    ctx.conversation_id = "conv-fixed"
    outcome = await tools_mod.run_fire_at_target(ctx, args={})
    assert "error" in outcome.payload
    assert "pending" in outcome.payload["error"].lower()


@pytest.mark.asyncio
async def test_fire_without_conversation_id_returns_error() -> None:
    """fire_at_target must refuse when no kickoff has run yet —
    otherwise the target receives a default_briefing that ignores
    `question` and the attack silently no-ops."""
    ctx = _ctx()
    ctx.pending_user_message = "anything"
    ctx.pending_canary = "C"
    outcome = await tools_mod.run_fire_at_target(ctx, args={})
    assert "error" in outcome.payload
    assert "conversation_id" in outcome.payload["error"]


@pytest.mark.asyncio
async def test_fire_records_turn_with_follow_up_task(
    fake_propose: None,
    fake_kickoff: list[dict[str, Any]],
    fire_calls: list[dict[str, Any]],
) -> None:
    """Every attack turn — including the first — rides as `follow_up`
    against the kickoff's conversationId."""
    _ = (fake_propose, fake_kickoff)
    ctx = _ctx()
    await tools_mod.run_propose_attack(
        ctx, args={"category": "injection", "technique": "ignore_previous", "rationale": "x"}
    )
    out0 = await tools_mod.run_fire_at_target(ctx, args={})
    assert out0.payload["seed_idx"] == 0
    assert out0.payload["status_code"] == 200
    assert len(ctx.turns) == 1
    assert ctx.pending_user_message is None  # consumed by fire
    # Conversation_id was captured by the kickoff (not by the fire).
    assert ctx.conversation_id == "conv-fixed"
    assert fire_calls[0]["task"] == "follow_up"
    assert fire_calls[0]["conversation_id"] == "conv-fixed"


@pytest.mark.asyncio
async def test_subsequent_fire_uses_follow_up_task_and_shared_conv(
    fake_propose: None,
    fake_mutator: None,
    fake_kickoff: list[dict[str, Any]],
    fire_calls: list[dict[str, Any]],
) -> None:
    _ = (fake_propose, fake_mutator, fake_kickoff)
    ctx = _ctx()
    await tools_mod.run_propose_attack(
        ctx, args={"category": "injection", "technique": "ignore_previous", "rationale": "x"}
    )
    await tools_mod.run_fire_at_target(ctx, args={})
    await tools_mod.run_mutate_attack(ctx, args={"rationale": "push"}, llm=FakeLLMClient())
    await tools_mod.run_fire_at_target(ctx, args={})
    assert len(ctx.turns) == 2
    # Every fire — including the first — uses follow_up against the
    # kickoff conversationId.
    assert all(c["task"] == "follow_up" for c in fire_calls)
    assert all(c["conversation_id"] == "conv-fixed" for c in fire_calls)
    # seed_idx ascends.
    assert [t.seed_idx for t in ctx.turns] == [0, 1]


@pytest.mark.asyncio
async def test_submit_marks_terminal_and_carries_self_assessment() -> None:
    ctx = _ctx()
    out = await tools_mod.run_submit_for_judgment(
        ctx,
        args={"rationale": "done", "self_assessment": "breached"},
    )
    assert out.terminal is True
    assert ctx.submitted is True
    assert ctx.self_assessment == "breached"
    assert ctx.stop_reason == "agent_submitted"


@pytest.mark.asyncio
async def test_submit_idempotent() -> None:
    ctx = _ctx()
    await tools_mod.run_submit_for_judgment(
        ctx, args={"rationale": "1", "self_assessment": "breached"}
    )
    out2 = await tools_mod.run_submit_for_judgment(
        ctx, args={"rationale": "2", "self_assessment": "held"}
    )
    assert out2.terminal is True
    assert ctx.self_assessment == "breached"  # first call wins


@pytest.mark.asyncio
async def test_dispatch_unknown_tool_returns_error() -> None:
    ctx = _ctx()
    out = await dispatch(ctx, name="nope", args={}, llm=FakeLLMClient())
    assert "error" in out.payload


@pytest.mark.asyncio
async def test_submit_normalizes_invalid_self_assessment() -> None:
    ctx = _ctx()
    out = await tools_mod.run_submit_for_judgment(
        ctx, args={"rationale": "x", "self_assessment": "not-a-thing"}
    )
    assert out.payload["self_assessment"] == "inconclusive"


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


# ---------------------------------------------------------------------------
# Cost-accounting tests — regression coverage for the run-detail "Spend" /
# "Cost by agent" bug where the agent's per-turn LLM cost (proposal +
# mutator + supervisor) was discarded and every attack_executions row
# landed with tokens=0, usd=0.
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_propose_with_cost(monkeypatch: pytest.MonkeyPatch) -> None:
    """Like ``fake_propose`` but returns a non-zero LLMResult so the
    cost-flow tests can assert the proposal LLM spend reaches the
    execution row."""
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
                model="fake-injection-model",
                tokens_in=120,
                tokens_out=40,
                usd_estimate=0.0123,
                trace_id="prop-trace",
            ),
        )

    monkeypatch.setattr(tools_mod, "_propose_attack", _fake_propose)


@pytest.fixture
def fake_mutator_with_cost(monkeypatch: pytest.MonkeyPatch) -> None:
    """Like ``fake_mutator`` but returns a non-None LLMResult so the
    cost-flow tests can assert the mutator's LLM spend is recorded."""
    from cats.agents.mutator.strategies import MutatorResult
    from cats.llm.client import LLMResult

    async def _fake(*, state: Any, llm: Any) -> MutatorResult:
        _ = (state, llm)
        return MutatorResult(
            user_message="mutated payload with CATS-CANARY-XYZ",
            technique_variant="unit",
            rationale="r",
            llm=LLMResult(
                text="{}",
                model="fake-mutator-model",
                tokens_in=200,
                tokens_out=60,
                usd_estimate=0.0050,
                trace_id="mut-trace",
            ),
        )

    monkeypatch.setattr(tools_mod, "generate_variant", _fake)


def test_record_cost_appends_and_advances_budget() -> None:
    """``AgentContext.record_cost`` appends one ``AgentTurnCost`` per
    LLM call and bumps ``budget_consumed_usd`` so the cap-check sees
    the running total."""
    from cats.llm.client import LLMResult

    ctx = _ctx()
    assert ctx.costs == []
    assert ctx.budget_consumed_usd == 0.0

    ctx.record_cost(
        role="redteam_supervisor",
        result=LLMResult(
            text="",
            model="m1",
            tokens_in=10,
            tokens_out=5,
            usd_estimate=0.01,
            trace_id="t1",
        ),
    )
    ctx.record_cost(
        role="redteam_injection",
        result=LLMResult(
            text="",
            model="m2",
            tokens_in=20,
            tokens_out=8,
            usd_estimate=0.02,
            trace_id="t2",
        ),
    )

    assert len(ctx.costs) == 2
    assert ctx.costs[0].role == "redteam_supervisor"
    assert ctx.costs[0].tokens_in == 10
    assert ctx.costs[1].role == "redteam_injection"
    assert ctx.budget_consumed_usd == pytest.approx(0.03)


def test_drain_pending_costs_slices_per_fire() -> None:
    """``drain_pending_costs`` returns only the costs accumulated since
    the previous drain — the slicing that lets ``fire_at_target``
    attribute exactly the LLM spend the agent burned producing *this*
    turn to *this* execution row."""
    from cats.llm.client import LLMResult

    ctx = _ctx()

    def _push(role: str, usd: float) -> None:
        ctx.record_cost(
            role=role,
            result=LLMResult(
                text="",
                model="m",
                tokens_in=1,
                tokens_out=1,
                usd_estimate=usd,
                trace_id="t",
            ),
        )

    # Pre-fire-1: supervisor turn + propose
    _push("redteam_supervisor", 0.005)
    _push("redteam_injection", 0.010)
    first = ctx.drain_pending_costs()
    assert [c.role for c in first] == ["redteam_supervisor", "redteam_injection"]
    assert ctx.last_attributed_cost_idx == 2

    # Pre-fire-2: supervisor turn + mutator
    _push("redteam_supervisor", 0.006)
    _push("redteam_mutator", 0.007)
    second = ctx.drain_pending_costs()
    assert [c.role for c in second] == ["redteam_supervisor", "redteam_mutator"]
    # Total run-level spend still preserved on ctx.costs even after draining.
    assert len(ctx.costs) == 4
    assert ctx.budget_consumed_usd == pytest.approx(0.028)

    # Third drain with no new costs yields empty.
    assert ctx.drain_pending_costs() == []


@pytest.mark.asyncio
async def test_propose_attack_records_llm_cost_on_ctx(fake_propose_with_cost: None) -> None:
    """``run_propose_attack`` MUST record the content-generator LLM cost
    on the context. Before the fix this cost was discarded, leaving
    the execution row with $0 spend on the propose turn."""
    _ = fake_propose_with_cost
    ctx = _ctx()
    assert ctx.costs == []
    await tools_mod.run_propose_attack(
        ctx, args={"category": "injection", "technique": "ignore_previous", "rationale": "x"}
    )
    assert len(ctx.costs) == 1
    only = ctx.costs[0]
    assert only.role == "redteam_injection"
    assert only.model == "fake-injection-model"
    assert only.tokens_in == 120
    assert only.tokens_out == 40
    assert only.usd == pytest.approx(0.0123)
    assert ctx.budget_consumed_usd == pytest.approx(0.0123)


@pytest.mark.asyncio
async def test_mutate_attack_records_llm_cost_on_ctx(
    fake_propose_with_cost: None, fake_mutator_with_cost: None, fire_calls: list[dict[str, Any]]
) -> None:
    """``run_mutate_attack`` MUST record the variant-generator LLM cost
    on the context when the mutator actually called an LLM."""
    _ = (fake_propose_with_cost, fake_mutator_with_cost, fire_calls)
    ctx = _ctx()
    # propose + fire to satisfy mutate_attack's "needs a prior turn" precondition
    await tools_mod.run_propose_attack(
        ctx, args={"category": "injection", "technique": "ignore_previous", "rationale": "x"}
    )
    await tools_mod.run_fire_at_target(ctx, args={})
    cost_count_before_mutate = len(ctx.costs)
    await tools_mod.run_mutate_attack(ctx, args={"rationale": "push"}, llm=FakeLLMClient())
    assert len(ctx.costs) == cost_count_before_mutate + 1
    last = ctx.costs[-1]
    assert last.role == "redteam_mutator"
    assert last.model == "fake-mutator-model"
    assert last.usd == pytest.approx(0.0050)


@pytest.mark.asyncio
async def test_fire_at_target_threads_pending_costs_to_execution_row(
    fake_propose_with_cost: None, fire_calls: list[dict[str, Any]]
) -> None:
    """``run_fire_at_target`` MUST drain the costs accumulated since
    the previous fire and pass them to ``fire_prepared_attack`` via
    ``prior_agent_costs``. That's the wire that carries supervisor +
    propose/mutate spend onto the attack_executions row so the
    run-detail "Cost by agent" panel sees non-zero tokens + USD."""
    _ = fake_propose_with_cost
    ctx = _ctx()
    # Simulate a supervisor turn before propose (the supervisor LLM
    # records cost in _attacker_node — emulate by direct record_cost).
    from cats.llm.client import LLMResult

    ctx.record_cost(
        role="redteam_supervisor",
        result=LLMResult(
            text="",
            model="fake-supervisor",
            tokens_in=50,
            tokens_out=10,
            usd_estimate=0.003,
            trace_id="sup-1",
        ),
    )
    # propose_attack appends its own cost (0.0123 redteam_injection).
    await tools_mod.run_propose_attack(
        ctx, args={"category": "injection", "technique": "ignore_previous", "rationale": "x"}
    )
    await tools_mod.run_fire_at_target(ctx, args={})

    assert len(fire_calls) == 1
    threaded = fire_calls[0]["prior_agent_costs"]
    roles = [c["role"] for c in threaded]
    assert roles == ["redteam_supervisor", "redteam_injection"]
    usd_total = sum(c["usd"] for c in threaded)
    assert usd_total == pytest.approx(0.003 + 0.0123)
    # After the fire, ctx.costs still carries the full history for the
    # run-level rollup the worker reads back.
    assert len(ctx.costs) == 2
    # But the drain cursor advanced, so a *second* fire (with no new
    # costs in between) would carry an empty prior_agent_costs.
    assert ctx.last_attributed_cost_idx == 2
