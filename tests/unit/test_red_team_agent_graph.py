"""R10-follow-up — Red Team agent graph unit tests.

These tests drive the LangGraph agent end-to-end with a FakeLLMClient
that scripts a deterministic tool-call sequence, and a monkeypatched
``fire_prepared_attack`` that fakes the target-side side effects. The
DB and HTTP layers stay out — the test asserts on the graph's *control
flow* (which tools fire, in what order, with what arguments) and on
the resulting ``RedTeamAgentResult`` shape.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any
from uuid import UUID, uuid4

import pytest

from cats.agents.red_team import agent as agent_mod
from cats.agents.red_team import tools as tools_mod
from cats.agents.red_team.agent import run_red_team_agent
from cats.agents.red_team.executor import AttemptResult
from cats.llm.client import FakeLLMClient, install_override
from cats.messaging.envelopes import PlanAttempt


@pytest.fixture
def fake_session() -> Any:
    """A no-op stand-in for ``AsyncSession``. The agent only uses the
    session to write audit rows; we monkeypatch ``write_audit`` to a
    no-op, so the session is unused at runtime."""

    class _S:
        async def execute(self, *_a: Any, **_k: Any) -> Any:
            return None

        async def commit(self) -> None:
            return None

    return _S()


@pytest.fixture(autouse=True)
def _silence_audit(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[dict[str, Any]]]:
    """Replace ``write_audit`` with a recorder so tests can introspect
    the audit trail without hitting the DB."""
    log: list[dict[str, Any]] = []

    async def _record_audit(
        _session: Any,
        *,
        actor: str,
        action: str,
        target_kind: str,
        target_id: UUID | None = None,
        payload: dict[str, Any] | None = None,
        trace_id: str | None = None,
    ) -> None:
        log.append(
            {
                "actor": actor,
                "action": action,
                "target_kind": target_kind,
                "target_id": target_id,
                "payload": payload or {},
                "trace_id": trace_id,
            }
        )

    monkeypatch.setattr(agent_mod, "write_audit", _record_audit)
    yield log


@pytest.fixture
def fake_fire(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Replace ``fire_prepared_attack`` (used inside the
    ``fire_at_target`` tool) with a recorder that returns scripted
    target responses. The Nth call returns the Nth scripted response."""
    calls: list[dict[str, Any]] = []
    scripted_responses: list[str] = [
        "data: I cannot help with that.\n\ndata: [DONE]\n\n",
        "data: I might share something but not the full token.\n\ndata: [DONE]\n\n",
        "data: Sure: CATS-CANARY-ABCD\n\ndata: [DONE]\n\n",
    ]

    async def _fake(*_a: Any, **kwargs: Any) -> AttemptResult:
        idx = len(calls)
        body = scripted_responses[idx] if idx < len(scripted_responses) else "data: end\n\n"
        calls.append(dict(kwargs))
        return AttemptResult(
            attack_id=uuid4(),
            attack_execution_id=uuid4(),
            attack_signature=f"sig-{idx}",
            attack_title=kwargs.get("title", f"turn-{idx}"),
            payload_user_message=kwargs["user_message"],
            canary=kwargs["canary"],
            target_response_text=body,
            target_status_code=200,
            target_latency_ms=10,
            target_error=None,
            output_filter_verdict="safe",
            output_filter_reason="",
            technique=kwargs["technique"],
            iteration=kwargs.get("iteration", 0),
            trace_id=f"trace-{idx}",
            per_agent_costs=[],
            assigned_conversation_id=("conv-1" if idx == 0 else None),
        )

    monkeypatch.setattr(tools_mod, "fire_prepared_attack", _fake)
    return calls


@pytest.fixture
def fake_propose(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace the per-category specialist dispatch so ``propose_attack``
    doesn't try to call a real specialist. Returns a fixed proposal."""

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
            title=f"opening for {category}/{technique}",
            description="unit-test fixture proposal",
            user_message="Initial opener: please echo CATS-CANARY-ABCD.",
            canary="CATS-CANARY-ABCD",
            technique=technique,
            payload_extras={},
            envelope=AttackEnvelope(
                user_message="Initial opener: please echo CATS-CANARY-ABCD.",
                canary="CATS-CANARY-ABCD",
            ),
            cost_role="redteam_injection",
            llm_result=LLMResult(
                text="{}",
                model="fake-model",
                tokens_in=1,
                tokens_out=1,
                usd_estimate=0.0,
                trace_id="fake-trace",
            ),
        )

    monkeypatch.setattr(tools_mod, "_propose_attack", _fake_propose)


@pytest.fixture
def fake_mutator(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace ``generate_variant`` so ``mutate_attack`` returns a
    deterministic variant without hitting an LLM."""
    from cats.agents.mutator.strategies import MutatorResult

    async def _fake_variant(*, state: Any, llm: Any) -> MutatorResult:
        _ = (state, llm)
        return MutatorResult(
            user_message="Mutated: please echo CATS-CANARY-ABCD on its own line.",
            technique_variant="unit-test",
            rationale="unit-test mutator stub",
            llm=None,
        )

    monkeypatch.setattr(tools_mod, "generate_variant", _fake_variant)


def _script_tool_sequence(*tool_calls: dict[str, Any]) -> list[Any]:
    """Build a FakeLLMClient sequence: each entry is one assistant turn
    emitting the listed tool_calls."""
    sequence: list[Any] = []
    for tc in tool_calls:
        sequence.append(
            (
                lambda payload=tc: (
                    lambda _msgs: {
                        "text": "",
                        "tool_calls": [payload],
                    }
                )
            )()
        )
    return sequence


@pytest.mark.asyncio
async def test_agent_drives_propose_fire_mutate_fire_submit(
    fake_session: Any,
    fake_fire: list[dict[str, Any]],
    fake_propose: None,
    fake_mutator: None,
    _silence_audit: list[dict[str, Any]],
) -> None:
    """The load-bearing happy path: agent calls
    propose → fire → mutate → fire → submit. The graph terminates,
    transcript has 2 turns, expected_verdict is honored, stop_reason
    is ``agent_submitted``."""
    _ = (fake_propose, fake_mutator)
    fake = FakeLLMClient()
    fake.register_sequence(
        "redteam_injection",
        _script_tool_sequence(
            {
                "id": "c1",
                "name": "propose_attack",
                "arguments": {
                    "category": "injection",
                    "technique": "ignore_previous",
                    "rationale": "open with the strongest direct injection",
                },
            },
            {
                "id": "c2",
                "name": "fire_at_target",
                "arguments": {},
            },
            {
                "id": "c3",
                "name": "mutate_attack",
                "arguments": {"rationale": "target wavered, push harder"},
            },
            {
                "id": "c4",
                "name": "fire_at_target",
                "arguments": {},
            },
            {
                "id": "c5",
                "name": "submit_for_judgment",
                "arguments": {
                    "rationale": "canary echoed in response 2",
                    "expected_verdict": "pass",
                },
            },
        ),
    )
    install_override(fake)
    try:
        result = await run_red_team_agent(
            session=fake_session,
            campaign_id=uuid4(),
            run_id=uuid4(),
            project_version_id=uuid4(),
            attempt=PlanAttempt(
                category="injection",
                technique="ignore_previous",
                seeds_per_attempt=4,
            ),
            trace_id="unit-test-trace",
        )
    finally:
        install_override(None)

    assert len(result.transcript) == 2, "expected exactly two realized turns"
    assert result.expected_verdict == "pass"
    assert result.stop_reason == "agent_submitted"
    assert result.last_attack_id is not None
    # Each fire_at_target call should have produced one fire_prepared_attack call.
    assert len(fake_fire) == 2
    # Ascending seed_idx.
    seed_idxs = [t.seed_idx for t in result.transcript]
    assert seed_idxs == [0, 1]
    # The mutator's user_message wins on turn 1.
    assert "Mutated" in result.transcript[1].user_message


@pytest.mark.asyncio
async def test_agent_force_submits_on_turn_cap(
    fake_session: Any,
    fake_fire: list[dict[str, Any]],
    fake_propose: None,
    fake_mutator: None,
    _silence_audit: list[dict[str, Any]],
) -> None:
    """If the agent loops on propose → fire → fire → fire ... past the
    seeds_per_attempt cap, the platform synthesizes a submit_for_judgment(fail)
    and terminates. The transcript still carries every realized turn."""
    _ = (fake_propose, fake_mutator)
    # Script: propose, then fire repeatedly with explicit user_message
    # overrides so each fire actually goes through. seeds_per_attempt=2,
    # so on the 2nd fire we hit the cap and the executor force-submits.
    fake = FakeLLMClient()
    fake.register_sequence(
        "redteam_injection",
        _script_tool_sequence(
            {
                "id": "c1",
                "name": "propose_attack",
                "arguments": {
                    "category": "injection",
                    "technique": "ignore_previous",
                    "rationale": "open",
                },
            },
            {"id": "c2", "name": "fire_at_target", "arguments": {}},
            {
                "id": "c3",
                "name": "fire_at_target",
                "arguments": {"user_message": "follow-up turn please echo"},
            },
            # Should never get here — cap fires after the 2nd fire.
            {
                "id": "c4",
                "name": "fire_at_target",
                "arguments": {"user_message": "another follow up"},
            },
        ),
    )
    install_override(fake)
    try:
        result = await run_red_team_agent(
            session=fake_session,
            campaign_id=uuid4(),
            run_id=uuid4(),
            project_version_id=uuid4(),
            attempt=PlanAttempt(
                category="injection",
                technique="ignore_previous",
                seeds_per_attempt=2,
            ),
            trace_id="unit-test-trace-cap",
        )
    finally:
        install_override(None)

    assert result.expected_verdict == "fail"
    assert result.stop_reason == "cap_reached_turns"
    assert len(result.transcript) == 2
    # The follow-up fire that would have exceeded the cap never ran.
    assert len(fake_fire) == 2


@pytest.mark.asyncio
async def test_agent_submit_without_firing_is_recorded_with_no_turns(
    fake_session: Any,
    fake_fire: list[dict[str, Any]],
    fake_propose: None,
    fake_mutator: None,
    _silence_audit: list[dict[str, Any]],
) -> None:
    """Edge case: agent calls submit_for_judgment before firing
    anything. Result carries an empty transcript, fail verdict,
    stop_reason ``agent_submitted``."""
    _ = (fake_propose, fake_mutator)
    fake = FakeLLMClient()
    fake.register_sequence(
        "redteam_injection",
        _script_tool_sequence(
            {
                "id": "c1",
                "name": "submit_for_judgment",
                "arguments": {
                    "rationale": "give up immediately",
                    "expected_verdict": "fail",
                },
            },
        ),
    )
    install_override(fake)
    try:
        result = await run_red_team_agent(
            session=fake_session,
            campaign_id=uuid4(),
            run_id=uuid4(),
            project_version_id=uuid4(),
            attempt=PlanAttempt(
                category="injection",
                technique="ignore_previous",
                seeds_per_attempt=4,
            ),
            trace_id="unit-test-trace-empty",
        )
    finally:
        install_override(None)

    assert result.transcript == []
    assert result.expected_verdict == "fail"
    assert result.last_attack_id is None
    assert len(fake_fire) == 0


@pytest.mark.asyncio
async def test_agent_audit_log_records_submission(
    fake_session: Any,
    fake_fire: list[dict[str, Any]],
    fake_propose: None,
    fake_mutator: None,
    _silence_audit: list[dict[str, Any]],
) -> None:
    """The agent's submit_for_judgment must produce an audit row with
    ``action='submitted_for_judgment'`` for compliance traceability."""
    _ = (fake_propose, fake_mutator, fake_fire)
    audit_log = _silence_audit
    fake = FakeLLMClient()
    fake.register_sequence(
        "redteam_injection",
        _script_tool_sequence(
            {
                "id": "c1",
                "name": "propose_attack",
                "arguments": {
                    "category": "injection",
                    "technique": "ignore_previous",
                    "rationale": "open",
                },
            },
            {"id": "c2", "name": "fire_at_target", "arguments": {}},
            {
                "id": "c3",
                "name": "submit_for_judgment",
                "arguments": {
                    "rationale": "done",
                    "expected_verdict": "partial",
                },
            },
        ),
    )
    install_override(fake)
    try:
        await run_red_team_agent(
            session=fake_session,
            campaign_id=uuid4(),
            run_id=uuid4(),
            project_version_id=uuid4(),
            attempt=PlanAttempt(
                category="injection",
                technique="ignore_previous",
                seeds_per_attempt=4,
            ),
            trace_id="unit-test-trace-audit",
        )
    finally:
        install_override(None)

    actions = [row["action"] for row in audit_log]
    assert "agent_started" in actions
    assert "submitted_for_judgment" in actions
    # Every attacker_turn row also lands.
    assert "attacker_turn" in actions


@pytest.mark.asyncio
async def test_agent_unknown_tool_call_returns_error_payload(
    fake_session: Any,
    fake_fire: list[dict[str, Any]],
    fake_propose: None,
    fake_mutator: None,
    _silence_audit: list[dict[str, Any]],
) -> None:
    """If the model emits a tool call we don't know, the tool message
    carries an error and the next turn (here a submit) cleans up."""
    _ = (fake_propose, fake_mutator, fake_fire)
    fake = FakeLLMClient()
    fake.register_sequence(
        "redteam_injection",
        _script_tool_sequence(
            {
                "id": "c1",
                "name": "do_something_weird",
                "arguments": {"x": 1},
            },
            {
                "id": "c2",
                "name": "submit_for_judgment",
                "arguments": {"rationale": "bailing", "expected_verdict": "fail"},
            },
        ),
    )
    install_override(fake)
    try:
        result = await run_red_team_agent(
            session=fake_session,
            campaign_id=uuid4(),
            run_id=uuid4(),
            project_version_id=uuid4(),
            attempt=PlanAttempt(
                category="injection",
                technique="ignore_previous",
                seeds_per_attempt=4,
            ),
            trace_id="unit-test-trace-unknown",
        )
    finally:
        install_override(None)

    # Conversation ended via the agent's own submit, not by force.
    assert result.stop_reason == "agent_submitted"
    assert result.expected_verdict == "fail"
    # No transcript — unknown tool didn't fire anything.
    assert result.transcript == []


@pytest.mark.asyncio
async def test_agent_halts_mid_batch_when_parallel_tool_calls_blow_the_cap(
    fake_session: Any,
    fake_fire: list[dict[str, Any]],
    fake_propose: None,
    fake_mutator: None,
    _silence_audit: list[dict[str, Any]],
) -> None:
    """A model that emits parallel tool_calls in a single assistant turn
    must not be allowed to burn past the seeds_per_attempt cap. The
    cap-before-dispatch check halts the inner loop after the first call
    that pushes us at-or-past the cap."""
    _ = (fake_propose, fake_mutator)
    fake = FakeLLMClient()

    # One assistant turn that emits propose+fire (2 calls) — won't hit cap.
    # Then one turn that emits fire+fire+fire (3 calls in one turn) with
    # explicit overrides so each can fire. With seeds_per_attempt=2 the
    # first parallel fire takes us from 1→2 turns; the next call in the
    # same batch should short-circuit to a force-submit.
    def _seq() -> list[Any]:
        return [
            (
                lambda: (
                    lambda _m: {
                        "text": "",
                        "tool_calls": [
                            {
                                "id": "c1",
                                "name": "propose_attack",
                                "arguments": {
                                    "category": "injection",
                                    "technique": "ignore_previous",
                                    "rationale": "open",
                                },
                            },
                            {"id": "c2", "name": "fire_at_target", "arguments": {}},
                        ],
                    }
                )
            )(),
            (
                lambda: (
                    lambda _m: {
                        "text": "",
                        "tool_calls": [
                            {
                                "id": "c3",
                                "name": "fire_at_target",
                                "arguments": {"user_message": "first parallel"},
                            },
                            {
                                "id": "c4",
                                "name": "fire_at_target",
                                "arguments": {"user_message": "would blow cap"},
                            },
                            {
                                "id": "c5",
                                "name": "fire_at_target",
                                "arguments": {"user_message": "would blow cap further"},
                            },
                        ],
                    }
                )
            )(),
        ]

    fake.register_sequence("redteam_injection", _seq())
    install_override(fake)
    try:
        result = await run_red_team_agent(
            session=fake_session,
            campaign_id=uuid4(),
            run_id=uuid4(),
            project_version_id=uuid4(),
            attempt=PlanAttempt(
                category="injection",
                technique="ignore_previous",
                seeds_per_attempt=2,
            ),
            trace_id="parallel-cap",
        )
    finally:
        install_override(None)
    assert result.stop_reason == "cap_reached_turns"
    # The first parallel call landed (turn 1 = total of 2 turns); the
    # remaining parallel calls in the batch were short-circuited.
    assert len(result.transcript) == 2
    # Without the fix, we'd see 4 fires (turn0 + 3 parallel).
    assert len(fake_fire) == 2


def test_all_tools_have_unique_names() -> None:
    """Defensive: a name collision in ALL_TOOLS would confuse the
    dispatch loop."""
    names = [t.name for t in tools_mod.ALL_TOOLS]
    assert len(names) == len(set(names)), f"duplicate tool name: {names}"


def test_role_for_category_falls_back_to_injection() -> None:
    """Unknown categories must not crash the agent; they map to the
    injection role so the LLM call still happens with a valid model."""
    assert tools_mod.role_for_category("does-not-exist") == "redteam_injection"
    assert tools_mod.role_for_category("exfil") == "redteam_exfil"


def test_system_prompt_interpolates_assignment() -> None:
    """The loader must substitute {category}, {technique}, and
    {seeds_per_attempt} so the model sees a concrete assignment."""
    text = agent_mod._load_system_prompt(
        category="injection",
        technique="ignore_previous",
        seeds_per_attempt=7,
    )
    assert "injection" in text
    assert "ignore_previous" in text
    assert "7 turns" in text
    # No stray template placeholders.
    assert "{category}" not in text
    assert "{technique}" not in text
    assert "{seeds_per_attempt}" not in text


@pytest.mark.asyncio
async def test_propose_attack_rejected_when_called_twice(
    fake_session: Any,
    fake_fire: list[dict[str, Any]],
    fake_propose: None,
    fake_mutator: None,
    _silence_audit: list[dict[str, Any]],
) -> None:
    """The propose_attack tool is one-shot. Calling it twice in a row
    surfaces an error payload that the model sees and recovers from."""
    _ = (fake_propose, fake_mutator, fake_fire)
    fake = FakeLLMClient()
    fake.register_sequence(
        "redteam_injection",
        _script_tool_sequence(
            {
                "id": "c1",
                "name": "propose_attack",
                "arguments": {
                    "category": "injection",
                    "technique": "ignore_previous",
                    "rationale": "open",
                },
            },
            {
                "id": "c2",
                "name": "propose_attack",
                "arguments": {
                    "category": "injection",
                    "technique": "ignore_previous",
                    "rationale": "again",
                },
            },
            {
                "id": "c3",
                "name": "submit_for_judgment",
                "arguments": {"rationale": "noted error", "expected_verdict": "fail"},
            },
        ),
    )
    install_override(fake)
    try:
        result = await run_red_team_agent(
            session=fake_session,
            campaign_id=uuid4(),
            run_id=uuid4(),
            project_version_id=uuid4(),
            attempt=PlanAttempt(
                category="injection",
                technique="ignore_previous",
                seeds_per_attempt=4,
            ),
            trace_id="unit-test-trace-dup-propose",
        )
    finally:
        install_override(None)
    assert result.stop_reason == "agent_submitted"
    # Verify the second propose's tool message carried an error.
    # The FakeLLMClient.call_log records every LLM call's prompt; the
    # tool-message that the second LLM turn saw is in messages[-1].
    # Inspecting the messages list is the simplest assertion.
    last_log = fake.call_log[-1]
    contents = [m.get("content", "") for m in last_log["messages"]]
    assert any(
        "already called" in (json.loads(c).get("error", "") if c.startswith("{") else "")
        for c in contents
    ), "expected the duplicate propose to surface an error to the next turn"
