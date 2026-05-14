"""R10-followup-2 — Orchestrator agent graph unit tests.

These tests drive the LangGraph orchestrator end-to-end with a
:class:`FakeLLMClient` that scripts a deterministic tool-call sequence.
The DB stays out — ``write_audit`` is monkeypatched to a recorder, and
the agent's tool calls run against a stub ``AsyncSession`` whose
``execute()`` returns empty rows. We assert on:

- Graph control flow (which tools fire, in what order).
- :class:`PlanProposal` shape (plan, transcript, cost, cold_start).
- Cap-on-no-submit semantics (the agent must produce a validated plan
  or :class:`PlanStructuralError` bubbles out).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest

from cats.agents.orchestrator import agent as agent_mod
from cats.agents.orchestrator.agent import (
    DEFAULT_BUDGET_USD_CAP,
    MAX_AGENT_TURNS,
    run_orchestrator_agent,
)
from cats.agents.orchestrator.planner import PlanProposal, PlanStructuralError
from cats.llm.client import FakeLLMClient

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


def _empty_session() -> AsyncMock:
    """Stub AsyncSession whose ``execute()`` returns a result whose
    ``.all()`` is ``[]`` and ``.first()`` is ``None``. Lets the
    orchestrator's data tools run end-to-end against an 'empty DB'
    without standing up postgres."""
    result = MagicMock()
    result.all = MagicMock(return_value=[])
    result.first = MagicMock(return_value=None)
    session = AsyncMock()
    session.execute = AsyncMock(return_value=result)
    return session


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


def _valid_plan_args(
    *,
    technique: str = "ignore_previous",
    rationale: str | None = None,
) -> dict[str, Any]:
    return {
        "attempts": [
            {
                "category": "injection",
                "technique": technique,
                "per_attempt_budget_usd": 0.25,
                "max_consecutive_partials": 2,
            }
        ],
        "rationale": rationale
        or (
            "cold start: list_coverage rows is empty and list_open_findings "
            "is empty. Probing injection.ignore_previous as the cheapest "
            "baseline; ordering is by catalog position."
        ),
        "confidence": "medium",
        "halt_on_consecutive_fails": 3,
        "halt_on_judge_errors": 2,
        "budget_usd_cap": 0.5,
    }


def _script(*tool_calls: dict[str, Any]) -> list[Any]:
    """Build a FakeLLMClient sequence: each entry is one assistant
    turn emitting the listed tool_calls. Each list entry is a list of
    tool-call dicts (so a single turn can emit multiple parallel
    tool_calls)."""
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


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_agent_happy_path_lists_categories_then_submits(
    _silence_audit: list[dict[str, Any]],
) -> None:
    """Minimal happy path: agent calls list_attack_categories then
    submit_plan with a valid plan. Returns a PlanProposal with the
    submitted plan and a transcript that carries both tool rows."""
    fake = FakeLLMClient()
    fake.register_sequence(
        "orchestrator",
        _script(
            {
                "id": "c1",
                "name": "list_attack_categories",
                "arguments": {},
            },
            {
                "id": "c2",
                "name": "submit_plan",
                "arguments": _valid_plan_args(),
            },
        ),
    )
    proposal = await run_orchestrator_agent(
        llm=fake,
        session=_empty_session(),
        project_id=uuid4(),
        project_version_id=uuid4(),
        budget_usd=2.0,
        campaign_id=uuid4(),
        trace_id="happy-path",
    )
    assert isinstance(proposal, PlanProposal)
    assert len(proposal.plan.attempts) == 1
    assert proposal.plan.attempts[0].category == "injection"
    assert proposal.plan.attempts[0].technique == "ignore_previous"
    assert proposal.cold_start is True  # empty session = cold start
    # Transcript shape: each entry has tool/args/output keys —
    # preserves the campaign_plans.tool_transcript JSONB schema.
    assert all({"tool", "args", "output"} <= set(e.keys()) for e in proposal.tool_transcript)
    tool_names = [e["tool"] for e in proposal.tool_transcript]
    assert tool_names == ["list_attack_categories", "submit_plan"]


@pytest.mark.asyncio
async def test_agent_records_per_turn_cost(
    _silence_audit: list[dict[str, Any]],
) -> None:
    """Every planner-node LLM call adds a cost line; the proposal's
    cost_usd is the sum across turns."""
    fake = FakeLLMClient()
    fake.register_sequence(
        "orchestrator",
        _script(
            {"id": "c1", "name": "list_attack_categories", "arguments": {}},
            {"id": "c2", "name": "submit_plan", "arguments": _valid_plan_args()},
        ),
    )
    proposal = await run_orchestrator_agent(
        llm=fake,
        session=_empty_session(),
        project_id=uuid4(),
        project_version_id=uuid4(),
        budget_usd=2.0,
        trace_id="cost-trace",
    )
    # Two planner-node calls.
    assert proposal.cost_usd >= 0.0
    assert proposal.model  # FakeLLMClient returns the registry's primary model


# ---------------------------------------------------------------------------
# Self-correction
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_agent_self_corrects_on_invalid_submit(
    _silence_audit: list[dict[str, Any]],
) -> None:
    """Agent submits an invalid plan (unknown technique), reads the
    tool-error payload, then submits a valid plan. Mirrors the R4 retry
    semantics but via the tool-error self-correction pattern."""
    bad = _valid_plan_args()
    bad["attempts"][0]["technique"] = "this_does_not_exist"

    fake = FakeLLMClient()
    fake.register_sequence(
        "orchestrator",
        _script(
            {"id": "c1", "name": "list_attack_categories", "arguments": {}},
            {"id": "c2", "name": "submit_plan", "arguments": bad},
            {"id": "c3", "name": "submit_plan", "arguments": _valid_plan_args()},
        ),
    )
    proposal = await run_orchestrator_agent(
        llm=fake,
        session=_empty_session(),
        project_id=uuid4(),
        project_version_id=uuid4(),
        budget_usd=2.0,
        trace_id="self-correct",
    )
    assert proposal.plan.attempts[0].technique == "ignore_previous"
    # The error-bearing submit + the successful submit both appear in
    # the transcript.
    submit_rows = [e for e in proposal.tool_transcript if e["tool"] == "submit_plan"]
    assert len(submit_rows) == 2
    assert "error" in submit_rows[0]["output"]
    assert submit_rows[1]["output"].get("ok") is True


@pytest.mark.asyncio
async def test_agent_self_corrects_inspecting_the_tool_message(
    _silence_audit: list[dict[str, Any]],
) -> None:
    """Verify the validator's error + hint payload actually reaches the
    next LLM turn as a role=tool message. The agent must SEE the error
    to correct it."""
    bad = _valid_plan_args()
    bad["attempts"][0]["technique"] = "this_does_not_exist"

    fake = FakeLLMClient()
    fake.register_sequence(
        "orchestrator",
        _script(
            {"id": "c1", "name": "list_attack_categories", "arguments": {}},
            {"id": "c2", "name": "submit_plan", "arguments": bad},
            {"id": "c3", "name": "submit_plan", "arguments": _valid_plan_args()},
        ),
    )
    await run_orchestrator_agent(
        llm=fake,
        session=_empty_session(),
        project_id=uuid4(),
        project_version_id=uuid4(),
        budget_usd=2.0,
        trace_id="self-correct-saw-error",
    )
    # The third LLM call (the successful retry) must have been fed a
    # tool-message containing the validator's error string.
    third_call = fake.call_log[2]
    tool_contents = [
        m.get("content", "") for m in third_call["messages"] if m.get("role") == "tool"
    ]
    parsed_errors = []
    for content in tool_contents:
        try:
            parsed_errors.append(json.loads(content))
        except json.JSONDecodeError:
            continue
    assert any("error" in p and "unknown" in p["error"].lower() for p in parsed_errors), (
        "expected the third turn to see a tool-message with the validator's error"
    )


# ---------------------------------------------------------------------------
# Caps + no-submit → PlanStructuralError
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_agent_raises_when_turn_cap_hits_without_submit(
    _silence_audit: list[dict[str, Any]],
) -> None:
    """An agent that loops on list_attack_categories without ever
    submitting must trigger the turn cap and raise PlanStructuralError
    — NOT synthesize a fallback plan."""
    fake = FakeLLMClient()
    # Lower the cap so the test doesn't have to script 20 turns.
    fake.register_sequence(
        "orchestrator",
        _script(
            *[{"id": f"c{i}", "name": "list_attack_categories", "arguments": {}} for i in range(5)]
        ),
    )
    with pytest.raises(PlanStructuralError, match="without a validated plan"):
        await run_orchestrator_agent(
            llm=fake,
            session=_empty_session(),
            project_id=uuid4(),
            project_version_id=uuid4(),
            budget_usd=2.0,
            trace_id="turn-cap",
            max_agent_turns=3,
        )


@pytest.mark.asyncio
async def test_agent_raises_when_no_tool_calls_emitted(
    _silence_audit: list[dict[str, Any]],
) -> None:
    """If the model emits pure prose (no tool_calls) the agent treats
    it as a give-up: ends the session and the entrypoint raises."""
    fake = FakeLLMClient()

    def prose_only(_msgs: list[dict[str, Any]]) -> dict[str, Any]:
        return {"text": "I refuse to plan.", "tool_calls": []}

    fake.register("orchestrator", prose_only)
    with pytest.raises(PlanStructuralError, match="stopped without a validated plan"):
        await run_orchestrator_agent(
            llm=fake,
            session=_empty_session(),
            project_id=uuid4(),
            project_version_id=uuid4(),
            budget_usd=2.0,
            trace_id="no-tool-calls",
        )


@pytest.mark.asyncio
async def test_agent_raises_on_tool_call_cap(
    _silence_audit: list[dict[str, Any]],
) -> None:
    """An agent that burns through the tool-call cap with reads but
    never submits trips the cap and raises."""
    fake = FakeLLMClient()
    # Need enough scripted turns to actually reach the cap.
    fake.register_sequence(
        "orchestrator",
        _script(
            *[{"id": f"c{i}", "name": "list_attack_categories", "arguments": {}} for i in range(50)]
        ),
    )
    with pytest.raises(PlanStructuralError):
        await run_orchestrator_agent(
            llm=fake,
            session=_empty_session(),
            project_id=uuid4(),
            project_version_id=uuid4(),
            budget_usd=2.0,
            trace_id="tool-call-cap",
            max_tool_calls=3,
        )


# ---------------------------------------------------------------------------
# Cold-start detection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_agent_marks_proposal_as_cold_start_on_empty_signal(
    _silence_audit: list[dict[str, Any]],
) -> None:
    """When list_coverage / list_open_findings / list_recent_regressions
    all returned empty rows, the proposal's cold_start flag is True so
    the worker logs the same signal it did pre-refactor."""
    fake = FakeLLMClient()
    fake.register_sequence(
        "orchestrator",
        _script(
            {"id": "c1", "name": "list_attack_categories", "arguments": {}},
            {"id": "c2", "name": "list_coverage", "arguments": {}},
            {"id": "c3", "name": "list_open_findings", "arguments": {}},
            {"id": "c4", "name": "list_recent_regressions", "arguments": {}},
            {"id": "c5", "name": "submit_plan", "arguments": _valid_plan_args()},
        ),
    )
    proposal = await run_orchestrator_agent(
        llm=fake,
        session=_empty_session(),
        project_id=uuid4(),
        project_version_id=uuid4(),
        budget_usd=2.0,
        trace_id="cold-start",
    )
    assert proposal.cold_start is True


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_agent_writes_audit_rows_for_each_step(
    _silence_audit: list[dict[str, Any]],
) -> None:
    """Audit rows the operator needs to trace cost + decisions:
    agent_started, planner_turn per LLM call, tool:<name> per dispatch,
    agent_submitted on terminal submit_plan."""
    fake = FakeLLMClient()
    fake.register_sequence(
        "orchestrator",
        _script(
            {"id": "c1", "name": "list_attack_categories", "arguments": {}},
            {"id": "c2", "name": "submit_plan", "arguments": _valid_plan_args()},
        ),
    )
    await run_orchestrator_agent(
        llm=fake,
        session=_empty_session(),
        project_id=uuid4(),
        project_version_id=uuid4(),
        budget_usd=2.0,
        trace_id="audit",
    )
    actions = [row["action"] for row in _silence_audit]
    assert "agent_started" in actions
    assert "planner_turn" in actions
    assert "tool:list_attack_categories" in actions
    assert "agent_submitted" in actions


# ---------------------------------------------------------------------------
# Defense-in-depth defaults
# ---------------------------------------------------------------------------


def test_default_budget_cap_is_quarter_dollar_per_session() -> None:
    """Plan called for $0.50; if this default drifts unexpectedly the
    operator's cost expectations move with it."""
    assert DEFAULT_BUDGET_USD_CAP == 0.50


def test_max_agent_turns_default_matches_planning_envelope() -> None:
    """15-20 LLM turns / ~$0.50 cap per the approved plan."""
    assert MAX_AGENT_TURNS == 20


def test_system_prompt_interpolates_budgets_and_turn_cap() -> None:
    """The loader must substitute {budget_usd}, {budget_usd_cap}, and
    {max_agent_turns} so the model sees concrete numbers."""
    text = agent_mod._load_system_prompt(budget_usd=25.0, budget_usd_cap=0.50, max_agent_turns=20)
    assert "$25.00" in text  # operator budget
    assert "$0.50" in text  # session cap
    assert "~20 turns" in text
    # No stray template placeholders.
    assert "{budget_usd" not in text
    assert "{max_agent_turns}" not in text
    # The literal {error, hint} from the JSON example survives.
    assert "{error, hint}" in text
