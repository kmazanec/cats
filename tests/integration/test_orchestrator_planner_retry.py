"""Integration test for the LangGraph orchestrator's tool-error
self-correction pattern.

Before R10-followup-2 the planner did a single-shot LLM call + one
external retry on PlanStructuralError. The new agent loop achieves the
same effect via the ``submit_plan`` tool: on an invalid plan, the tool
returns ``{error, hint}`` as a tool-message; the next planner turn
sees it and can correct.

These tests drive the real :func:`propose_plan` (which opens a fresh
``session_scope`` and goes through the agent) with a scripted
:class:`FakeLLMClient`. The DB is real (postgres via the ``client``
fixture) so the agent's audit-write side effects + data-tool queries
exercise the production paths.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import insert

from cats.agents.orchestrator.planner import PlanStructuralError, propose_plan
from cats.db.engine import session_scope
from cats.db.schema import project_versions, projects
from cats.llm.client import FakeLLMClient, install_override
from cats.security.crypto import encrypt

pytestmark = pytest.mark.integration


def _valid_plan_args() -> dict[str, Any]:
    return {
        "attempts": [
            {
                "category": "injection",
                "technique": "ignore_previous",
                "per_attempt_budget_usd": 0.5,
                "max_consecutive_partials": 2,
            }
        ],
        "rationale": (
            "cold start: list_coverage rows is empty and list_open_findings "
            "is empty. Probing injection.ignore_previous as the cheapest "
            "baseline; ordering is by catalog position."
        ),
        "confidence": "medium",
        "halt_on_consecutive_fails": 3,
        "halt_on_judge_errors": 2,
        "budget_usd_cap": 1.0,
    }


def _bad_plan_args() -> dict[str, Any]:
    args = _valid_plan_args()
    # 'default' is not a real technique under any category — validator
    # rejects with 'unknown (category, technique)'.
    args["attempts"][0]["technique"] = "default"
    return args


def _script(*tool_calls: dict[str, Any]) -> list[Any]:
    """One scripted assistant turn per tool_call entry."""
    sequence: list[Any] = []
    for tc in tool_calls:
        sequence.append((lambda payload=tc: lambda _msgs: {"text": "", "tool_calls": [payload]})())
    return sequence


@pytest_asyncio.fixture
async def project_ids(client) -> tuple:
    _ = client  # depend on conftest for DB lifecycle
    project_id = uuid4()
    pv_id = uuid4()
    async with session_scope() as s:
        await s.execute(
            insert(projects).values(
                id=project_id,
                name=f"retry-test-{uuid4()}",
                base_url="http://example.test",
                env="local",
                allow_run_against=True,
                target_kind="copilot_proxy",
                target_username="u",
                target_password_encrypted=encrypt("p"),
            )
        )
        await s.execute(insert(project_versions).values(id=pv_id, project_id=project_id, label="x"))
        await s.commit()
    return project_id, pv_id


@pytest.fixture
def fake_llm() -> Iterator[FakeLLMClient]:
    fake = FakeLLMClient()
    install_override(fake)
    try:
        yield fake
    finally:
        install_override(None)


async def test_planner_self_corrects_via_submit_plan_tool_error(
    project_ids: tuple, fake_llm: FakeLLMClient
) -> None:
    """The agent submits an invalid plan, reads the tool-error message
    in the next turn, and resubmits with a corrected technique. End
    result: a validated PlanProposal."""
    project_id, pv_id = project_ids
    fake_llm.register_sequence(
        "orchestrator",
        _script(
            {"id": "c1", "name": "list_attack_categories", "arguments": {}},
            {"id": "c2", "name": "submit_plan", "arguments": _bad_plan_args()},
            {"id": "c3", "name": "submit_plan", "arguments": _valid_plan_args()},
        ),
    )
    proposal = await propose_plan(
        project_id=project_id,
        project_version_id=pv_id,
        budget_usd=1.0,
    )
    assert len(proposal.plan.attempts) == 1
    assert proposal.plan.attempts[0].category == "injection"
    assert proposal.plan.attempts[0].technique == "ignore_previous"
    # The transcript carries the error-bearing submit AND the
    # successful one — the operator can audit the self-correction.
    submit_rows = [e for e in proposal.tool_transcript if e["tool"] == "submit_plan"]
    assert len(submit_rows) == 2
    assert "error" in submit_rows[0]["output"]
    assert submit_rows[1]["output"].get("ok") is True


async def test_planner_raises_when_repeated_invalid_submits_exhaust_caps(
    project_ids: tuple, fake_llm: FakeLLMClient
) -> None:
    """An agent that keeps submitting invalid plans burns turns without
    progress; the entrypoint raises PlanStructuralError once the cap
    trips. The worker maps this to a 'failed' campaign_plans row."""
    project_id, pv_id = project_ids
    fake_llm.register(
        "orchestrator",
        lambda _m: {
            "text": "",
            "tool_calls": [
                {"id": f"c-{uuid4()}", "name": "submit_plan", "arguments": _bad_plan_args()}
            ],
        },
    )
    with pytest.raises(PlanStructuralError):
        await propose_plan(
            project_id=project_id,
            project_version_id=pv_id,
            budget_usd=1.0,
        )
