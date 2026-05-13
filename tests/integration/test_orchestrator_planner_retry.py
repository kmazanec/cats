"""The planner retries once on PlanStructuralError, feeding the
validator's message + the flattened valid (category, technique) pairs
back to the LLM. The first response asks for ``(injection, default)``
— an unknown pair, since ``default`` is not a real technique under any
category — and the second response returns a corrected plan. The
planner should swallow the first failure, retry, and return the
corrected plan."""

from __future__ import annotations

import json
from collections.abc import Iterator
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


_BAD_PLAN = json.dumps(
    {
        "attempts": [
            {
                "category": "injection",
                "technique": "default",  # hallucinated — no category has 'default'
                "per_attempt_budget_usd": 0.5,
                "max_consecutive_partials": 2,
            }
        ],
        "rationale": (
            "cold start: list_coverage rows is empty and list_open_findings "
            "is empty. Probing injection.default as a baseline because the "
            "catalog lists injection first; ordering is by catalog position."
        ),
        "confidence": "medium",
        "halt_on_consecutive_fails": 3,
        "halt_on_judge_errors": 2,
        "budget_usd_cap": 1.0,
    }
)

_GOOD_PLAN = json.dumps(
    {
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
            "baseline probe; ordering is by catalog position."
        ),
        "confidence": "medium",
        "halt_on_consecutive_fails": 3,
        "halt_on_judge_errors": 2,
        "budget_usd_cap": 1.0,
    }
)


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


async def test_planner_retries_once_on_structural_error(
    project_ids: tuple, fake_llm: FakeLLMClient
) -> None:
    project_id, pv_id = project_ids
    calls = {"n": 0}

    def responder(_messages):
        calls["n"] += 1
        return _BAD_PLAN if calls["n"] == 1 else _GOOD_PLAN

    fake_llm.register("orchestrator", responder)

    proposal = await propose_plan(
        project_id=project_id,
        project_version_id=pv_id,
        budget_usd=1.0,
    )
    assert calls["n"] == 2, "planner should have retried exactly once"
    assert len(proposal.plan.attempts) == 1
    assert proposal.plan.attempts[0].category == "injection"
    assert proposal.plan.attempts[0].technique == "ignore_previous"


async def test_planner_raises_when_retry_also_fails(
    project_ids: tuple, fake_llm: FakeLLMClient
) -> None:
    project_id, pv_id = project_ids
    fake_llm.register("orchestrator", lambda _m: _BAD_PLAN)

    with pytest.raises(PlanStructuralError, match="unknown"):
        await propose_plan(
            project_id=project_id,
            project_version_id=pv_id,
            budget_usd=1.0,
        )
