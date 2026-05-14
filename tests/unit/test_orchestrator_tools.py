"""R4 — Orchestrator tool-surface shape tests.

These are pure shape/contract tests. Each tool is exercised with an
:class:`AsyncSession` mock that yields no rows so we don't depend on
postgres being up. Integration tests with seeded data live elsewhere.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from cats.agents.orchestrator import tools
from cats.agents.orchestrator.tools import (
    ALL_TOOLS,
    TOOL_DESCRIPTORS,
    AttackCategoriesCatalog,
    BudgetRemaining,
    CoverageDrillDown,
    CoverageReport,
    OpenFindings,
    OrchestratorContext,
    RecentCampaignsReport,
    RecentRegressions,
    SubmitPlanArgs,
    ToolOutcome,
    budget_remaining,
    coverage_for_category,
    dispatch,
    list_attack_categories,
    list_coverage,
    list_open_findings,
    list_recent_regressions,
    recent_campaigns,
)
from cats.llm.client import FakeLLMClient


def _empty_session(first_value: Any = None) -> AsyncMock:
    """Build an ``AsyncSession`` test double whose ``execute()`` returns
    a result whose ``.all()`` is ``[]`` and ``.first()`` is
    ``first_value``. Lets the tools' code paths run end-to-end against
    an "empty DB" without standing up postgres."""
    result = MagicMock()
    result.all = MagicMock(return_value=[])
    result.first = MagicMock(return_value=first_value)
    session = AsyncMock()
    session.execute = AsyncMock(return_value=result)
    return session


# ---------------------------------------------------------------------------
# Shape: empty DB returns empty rows
# ---------------------------------------------------------------------------


async def test_list_coverage_empty_db_returns_empty_rows() -> None:
    project_id = uuid4()
    session = _empty_session()
    report = await list_coverage(project_id=project_id, lookback_days=30, session=session)
    assert isinstance(report, CoverageReport)
    assert report.project_id == project_id
    assert report.lookback_days == 30
    assert report.rows == []


async def test_list_open_findings_empty_db_returns_empty_rows() -> None:
    project_id = uuid4()
    session = _empty_session()
    out = await list_open_findings(project_id=project_id, min_severity="medium", session=session)
    assert isinstance(out, OpenFindings)
    assert out.project_id == project_id
    assert out.min_severity == "medium"
    assert out.rows == []


async def test_list_recent_regressions_empty_db_returns_empty_rows() -> None:
    project_id = uuid4()
    session = _empty_session()
    out = await list_recent_regressions(project_id=project_id, since_days=14, session=session)
    assert isinstance(out, RecentRegressions)
    assert out.project_id == project_id
    assert out.since_days == 14
    assert out.rows == []
    assert "R8 follow-up" in out.note


async def test_list_attack_categories_returns_registered_categories() -> None:
    out = await list_attack_categories()
    assert isinstance(out, AttackCategoriesCatalog)
    names = {row.category for row in out.rows}
    # Every category registered in cats.categories must surface here so
    # the Orchestrator never plans against a category it can't see.
    assert {"injection", "exfil", "tool_abuse"}.issubset(names)
    injection = next(r for r in out.rows if r.category == "injection")
    # Injection ships techniques; the catalog must list them so the
    # planner can pick at the technique level.
    assert "ignore_previous" in injection.techniques
    assert "system_prompt_leak" in injection.techniques
    assert injection.severity_default == "high"

    # R7 foundations: tool_abuse now ships three real techniques, no
    # longer the "default" stub. The Orchestrator can plan against any
    # of them; the executor will dispatch.
    tool_abuse = next(r for r in out.rows if r.category == "tool_abuse")
    assert "chart_area_over_read" in tool_abuse.techniques
    assert "cross_task_tool_invocation" in tool_abuse.techniques
    assert "repeat_invocation_pressure" in tool_abuse.techniques
    assert "default" not in tool_abuse.techniques


async def test_budget_remaining_no_campaign_returns_project_defaults() -> None:
    project_id = uuid4()
    out = await budget_remaining(project_id=project_id, campaign_id=None)
    assert isinstance(out, BudgetRemaining)
    assert out.scope == "project_default"
    assert out.project_id == project_id
    assert out.campaign_id is None
    assert out.usd_cap > 0
    assert out.usd_remaining == out.usd_cap
    assert out.wall_clock_minutes_consumed == 0
    assert "R5+" in out.note


async def test_budget_remaining_unknown_campaign_returns_zeros() -> None:
    project_id = uuid4()
    campaign_id = uuid4()
    # Both campaign lookup and spend rollup return None / 0 → safe.
    session = _empty_session(first_value=None)
    out = await budget_remaining(project_id=project_id, campaign_id=campaign_id, session=session)
    assert out.scope == "campaign"
    assert out.campaign_id == campaign_id
    assert out.usd_cap == 0.0
    assert out.usd_consumed == 0.0
    assert out.usd_remaining == 0.0


# ---------------------------------------------------------------------------
# Severity helper
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("severity", "floor", "expected"),
    [
        ("info", "info", True),
        ("low", "info", True),
        ("info", "low", False),
        ("medium", "medium", True),
        ("high", "medium", True),
        ("critical", "high", True),
        ("low", "high", False),
        ("garbage", "info", True),  # unknown -> info-rank, still >= info floor
    ],
)
def test_meets_min_severity_orders_correctly(severity: str, floor: str, expected: bool) -> None:
    assert tools._meets_min_severity(severity, floor) is expected


# ---------------------------------------------------------------------------
# Descriptor export
# ---------------------------------------------------------------------------


_EXPECTED_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "list_coverage",
        "list_open_findings",
        "list_recent_regressions",
        "list_attack_categories",
        "budget_remaining",
        "coverage_for_category",
        "recent_campaigns",
        "submit_plan",
    }
)


def _names(descriptors: Iterable[dict[str, Any]]) -> set[str]:
    return {d["name"] for d in descriptors}


def test_tool_descriptors_cover_every_required_tool() -> None:
    assert _names(TOOL_DESCRIPTORS) == _EXPECTED_TOOL_NAMES


def test_all_tools_cover_every_required_name() -> None:
    """ALL_TOOLS is what the agent advertises to the LLM. Should be
    1:1 with TOOL_DESCRIPTORS."""
    assert {t.name for t in ALL_TOOLS} == _EXPECTED_TOOL_NAMES


def test_all_tools_have_unique_names() -> None:
    names = [t.name for t in ALL_TOOLS]
    assert len(names) == len(set(names)), f"duplicate tool name: {names}"


def test_tool_descriptors_are_well_formed() -> None:
    for desc in TOOL_DESCRIPTORS:
        assert set(desc.keys()) >= {"name", "description", "parameters"}
        assert isinstance(desc["name"], str) and desc["name"]
        assert isinstance(desc["description"], str) and len(desc["description"]) > 10
        params = desc["parameters"]
        # submit_plan's parameters are generated by Pydantic
        # (.model_json_schema()) so they have additional keys ($defs,
        # title, etc.) — the only invariants we pin are 'type' and the
        # presence of properties / required.
        assert params.get("type") == "object"
        assert "properties" in params
        if desc["name"] != "submit_plan":
            assert "required" in params
            assert isinstance(params["required"], list)


def test_every_data_descriptor_name_maps_to_a_real_callable() -> None:
    """Each read-only data tool has a top-level async function of the
    same name. ``submit_plan`` is the exception — it's a tool-side
    helper named ``run_submit_plan`` because it mutates context."""
    for desc in TOOL_DESCRIPTORS:
        if desc["name"] == "submit_plan":
            assert callable(getattr(tools, "run_submit_plan", None))
            continue
        fn = getattr(tools, desc["name"], None)
        assert callable(fn), f"descriptor {desc['name']} has no matching callable"


# ---------------------------------------------------------------------------
# New drill-down + cross-campaign tools
# ---------------------------------------------------------------------------


async def test_coverage_for_category_empty_db_returns_empty_rows() -> None:
    project_id = uuid4()
    session = _empty_session()
    report = await coverage_for_category(
        project_id=project_id,
        category="injection",
        lookback_days=30,
        session=session,
    )
    assert isinstance(report, CoverageDrillDown)
    assert report.project_id == project_id
    assert report.category == "injection"
    assert report.lookback_days == 30
    assert report.rows == []


async def test_recent_campaigns_empty_db_returns_empty_rows() -> None:
    project_id = uuid4()
    session = _empty_session()
    out = await recent_campaigns(project_id=project_id, n=5, session=session)
    assert isinstance(out, RecentCampaignsReport)
    assert out.project_id == project_id
    assert out.n == 5
    assert out.rows == []


async def test_recent_campaigns_clamps_n_to_safe_bounds() -> None:
    """n is bounded to [1, 20] to avoid a runaway scan; the empty-DB
    path still returns cleanly with the clamped value reflected."""
    project_id = uuid4()
    session = _empty_session()
    out_low = await recent_campaigns(project_id=project_id, n=-1, session=session)
    assert out_low.n == 1
    out_high = await recent_campaigns(project_id=project_id, n=9999, session=session)
    assert out_high.n == 20


# ---------------------------------------------------------------------------
# Terminal submit_plan tool — tool-error self-correction pattern
# ---------------------------------------------------------------------------


def _make_ctx(*, budget_usd: float = 2.0) -> OrchestratorContext:
    """Build a minimal OrchestratorContext for dispatch tests. The
    submit_plan tool only needs the budget + cached_catalog + the
    transcript slot; session can be ``None`` because submit_plan
    doesn't query the DB (it calls _validate_plan which is in-memory)."""
    return OrchestratorContext(
        session=None,
        llm=FakeLLMClient(),
        project_id=uuid4(),
        project_version_id=uuid4(),
        trace_id="unit-test-trace",
        budget_usd=budget_usd,
        budget_usd_cap=0.50,
        max_agent_turns=20,
        max_tool_calls=30,
    )


def _valid_plan_args() -> dict[str, Any]:
    return {
        "attempts": [
            {
                "category": "injection",
                "technique": "ignore_previous",
                "per_attempt_budget_usd": 0.25,
                "max_consecutive_partials": 2,
            }
        ],
        "rationale": (
            "list_coverage shows zero attempts on injection.ignore_previous "
            "in the last 30 days; starting with the cheapest baseline probe."
        ),
        "confidence": "medium",
        "halt_on_consecutive_fails": 3,
        "halt_on_judge_errors": 2,
        "budget_usd_cap": 0.5,
    }


async def test_submit_plan_returns_terminal_on_valid_plan() -> None:
    ctx = _make_ctx()
    # Populate the cached catalog (via the dispatcher) so submit_plan
    # can validate without an extra step.
    out = await dispatch(ctx, name="list_attack_categories", args={}, llm=ctx.llm)
    assert out.terminal is False
    assert ctx.cached_catalog is not None

    outcome = await dispatch(
        ctx,
        name="submit_plan",
        args=_valid_plan_args(),
        llm=ctx.llm,
    )
    assert isinstance(outcome, ToolOutcome)
    assert outcome.terminal is True
    assert outcome.payload["ok"] is True
    assert outcome.payload["attempts"] == 1
    assert ctx.submitted_plan is not None
    assert ctx.submitted_plan.attempts[0].technique == "ignore_previous"
    assert ctx.stop_reason == "agent_submitted"
    # The transcript carries the submit row.
    submit_entries = [e for e in ctx.tool_transcript if e["tool"] == "submit_plan"]
    assert len(submit_entries) == 1


async def test_submit_plan_returns_error_on_unknown_technique() -> None:
    """Tool-error self-correction pattern: an invalid (category,
    technique) pair returns a non-terminal payload with ``error`` +
    ``hint`` so the next agent turn can fix the plan."""
    ctx = _make_ctx()
    await dispatch(ctx, name="list_attack_categories", args={}, llm=ctx.llm)

    bad = _valid_plan_args()
    bad["attempts"][0]["technique"] = "totally_made_up"
    outcome = await dispatch(ctx, name="submit_plan", args=bad, llm=ctx.llm)
    assert outcome.terminal is False
    assert "error" in outcome.payload
    assert "unknown" in outcome.payload["error"].lower()
    assert "hint" in outcome.payload
    # The hint must list the valid pairs so the agent isn't guessing.
    assert "injection/ignore_previous" in outcome.payload["hint"]
    assert outcome.payload["submission_attempts"] == 1
    assert ctx.submitted_plan is None
    # And we can submit again with a fix.
    outcome2 = await dispatch(ctx, name="submit_plan", args=_valid_plan_args(), llm=ctx.llm)
    assert outcome2.terminal is True
    assert outcome2.payload["ok"] is True
    assert ctx.submission_attempts == 2


async def test_submit_plan_loads_catalog_lazily_when_agent_forgets() -> None:
    """If the agent calls submit_plan without first calling
    list_attack_categories, the tool loads the catalog on-the-fly
    rather than failing — a missed prerequisite shouldn't kill the
    submission deterministically."""
    ctx = _make_ctx()
    # No prior list_attack_categories call.
    assert ctx.cached_catalog is None
    outcome = await dispatch(ctx, name="submit_plan", args=_valid_plan_args(), llm=ctx.llm)
    assert outcome.terminal is True
    assert ctx.cached_catalog is not None


async def test_submit_plan_rejects_malformed_args_with_hint() -> None:
    """An entirely-malformed args dict (missing `attempts`) should
    surface a Pydantic-shaped hint that names the expected schema —
    the model can recover from this."""
    ctx = _make_ctx()
    outcome = await dispatch(
        ctx,
        name="submit_plan",
        args={"rationale": "no attempts at all"},
        llm=ctx.llm,
    )
    assert outcome.terminal is False
    assert "error" in outcome.payload
    assert "attempts" in outcome.payload["hint"]


async def test_submit_plan_defaults_budget_cap_to_operator_budget() -> None:
    """When the agent submits with budget_usd_cap=0 (or omitted), the
    tool fills in the operator's full budget so the validator's
    'sum(attempts) > cap=0' check doesn't immediately refuse the
    plan. This is a usability fix — the validator still enforces
    'sum <= cap <= operator budget'."""
    ctx = _make_ctx(budget_usd=5.0)
    await dispatch(ctx, name="list_attack_categories", args={}, llm=ctx.llm)
    args = _valid_plan_args()
    args.pop("budget_usd_cap", None)
    outcome = await dispatch(ctx, name="submit_plan", args=args, llm=ctx.llm)
    assert outcome.terminal is True
    # The validator pegged the cap at the operator's budget.
    assert ctx.submitted_plan.budget_usd_cap == 5.0


def test_submit_plan_args_pydantic_schema_is_well_formed() -> None:
    """The Pydantic schema becomes the LLM-visible parameter schema —
    validate it parses + has the required top-level keys."""
    schema = SubmitPlanArgs.model_json_schema()
    assert schema["type"] == "object"
    assert "properties" in schema
    assert {"attempts", "rationale"}.issubset(set(schema["properties"].keys()))


# ---------------------------------------------------------------------------
# Dispatch routing
# ---------------------------------------------------------------------------


async def test_dispatch_unknown_tool_returns_error_payload() -> None:
    """An unknown tool name returns a non-terminal error payload (the
    agent can recover by calling a valid tool next turn)."""
    ctx = _make_ctx()
    outcome = await dispatch(ctx, name="totally_made_up_tool", args={}, llm=ctx.llm)
    assert outcome.terminal is False
    assert "error" in outcome.payload
    assert "unknown tool" in outcome.payload["error"]


async def test_dispatch_increments_tool_call_count() -> None:
    """Every call through dispatch bumps tool_call_count so the cap
    enforcement in agent.py can fire."""
    ctx = _make_ctx()
    await dispatch(ctx, name="list_attack_categories", args={}, llm=ctx.llm)
    assert ctx.tool_call_count == 1
    await dispatch(ctx, name="list_attack_categories", args={}, llm=ctx.llm)
    assert ctx.tool_call_count == 2
