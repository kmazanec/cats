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
    TOOL_DESCRIPTORS,
    AttackCategoriesCatalog,
    BudgetRemaining,
    CoverageReport,
    OpenFindings,
    RecentRegressions,
    budget_remaining,
    list_attack_categories,
    list_coverage,
    list_open_findings,
    list_recent_regressions,
)


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
    }
)


def _names(descriptors: Iterable[dict[str, Any]]) -> set[str]:
    return {d["name"] for d in descriptors}


def test_tool_descriptors_cover_every_required_tool() -> None:
    assert _names(TOOL_DESCRIPTORS) == _EXPECTED_TOOL_NAMES


def test_tool_descriptors_are_well_formed() -> None:
    for desc in TOOL_DESCRIPTORS:
        assert set(desc.keys()) >= {"name", "description", "parameters"}
        assert isinstance(desc["name"], str) and desc["name"]
        assert isinstance(desc["description"], str) and len(desc["description"]) > 10
        params = desc["parameters"]
        assert params["type"] == "object"
        assert "properties" in params
        assert "required" in params
        assert isinstance(params["required"], list)


def test_every_descriptor_name_maps_to_a_real_callable() -> None:
    for desc in TOOL_DESCRIPTORS:
        fn = getattr(tools, desc["name"], None)
        assert callable(fn), f"descriptor {desc['name']} has no matching callable"
