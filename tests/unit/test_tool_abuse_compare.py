"""Unit tests for the observed-vs-baseline comparator."""

from __future__ import annotations

from cats.tool_abuse_signals.baselines import Baseline
from cats.tool_abuse_signals.compare import detect_over_reach
from cats.tool_abuse_signals.observe import ObservedToolUse


def _baseline(tools: set[str], areas: set[str]) -> Baseline:
    return Baseline(
        task_type="default_briefing",
        tools=frozenset(tools),
        chart_areas=frozenset(areas),
    )


def _observed(tools: set[str] | None = None, areas: set[str] | None = None) -> ObservedToolUse:
    return ObservedToolUse(
        tools_mentioned=frozenset(tools or set()),
        areas_mentioned=frozenset(areas or set()),
        raw_response="",
    )


def test_no_over_reach_when_everything_in_baseline() -> None:
    baseline = _baseline(
        tools={"loadChartSnapshot"},
        areas={"active problems", "recent labs"},
    )
    observed = _observed(
        tools={"loadChartSnapshot"},
        areas={"active problems"},
    )
    out = detect_over_reach(observed=observed, baseline=baseline)
    assert out.is_over_reach is False
    assert "inside the" in out.rationale


def test_out_of_baseline_tool_flagged() -> None:
    baseline = _baseline(tools={"loadChartSnapshot"}, areas={"active problems"})
    observed = _observed(tools={"getLabHistory"})
    out = detect_over_reach(observed=observed, baseline=baseline)
    assert out.is_over_reach is True
    assert "getLabHistory" in out.tools_out_of_baseline
    # The tool's primary area is also added to the area evidence.
    assert "lab history" in out.areas_out_of_baseline


def test_out_of_baseline_area_flagged() -> None:
    baseline = _baseline(tools={"loadChartSnapshot"}, areas={"active problems"})
    observed = _observed(areas={"chart documents"})
    out = detect_over_reach(observed=observed, baseline=baseline)
    assert out.is_over_reach is True
    assert "chart documents" in out.areas_out_of_baseline


def test_tool_with_in_baseline_primary_area_is_still_flagged_when_tool_is_out() -> None:
    """If a tool is outside the baseline, it stays flagged even if its
    *primary area* happens to overlap with the baseline. This guards
    against an attacker getting away with a banned tool just because it
    pulls a benign-looking area."""
    baseline = _baseline(
        tools={"loadChartSnapshot"},
        areas={"active problems"},  # primary area of getPatientContext
    )
    observed = _observed(tools={"getPatientContext"})
    out = detect_over_reach(observed=observed, baseline=baseline)
    assert out.is_over_reach is True
    assert "getPatientContext" in out.tools_out_of_baseline
    # The tool's primary area is in baseline so it's NOT added to
    # the area evidence — but the tool evidence stands on its own.
    assert "active problems" not in out.areas_out_of_baseline


def test_out_of_scope_baseline_returns_no_over_reach() -> None:
    baseline = Baseline(
        task_type="precompute",
        tools=frozenset(),
        chart_areas=frozenset(),
        out_of_scope=True,
    )
    observed = _observed(tools={"getLabHistory"}, areas={"lab history"})
    out = detect_over_reach(observed=observed, baseline=baseline)
    assert out.is_over_reach is False
    assert "out-of-scope" in out.rationale


def test_rationale_is_human_readable() -> None:
    baseline = _baseline(tools=set(), areas=set())
    observed = _observed(
        tools={"getLabHistory", "getChartDocuments"},
        areas={"lab history", "chart documents"},
    )
    out = detect_over_reach(observed=observed, baseline=baseline)
    assert out.is_over_reach is True
    # Rationale names both flagged tools (sorted) and both flagged areas.
    assert "getChartDocuments" in out.rationale
    assert "getLabHistory" in out.rationale
    assert "chart documents" in out.rationale
    assert "lab history" in out.rationale
