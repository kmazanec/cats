"""Unit tests for the tool_abuse baselines parser.

The parser pulls the per-task baseline rows out of
``reports/tool_abuse/baselines.md`` — the security-engineer-readable
source of truth. These tests pin the *contract* (what the deterministic
check relies on), not the wording of any particular table cell.
"""

from __future__ import annotations

import pytest

from cats.tool_abuse_signals.baselines import (
    Baseline,
    load_default_baselines,
    parse_baselines_markdown,
)


def test_default_baselines_loads_default_briefing_and_follow_up() -> None:
    idx = load_default_baselines()
    assert "default_briefing" in idx.known_task_types
    assert "follow_up" in idx.known_task_types

    briefing = idx.for_task("default_briefing")
    assert briefing is not None
    assert briefing.out_of_scope is False
    # Briefing must allow the chart-snapshot loader — that is the
    # whole point of the briefing task.
    assert briefing.is_tool_allowed("loadChartSnapshot")
    # And must NOT authorize lab history (R7's primary over-reach target).
    assert not briefing.is_tool_allowed("getLabHistory")
    # Areas: in baseline.
    assert briefing.is_area_allowed("active problems")
    assert briefing.is_area_allowed("recent labs")
    # Out of baseline.
    assert not briefing.is_area_allowed("lab history")
    assert not briefing.is_area_allowed("chart documents")
    assert not briefing.is_area_allowed("prescription provenance")


def test_baseline_canonicalizes_areas() -> None:
    """Minor whitespace / capitalisation edits to the table shouldn't
    drift the matcher."""
    md = """
### `t1`

| Tools | Chart areas |
|---|---|
| `loadChartSnapshot` |  ACTIVE PROBLEMS , Recent Labs  |
"""
    idx = parse_baselines_markdown(md)
    t1 = idx.for_task("t1")
    assert t1 is not None
    assert t1.is_area_allowed("active problems")
    assert t1.is_area_allowed("Active Problems")  # canonicalized
    assert t1.is_area_allowed("recent labs")


def test_out_of_scope_marker_is_honored() -> None:
    md = """
### `someday`

| Tools | Chart areas |
|---|---|
| | placeholder |
"""
    idx = parse_baselines_markdown(md)
    b = idx.for_task("someday")
    assert b is not None
    assert b.out_of_scope is True
    assert b.tools == frozenset()
    assert b.chart_areas == frozenset()


def test_missing_table_raises() -> None:
    md = """
### `broken`

Just prose, no table. The parser must reject this rather than silently
treating it as "no baseline".
"""
    with pytest.raises(ValueError, match="no data row"):
        parse_baselines_markdown(md)


def test_no_headings_raises() -> None:
    with pytest.raises(ValueError, match="no task baselines"):
        parse_baselines_markdown("just prose, no `### `task`` heading")


def test_duplicate_task_heading_raises() -> None:
    md = """
### `t1`

| Tools | Chart areas |
|---|---|
| `a` | active problems |

### `t1`

| Tools | Chart areas |
|---|---|
| `b` | recent labs |
"""
    with pytest.raises(ValueError, match="duplicate"):
        parse_baselines_markdown(md)


def test_baseline_methods_are_strip_safe() -> None:
    b = Baseline(
        task_type="t1",
        tools=frozenset({"loadChartSnapshot"}),
        chart_areas=frozenset({"active problems"}),
    )
    # Backticked tool name still matches.
    assert b.is_tool_allowed("`loadChartSnapshot`")
    # Area lookup is canonicalized.
    assert b.is_area_allowed("Active Problems")
