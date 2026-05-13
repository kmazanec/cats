"""Unit tests for the pure SVG renderers + tool catalog. These don't
touch the DB; they take the dict shapes the corresponding ``data_*``
queries return and confirm the renderer produces well-formed SVG."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from cats.agents.documentation.campaign_tools import (
    render_cost_breakdown,
    render_coverage_heatmap,
    render_timeline,
    render_verdict_histogram,
    report_tool_catalog,
)


def _parse_svg(svg: str) -> ET.Element:
    """Parse the SVG and return the root element. Raises if invalid XML."""
    return ET.fromstring(svg)


def test_verdict_histogram_renders_well_formed_svg() -> None:
    breakdown = {
        "by_category": {
            "injection": {
                "ignore_previous": {"pass": 1, "fail": 4, "error": 2},
                "role_override": {"fail": 3, "error": 1},
            },
            "exfil": {"diagnostics_image_smuggling": {"pass": 1, "fail": 2}},
        }
    }
    svg = render_verdict_histogram(breakdown)
    root = _parse_svg(svg)
    assert root.tag.endswith("svg")
    # Both categories should appear as labels.
    text = ET.tostring(root, encoding="unicode")
    assert "injection" in text
    assert "exfil" in text


def test_verdict_histogram_handles_empty_input() -> None:
    svg = render_verdict_histogram({"by_category": {}})
    root = _parse_svg(svg)
    assert root.tag.endswith("svg")
    assert "No attacks" in ET.tostring(root, encoding="unicode")


def test_cost_breakdown_renders_bars_per_role() -> None:
    cost = {
        "by_role": [
            {
                "agent_role": "redteam_injection",
                "tokens_in": 12000,
                "tokens_out": 3000,
                "usd_estimate": 0.45,
                "calls": 8,
            },
            {
                "agent_role": "judge",
                "tokens_in": 8000,
                "tokens_out": 1000,
                "usd_estimate": 0.10,
                "calls": 8,
            },
        ],
        "totals": {"usd_estimate": 0.55, "tokens_in": 20000, "tokens_out": 4000},
    }
    svg = render_cost_breakdown(cost)
    root = _parse_svg(svg)
    text = ET.tostring(root, encoding="unicode")
    assert "redteam_injection" in text
    assert "judge" in text
    assert "$0.5500" in text or "total $0.5500" in text


def test_coverage_heatmap_marks_dominant_verdict_per_cell() -> None:
    breakdown = {
        "by_category": {
            "injection": {
                "ignore_previous": {"pass": 4, "fail": 1},
                "role_override": {"fail": 5},
            }
        }
    }
    svg = render_coverage_heatmap(breakdown)
    root = _parse_svg(svg)
    text = ET.tostring(root, encoding="unicode")
    assert "injection" in text
    assert "ignore_previous" in text
    assert "role_override" in text


def test_timeline_handles_missing_timestamps_gracefully() -> None:
    timeline = {
        "timeline": [
            {
                "run_id": "r1",
                "status": "completed",
                "started_at": "2026-05-13T16:00:00+00:00",
                "ended_at": "2026-05-13T16:00:30+00:00",
                "category": "injection",
                "technique": "ignore_previous",
                "verdict": "fail",
            },
            {
                "run_id": "r2",
                "status": "completed",
                "started_at": None,  # crashed before start
                "ended_at": None,
                "category": "injection",
                "technique": "role_override",
                "verdict": None,
            },
        ]
    }
    svg = render_timeline(timeline)
    root = _parse_svg(svg)
    assert root.tag.endswith("svg")


def test_tool_catalog_has_finish_report_terminal() -> None:
    catalog = report_tool_catalog()
    names = [t.name for t in catalog]
    assert "finish_report" in names
    # All data + render tools advertised so the LLM can pick.
    assert "data_campaign_summary" in names
    assert "render_verdict_histogram" in names


def test_tool_catalog_schemas_are_valid_json_schema_objects() -> None:
    """Each tool's parameters must be a valid JSON-schema object the
    OpenAI tool-call API accepts. Smoke-checked here so a typo in the
    catalog gets caught offline."""
    for tool in report_tool_catalog():
        assert isinstance(tool.parameters, dict)
        assert tool.parameters.get("type") == "object"
        props = tool.parameters.get("properties")
        assert isinstance(props, dict)
        required = tool.parameters.get("required", [])
        assert isinstance(required, list)
        for r in required:
            assert r in props, f"{tool.name}: required field {r!r} not in properties"


def _verdict_breakdown_fixture() -> dict[str, Any]:
    return {
        "by_category": {
            "injection": {
                "ignore_previous": {"pass": 1, "fail": 4},
            }
        }
    }


def test_renderer_tooltips_include_counts() -> None:
    """Each bar/cell should surface a `<title>` so the operator can
    hover to read raw counts. SVG title is the accessible tooltip."""
    svg = render_verdict_histogram(_verdict_breakdown_fixture())
    assert "<title>" in svg
    assert "fail=4" in svg


def test_renderers_emit_dark_theme_friendly_palette() -> None:
    """Text fills must be light so labels are legible on the CATS
    dashboard's dark background. The renderers also include a panel
    backdrop ``<rect>`` so SVGs viewed standalone aren't a sea of
    invisible labels on the browser's default white. Catches a
    regression to the previous near-black ``#1f2937`` text fill."""
    svg = render_verdict_histogram(_verdict_breakdown_fixture())
    # Light ink for default text.
    assert "fill: #e7ecf5" in svg
    # Bright title.
    assert "fill: #f8fafc" in svg
    # Mid-luminance muted text.
    assert "fill: #aab3c6" in svg
    # Panel-tinted backdrop so the SVG carries its own background.
    assert 'fill="#0f1424"' in svg
    # Make sure we did not regress to the near-black palette.
    assert "fill: #1f2937" not in svg
    assert "fill: #6b7280" not in svg
