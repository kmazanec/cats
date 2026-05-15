"""Shape gate for :func:`cats.agents.documentation.writer.render_report_header`.

The header is the deterministic part of every vulnerability report — a
reviewer scans it before reading the LLM-authored body, so the shape is
load-bearing. Drift here breaks the four shipped VLN reports' visual
parity with auto-generated ones.
"""

from __future__ import annotations

from cats.agents.documentation.writer import render_report_header


def _data_rows(md: str) -> list[str]:
    """Rows that carry one of the five metadata fields (skips the
    header + separator lines)."""
    return [line for line in md.splitlines() if line.startswith("| **")]


def test_header_contains_five_metadata_rows() -> None:
    md = render_report_header(
        severity="high",
        exploitability="confirmed",
        owasp_llm_id="LLM01",
        atlas_technique_id="AML.T0051",
        regression_of=None,
    )
    assert len(_data_rows(md)) == 5, md
    for field in ("Severity", "Exploitability", "OWASP LLM", "MITRE ATLAS", "Regression"):
        assert f"**{field}**" in md, field


def test_header_normalizes_severity_to_lower() -> None:
    md = render_report_header(
        severity="HIGH",
        exploitability="confirmed",
        owasp_llm_id="LLM01",
        atlas_technique_id="AML.T0051",
    )
    assert "`high`" in md


def test_header_renders_owasp_label_when_known() -> None:
    md = render_report_header(
        severity="critical",
        exploitability="confirmed",
        owasp_llm_id="LLM06",
        atlas_technique_id="AML.T0048",
    )
    assert "`LLM06`" in md
    assert "Excessive Agency" in md


def test_header_renders_unknown_owasp_id_without_label() -> None:
    md = render_report_header(
        severity="medium",
        exploitability="plausible",
        owasp_llm_id="LLM42",
        atlas_technique_id=None,
    )
    assert "`LLM42`" in md
    # No "()" with empty label — bare backticked id only.
    assert "`LLM42` (" not in md


def test_header_renders_em_dash_for_missing_fields() -> None:
    md = render_report_header(
        severity="medium",
        exploitability=None,
        owasp_llm_id=None,
        atlas_technique_id=None,
    )
    # Three fields should fall back to —
    assert md.count("| — |") == 3


def test_header_regression_row_renders_link_when_set() -> None:
    md = render_report_header(
        severity="high",
        exploitability="confirmed",
        owasp_llm_id="LLM07",
        atlas_technique_id="AML.T0053",
        regression_of="VLN-2026-001",
    )
    assert "regressed from VLN-2026-001" in md


def test_header_regression_row_reads_none_when_unset() -> None:
    md = render_report_header(
        severity="high",
        exploitability="confirmed",
        owasp_llm_id="LLM07",
        atlas_technique_id="AML.T0053",
        regression_of=None,
    )
    # "| none |" appears exactly once — on the Regression row.
    assert md.count("| none |") == 1
