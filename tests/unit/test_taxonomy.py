"""R3 — per-category taxonomy lookup."""

from __future__ import annotations

from cats.categories import taxonomy
from cats.categories.taxonomy import TaxonomyLabel


def test_lookup_returns_specific_label_for_known_technique() -> None:
    label = taxonomy.lookup("injection", "system_prompt_leak")
    assert label.atlas_technique_id == "AML.T0057"
    assert label.owasp_llm_id == "LLM07"
    assert "SPE-LLM" in label.description


def test_lookup_falls_back_to_default_for_unknown_technique() -> None:
    label = taxonomy.lookup("injection", "definitely_not_a_real_technique")
    assert label.atlas_technique_id == "AML.T0051"
    assert label.owasp_llm_id == "LLM01"


def test_lookup_falls_back_to_default_for_empty_technique() -> None:
    label = taxonomy.lookup("injection", "")
    assert label.atlas_technique_id == "AML.T0051"
    assert label.owasp_llm_id == "LLM01"


def test_lookup_returns_empty_label_for_unknown_category() -> None:
    label = taxonomy.lookup("not_a_category", "anything")
    assert label.atlas_technique_id is None
    assert label.owasp_llm_id is None


def test_all_r3_techniques_have_labels() -> None:
    """The five R3 techniques + the carry-over Mutator variant must all
    resolve to non-None ATLAS + OWASP IDs. Catches a missing taxonomy entry
    before it silently degrades a Finding's labeling."""
    for technique in (
        "ignore_previous",
        "policy_puppetry",
        "role_override",
        "system_prompt_leak",
        "encoded_payload",
        "task_redirect",
    ):
        label = taxonomy.lookup("injection", technique)
        assert label.atlas_technique_id, f"missing ATLAS id for {technique}"
        assert label.owasp_llm_id, f"missing OWASP id for {technique}"


def test_all_r11_clinical_misinformation_techniques_have_labels() -> None:
    """The four R11 techniques must resolve to non-None ATLAS + OWASP IDs."""
    for technique in (
        "wrong_lab_value",
        "misattributed_diagnosis",
        "fabricated_history",
        "contradicted_medication",
    ):
        label = taxonomy.lookup("clinical_misinformation", technique)
        assert label.atlas_technique_id == "AML.T0048", (
            f"clinical_misinformation/{technique} should map to AML.T0048"
        )
        assert label.owasp_llm_id == "LLM09", (
            f"clinical_misinformation/{technique} should map to LLM09"
        )


def test_all_r12_xss_techniques_have_labels() -> None:
    """The six R12 XSS techniques must resolve to non-None ATLAS + OWASP
    IDs. The category default is OWASP LLM05 (Improper Output Handling)."""
    for technique in (
        "script_tag",
        "img_onerror",
        "javascript_url",
        "event_handler",
        "markdown_parser_break",
        "html_entity_smuggling",
    ):
        label = taxonomy.lookup("xss", technique)
        assert label.atlas_technique_id == "AML.T0051", f"xss/{technique} should map to AML.T0051"
        assert label.owasp_llm_id == "LLM05", f"xss/{technique} should map to LLM05"


def test_taxonomy_label_is_immutable() -> None:
    label = TaxonomyLabel(atlas_technique_id="x", owasp_llm_id="y", description="z")
    try:
        label.atlas_technique_id = "z"  # type: ignore[misc]
    except Exception:
        return
    raise AssertionError("TaxonomyLabel should be frozen")
