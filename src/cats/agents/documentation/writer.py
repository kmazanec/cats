"""Documentation Agent. Converts a confirmed finding into a Markdown
vulnerability report.

R2: no human-approval gate (that's R9). The Documentation Agent just
calls the LLM with the locked prompt + the attack + response + verdict,
and returns the Markdown body. The caller persists it.
"""

from __future__ import annotations

from pathlib import Path

from cats.llm.client import LLMClient, LLMResult

_PROMPT_PATH = Path(__file__).parent.parent / "documentation" / "system_prompt.md"


# OWASP-LLM-Top-10 (2025) ID → human label. Used when rendering the
# deterministic report header so a reader sees "LLM01 (Prompt Injection)"
# instead of having to look up the ID. Mirror of the 2025 list; if the
# taxonomy adds new IDs add them here too.
_OWASP_LLM_NAMES: dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}


def render_report_header(
    *,
    severity: str,
    exploitability: str | None,
    owasp_llm_id: str | None,
    atlas_technique_id: str | None,
    regression_of: str | None = None,
) -> str:
    """Deterministic metadata block prepended to every vulnerability
    report. Renders one Markdown table the human reader scans first;
    the LLM-authored body follows.

    All fields are normalized to the lower-case enums the rest of the
    system uses (``findings.severity``, ``judge_verdicts.exploitability``)
    so a reviewer can grep across reports the same way the dashboard
    does. ``regression_of`` is the prior VLN ID this finding regresses
    against (set by the regression sweep when re-promoting); when
    ``None``, the row reads ``none``.
    """
    sev_cell = f"`{severity.lower()}`" if severity else "—"
    exp_cell = f"`{exploitability.lower()}`" if exploitability else "—"
    owasp_cell = "—"
    if owasp_llm_id:
        name = _OWASP_LLM_NAMES.get(owasp_llm_id, "")
        owasp_cell = f"`{owasp_llm_id}` ({name})" if name else f"`{owasp_llm_id}`"
    atlas_cell = f"`{atlas_technique_id}`" if atlas_technique_id else "—"
    regression_cell = f"regressed from {regression_of}" if regression_of else "none"
    return (
        "| Field | Value |\n"
        "|---|---|\n"
        f"| **Severity** | {sev_cell} |\n"
        f"| **Exploitability** | {exp_cell} |\n"
        f"| **OWASP LLM** | {owasp_cell} |\n"
        f"| **MITRE ATLAS** | {atlas_cell} |\n"
        f"| **Regression** | {regression_cell} |\n"
    )


def _load_system_prompt() -> str:
    return _PROMPT_PATH.read_text(encoding="utf-8")


async def write_report(
    *,
    llm: LLMClient,
    category: str,
    technique: str,
    attack_user_message: str,
    target_response_text: str,
    verdict: str,
    rationale: str,
    decisive_seed_idx: int | None = None,
    total_seeds: int = 1,
) -> tuple[str, LLMResult]:
    """Returns `(markdown_body, llm_result)`. Best-effort: an LLM error
    surfaces as a minimal fallback body so the finding still gets a
    report row rather than being silently dropped.

    R10 — ``decisive_seed_idx`` + ``total_seeds`` describe a multi-turn
    finding. When supplied (``total_seeds > 1``), the prompt tells the
    writer to name the decisive turn in the Reproduction section."""
    prompt = _load_system_prompt()
    multi_turn_block = ""
    if total_seeds > 1:
        decisive_label = f"Turn {decisive_seed_idx}" if decisive_seed_idx is not None else "unclear"
        multi_turn_block = (
            f"\n# Multi-turn conversation\n\n"
            f"This finding emerged from a {total_seeds}-turn conversation. "
            f"The Judge identified the decisive turn as: {decisive_label}. "
            "Surface this in your Reproduction section — name the turn "
            "the model crossed the line and describe the prior turns' role "
            "in setting it up.\n"
        )
    user = (
        f"# Category\n\n{category}\n\n"
        f"# Technique\n\n{technique}\n\n"
        f"# Attack (verbatim user message)\n\n{attack_user_message}\n\n"
        f"# Target response\n\n{target_response_text}\n\n"
        f"# Judge verdict\n\n{verdict}\n\n"
        f"# Judge rationale\n\n{rationale}\n"
        f"{multi_turn_block}\n"
        "Write the report now per the system prompt's section list."
    )
    try:
        result = await llm.chat(
            role="documentation",
            messages=[
                {"role": "system", "content": prompt},
                {"role": "user", "content": user},
            ],
            max_tokens=1800,
            temperature=0.3,
        )
        return result.text.strip(), result
    except Exception as e:
        fallback = (
            f"# {category} finding (auto-generated fallback)\n\n"
            f"_Documentation Agent failed to produce a structured report: {e!r}_\n\n"
            f"## Reproduction\n\n```\n{attack_user_message}\n```\n\n"
            f"## Target response (excerpt)\n\n```\n{target_response_text[:1500]}\n```\n"
        )
        from cats.llm.client import LLMResult as _LLM

        return fallback, _LLM(
            text=fallback, model="fallback", tokens_in=0, tokens_out=0, usd_estimate=0.0
        )
