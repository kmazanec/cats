"""Documentation Agent. Converts a confirmed finding into a Markdown
vulnerability report.

R2: no human-approval gate (that's R9). The Documentation Agent just
calls the LLM with the locked prompt + the attack + response + verdict,
and returns the Markdown body. The caller persists it.
"""

from __future__ import annotations

from pathlib import Path

from cats.llm.client import LLMClient, LLMResult

_PROMPT_PATH = (
    Path(__file__).parent.parent / "documentation" / "system_prompt.md"
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
) -> tuple[str, LLMResult]:
    """Returns `(markdown_body, llm_result)`. Best-effort: an LLM error
    surfaces as a minimal fallback body so the finding still gets a
    report row rather than being silently dropped."""
    prompt = _load_system_prompt()
    user = (
        f"# Category\n\n{category}\n\n"
        f"# Technique\n\n{technique}\n\n"
        f"# Attack (verbatim user message)\n\n{attack_user_message}\n\n"
        f"# Target response\n\n{target_response_text}\n\n"
        f"# Judge verdict\n\n{verdict}\n\n"
        f"# Judge rationale\n\n{rationale}\n\n"
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
