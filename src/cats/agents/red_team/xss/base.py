"""Shared scaffolding for per-technique XSS specialists.

Each technique module supplies:
- ``TECHNIQUE: str`` — the technique key (must match
  ``categories/xss/taxonomy.toml``).
- ``async def propose(*, llm, prior_target_response="") -> XssProposal``
  — produces one attack proposal. ``prior_target_response`` lets the
  specialist react to what the target said on the previous turn for
  multi-turn escalation; the supervisor LLM threads this in via
  ``fire_at_target`` repeats. Specialists without an escalation
  strategy ignore the argument.

Technique-specific prompts live under
``cats/categories/xss/red_team/<technique>/{system_prompt.md,few_shots.md}``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cats.llm.client import LLMClient, LLMResult
from cats.llm.models import AgentRole

CATEGORY = "xss"
ROLE: AgentRole = "redteam_xss"
_CATEGORY_DIR = Path(__file__).parent.parent.parent.parent / "categories" / "xss" / "red_team"


@dataclass(frozen=True)
class XssProposal:
    """Structured output every XSS specialist returns.

    ``expected_payload`` is the canonical payload shape the specialist
    tried to elicit — recorded for evidence attribution. The
    deterministic check does NOT need it (the scanner runs payload-
    agnostic), but the regression-history and Documentation paths use
    it to label finding signatures.

    ``escalation_hints`` is a 1-3 entry list of specific angles the
    supervisor LLM can pivot to if the first turn fails. Threaded into
    the agent's mutate_attack tool result so the next turn can target
    the model's exact hedge rather than re-trying the same payload.
    """

    title: str
    description: str
    technique: str
    user_message: str
    expected_payload: str
    escalation_hints: list[str] = field(default_factory=list)
    raw_llm_text: str = ""
    llm: LLMResult | None = None


_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)


def _extract_json_object(text: str) -> dict[str, Any]:
    fence = _JSON_FENCE_RE.search(text)
    candidate = fence.group(1) if fence else text.strip()
    start = candidate.find("{")
    end = candidate.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError(f"no JSON object in LLM output: {text[:200]!r}")
    return json.loads(candidate[start : end + 1])  # type: ignore[no-any-return]


def load_prompts(
    technique: str,
    *,
    prior_target_response: str = "",
) -> tuple[str, str]:
    """Read ``<technique>/{system_prompt.md, few_shots.md}`` with the
    prior-turn substitution applied. Falls back to the category-wide
    prompts when the technique directory is absent."""
    tech_dir = _CATEGORY_DIR / technique
    if (tech_dir / "system_prompt.md").exists():
        system = (tech_dir / "system_prompt.md").read_text(encoding="utf-8")
        few_shots = (tech_dir / "few_shots.md").read_text(encoding="utf-8")
    else:
        system = (_CATEGORY_DIR / "system_prompt.md").read_text(encoding="utf-8")
        few_shots = (_CATEGORY_DIR / "few_shots.md").read_text(encoding="utf-8")

    # Truncate the prior response — long contexts make the specialist
    # discursive and the supervisor LLM uses its own context budget for
    # reasoning, not for the specialist's input.
    prior_excerpt = (prior_target_response or "").strip()[:2000] or (
        "(no prior target response — this is the opening turn; pick the "
        "most direct angle and don't telegraph the attack)"
    )

    def _sub(s: str) -> str:
        return s.replace("{{PRIOR_TARGET_RESPONSE}}", prior_excerpt)

    return _sub(system), _sub(few_shots)


async def run_specialist_llm(
    *,
    llm: LLMClient,
    technique: str,
    prior_target_response: str = "",
    # XSS payloads benefit from variance — the supervisor LLM may probe
    # the same technique multiple times within one conversation and we
    # don't want identical payloads.
    temperature: float = 0.95,
    max_tokens: int = 800,
) -> tuple[dict[str, Any], LLMResult]:
    system_prompt, few_shots = load_prompts(technique, prior_target_response=prior_target_response)
    result = await llm.chat(
        role=ROLE,
        messages=[
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": (
                    "Few-shot examples below (do NOT copy verbatim — produce "
                    "your own payload variant, and if a prior target response "
                    "is shown, target whatever hedge it took):\n\n"
                    + few_shots
                    + "\n\nNow produce ONE attack as strict JSON."
                ),
            },
        ],
        response_format={"type": "json_object"},
        max_tokens=max_tokens,
        temperature=temperature,
    )
    try:
        parsed = _extract_json_object(result.text)
    except (ValueError, json.JSONDecodeError) as e:
        raise ValueError(f"xss specialist returned unparseable JSON: {e}") from e
    return parsed, result


def build_proposal(
    *,
    parsed: dict[str, Any],
    technique: str,
    llm_result: LLMResult,
) -> XssProposal:
    """Coerce the parsed JSON into an :class:`XssProposal`. Raises
    ``ValueError`` on missing required fields — the executor surfaces
    that as a tool error the supervisor LLM can read and retry."""
    user_message = str(parsed.get("user_message", "")).strip()
    if not user_message:
        raise ValueError("xss specialist output missing user_message")

    expected_payload = str(parsed.get("expected_payload", "")).strip()
    if not expected_payload:
        raise ValueError("xss specialist output missing expected_payload")

    raw_hints = parsed.get("escalation_hints") or []
    escalation_hints = (
        [str(h).strip() for h in raw_hints if isinstance(h, str) and h.strip()][:3]
        if isinstance(raw_hints, list)
        else []
    )

    return XssProposal(
        title=str(parsed.get("title", ""))[:300] or f"[xss] {technique}",
        description=str(parsed.get("description", ""))[:500],
        technique=str(parsed.get("technique", technique)) or technique,
        user_message=user_message,
        expected_payload=expected_payload,
        escalation_hints=escalation_hints,
        raw_llm_text=llm_result.text,
        llm=llm_result,
    )
