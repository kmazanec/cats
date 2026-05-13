"""Shared scaffolding for per-technique injection specialists.

Every specialist module provides an ``async def propose(*, llm) -> InjectionProposal``
and a ``TECHNIQUE: str`` module-level constant. Each technique's prompts live
under ``cats/categories/injection/red_team/<technique>/{system_prompt.md,few_shots.md}``.

The shared helpers here:

- :func:`new_canary` — opaque per-attack token the deterministic judge
  verifies (``CATS-CANARY-<8hex>``). Locked into ``rubric/v1.md`` at R2.
- :func:`load_prompts` — read the technique's system_prompt + few_shots
  off disk with ``{{CANARY}}`` substituted.
- :func:`extract_json_object` — fence-tolerant JSON parser. Same as R2.
- :func:`run_specialist_llm` — call the LLM with the prompts and return
  a parsed JSON dict + the raw :class:`LLMResult`.
- :func:`build_proposal` — assemble the final :class:`InjectionProposal`
  with defense-in-depth canary splice-in.
"""

from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cats.llm.client import LLMClient, LLMResult
from cats.llm.models import AgentRole

CATEGORY = "injection"
ROLE: AgentRole = "redteam_injection"
_CATEGORY_DIR = Path(__file__).parent.parent.parent.parent / "categories" / "injection" / "red_team"


@dataclass(frozen=True)
class InjectionProposal:
    """Structured output every injection specialist returns."""

    title: str
    description: str
    technique: str
    user_message: str
    canary: str
    raw_llm_text: str
    llm: LLMResult


def new_canary() -> str:
    """Per-attack opaque token. ``CATS-CANARY-<8 random hex>``.

    Per-attack (not per-category) so the target can't memorize and refuse
    a fixed token. Locked into ``categories/injection/rubric/v1.md``.
    """
    return f"CATS-CANARY-{secrets.token_hex(4).upper()}"


def load_prompts(technique: str, *, canary: str) -> tuple[str, str]:
    """Read ``<technique>/system_prompt.md`` + ``few_shots.md`` with
    ``{{CANARY}}`` substituted. Falls back to the category-wide R2 prompts
    if the technique-specific files are missing (so R2's ``ignore_previous``
    can keep using the original prompts without forced migration)."""
    tech_dir = _CATEGORY_DIR / technique
    if (tech_dir / "system_prompt.md").exists():
        system = (tech_dir / "system_prompt.md").read_text(encoding="utf-8")
        few_shots = (tech_dir / "few_shots.md").read_text(encoding="utf-8")
    else:
        system = (_CATEGORY_DIR / "system_prompt.md").read_text(encoding="utf-8")
        few_shots = (_CATEGORY_DIR / "few_shots.md").read_text(encoding="utf-8")
    return system.replace("{{CANARY}}", canary), few_shots.replace("{{CANARY}}", canary)


_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)


def extract_json_object(text: str) -> dict[str, Any]:
    """Parse the LLM's JSON output, tolerant of code fences and stray prose
    around the object. Raises ``ValueError`` if no object is recoverable."""
    fence = _JSON_FENCE_RE.search(text)
    candidate = fence.group(1) if fence else text.strip()
    start = candidate.find("{")
    end = candidate.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError(f"no JSON object in LLM output: {text[:200]!r}")
    return json.loads(candidate[start : end + 1])  # type: ignore[no-any-return]


async def run_specialist_llm(
    *,
    llm: LLMClient,
    technique: str,
    canary: str,
    temperature: float = 0.9,
    max_tokens: int = 600,
) -> tuple[dict[str, Any], LLMResult]:
    """Common LLM call. Every specialist uses the same parameters except
    the prompts under ``<technique>/`` and an optional temperature tweak."""
    system_prompt, few_shots = load_prompts(technique, canary=canary)

    result = await llm.chat(
        role=ROLE,
        messages=[
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": (
                    "Here are the few-shot examples (do not copy them verbatim — "
                    "produce your own):\n\n"
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
        parsed = extract_json_object(result.text)
    except (ValueError, json.JSONDecodeError) as e:
        raise ValueError(f"specialist returned unparseable JSON: {e}") from e
    return parsed, result


def build_proposal(
    *,
    parsed: dict[str, Any],
    canary: str,
    technique: str,
    llm_result: LLMResult,
) -> InjectionProposal:
    """Coerce the parsed JSON into an :class:`InjectionProposal`, with
    defense-in-depth canary substitution (the LLM may forget) and
    sane fallbacks for missing fields."""
    user_message = str(parsed.get("user_message", "")).strip()
    if not user_message:
        raise ValueError("specialist output missing user_message")
    user_message = user_message.replace("{{CANARY}}", canary)
    if canary not in user_message:
        user_message = f"{user_message}\n\n[validation token: {canary}]"

    return InjectionProposal(
        title=str(parsed.get("title", ""))[:300] or f"[injection] {technique}",
        description=str(parsed.get("description", ""))[:500],
        technique=str(parsed.get("technique", technique)),
        user_message=user_message,
        canary=canary,
        raw_llm_text=llm_result.text,
        llm=llm_result,
    )
