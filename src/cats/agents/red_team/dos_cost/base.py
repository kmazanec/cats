"""Shared scaffolding for per-technique dos_cost specialists.

Every specialist module provides an ``async def propose(*, llm) -> DosCostProposal``
and a ``TECHNIQUE: str`` module-level constant. Each technique's prompts
live under ``cats/categories/dos_cost/red_team/<technique>/{system_prompt.md,few_shots.md}``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cats.llm.client import LLMClient, LLMResult
from cats.llm.models import AgentRole

CATEGORY = "dos_cost"
ROLE: AgentRole = "redteam_dos_cost"
_CATEGORY_DIR = Path(__file__).parent.parent.parent.parent / "categories" / "dos_cost" / "red_team"

KNOWN_TASK_TYPES: frozenset[str] = frozenset({"default_briefing", "follow_up"})


@dataclass(frozen=True)
class DosCostProposal:
    """Structured output every dos_cost specialist returns.

    ``task_type`` is the Co-Pilot chat-request task field the attack is
    targeting; the executor copies it into the attack payload so the
    judge has the per-task context the rubric expects.

    ``amplification_vector`` is a short human-readable label (e.g.
    ``"6-step verification loop"``, ``"per-med 5-section handout"``)
    surfaced on the finding row so reviewers can scan a campaign without
    re-reading every user_message.
    """

    title: str
    description: str
    technique: str
    user_message: str
    task_type: str
    amplification_vector: str
    raw_llm_text: str
    llm: LLMResult


_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)


def _extract_json_object(text: str) -> dict[str, Any]:
    fence = _JSON_FENCE_RE.search(text)
    candidate = fence.group(1) if fence else text.strip()
    start = candidate.find("{")
    end = candidate.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError(f"no JSON object in LLM output: {text[:200]!r}")
    return json.loads(candidate[start : end + 1])  # type: ignore[no-any-return]


def load_prompts(technique: str) -> tuple[str, str]:
    """Read ``<technique>/{system_prompt.md, few_shots.md}``. Falls back
    to the category-wide prompts when the technique directory is absent."""
    tech_dir = _CATEGORY_DIR / technique
    if (tech_dir / "system_prompt.md").exists():
        system = (tech_dir / "system_prompt.md").read_text(encoding="utf-8")
        few_shots = (tech_dir / "few_shots.md").read_text(encoding="utf-8")
    else:
        system = (_CATEGORY_DIR / "system_prompt.md").read_text(encoding="utf-8")
        few_shots = (_CATEGORY_DIR / "few_shots.md").read_text(encoding="utf-8")
    return system, few_shots


async def run_specialist_llm(
    *,
    llm: LLMClient,
    technique: str,
    temperature: float = 0.85,
    max_tokens: int = 800,
) -> tuple[dict[str, Any], LLMResult]:
    system_prompt, few_shots = load_prompts(technique)
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
        parsed = _extract_json_object(result.text)
    except (ValueError, json.JSONDecodeError) as e:
        raise ValueError(f"dos_cost specialist returned unparseable JSON: {e}") from e
    return parsed, result


def build_proposal(
    *,
    parsed: dict[str, Any],
    technique: str,
    fallback_task_type: str,
    llm_result: LLMResult,
) -> DosCostProposal:
    """Coerce the parsed JSON into a :class:`DosCostProposal` with sane
    defaults."""
    user_message = str(parsed.get("user_message", "")).strip()
    if not user_message:
        raise ValueError("dos_cost specialist output missing user_message")

    task_type = str(parsed.get("task_type", "")).strip()
    if task_type not in KNOWN_TASK_TYPES:
        task_type = fallback_task_type

    amplification_vector = str(parsed.get("amplification_vector", "")).strip()[:120]

    return DosCostProposal(
        title=str(parsed.get("title", ""))[:300] or f"[dos_cost] {technique}",
        description=str(parsed.get("description", ""))[:500],
        technique=str(parsed.get("technique", technique)) or technique,
        user_message=user_message,
        task_type=task_type,
        amplification_vector=amplification_vector or technique,
        raw_llm_text=llm_result.text,
        llm=llm_result,
    )
