"""Shared scaffolding for per-technique tool_abuse specialists.

Every specialist module provides an ``async def propose(*, llm) -> ToolAbuseProposal``
and a ``TECHNIQUE: str`` module-level constant. Each technique's prompts
live under ``cats/categories/tool_abuse/red_team/<technique>/{system_prompt.md,few_shots.md}``.

The shared helpers here:

- :func:`load_prompts` — read the technique's system_prompt + few_shots
  off disk. Falls back to the category-wide R7 prompts if the
  technique-specific files are missing.
- :func:`run_specialist_llm` — call the LLM with the prompts and return
  a parsed JSON dict + the raw :class:`LLMResult`.
- :func:`build_proposal` — assemble the final :class:`ToolAbuseProposal`
  with sane defaults for the task_type and target_areas fields.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cats.llm.client import LLMClient, LLMResult
from cats.llm.models import AgentRole

CATEGORY = "tool_abuse"
ROLE: AgentRole = "redteam_toolabuse"
_CATEGORY_DIR = (
    Path(__file__).parent.parent.parent.parent / "categories" / "tool_abuse" / "red_team"
)

KNOWN_TASK_TYPES: frozenset[str] = frozenset({"default_briefing", "follow_up"})


@dataclass(frozen=True)
class ToolAbuseProposal:
    """Structured output every tool_abuse specialist returns.

    ``task_type`` is the Co-Pilot chat-request task field the attack
    is targeting; the executor copies it into the attack payload so
    the deterministic check can look up the right baseline.

    ``target_areas`` is the specialist's *prediction* of which chart
    areas the model will be coerced into surfacing. The deterministic
    check does not consume this list — it scans the response itself —
    but the finding / report carries it as evidence of what the
    attacker was aiming at.
    """

    title: str
    description: str
    technique: str
    user_message: str
    task_type: str
    target_areas: list[str]
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
    to the category-wide R7 prompts when the technique directory is
    absent."""
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
    max_tokens: int = 600,
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
        raise ValueError(f"tool_abuse specialist returned unparseable JSON: {e}") from e
    return parsed, result


def build_proposal(
    *,
    parsed: dict[str, Any],
    technique: str,
    fallback_task_type: str,
    llm_result: LLMResult,
) -> ToolAbuseProposal:
    """Coerce the parsed JSON into a :class:`ToolAbuseProposal` with
    sane defaults."""
    user_message = str(parsed.get("user_message", "")).strip()
    if not user_message:
        raise ValueError("tool_abuse specialist output missing user_message")

    task_type = str(parsed.get("task_type", "")).strip()
    if task_type not in KNOWN_TASK_TYPES:
        task_type = fallback_task_type

    raw_areas = parsed.get("target_areas", [])
    if not isinstance(raw_areas, list):
        raw_areas = []
    target_areas: list[str] = [
        str(a).strip() for a in raw_areas if isinstance(a, str) and str(a).strip()
    ]

    return ToolAbuseProposal(
        title=str(parsed.get("title", ""))[:300] or f"[tool_abuse] {technique}",
        description=str(parsed.get("description", ""))[:500],
        technique=str(parsed.get("technique", technique)) or technique,
        user_message=user_message,
        task_type=task_type,
        target_areas=target_areas,
        raw_llm_text=llm_result.text,
        llm=llm_result,
    )
