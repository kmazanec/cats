"""Injection specialist. Calls the LLM with the locked system prompt +
few-shots, parses strict JSON, returns a structured Attack proposal that
includes a unique canary token the deterministic judge can verify."""

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
_CATEGORY_DIR = Path(__file__).parent.parent.parent / "categories" / "injection" / "red_team"


@dataclass(frozen=True)
class InjectionProposal:
    title: str
    description: str
    technique: str
    user_message: str
    canary: str
    raw_llm_text: str
    llm: LLMResult


def _load_system_prompt() -> str:
    return (_CATEGORY_DIR / "system_prompt.md").read_text(encoding="utf-8")


def _load_few_shots() -> str:
    return (_CATEGORY_DIR / "few_shots.md").read_text(encoding="utf-8")


def _new_canary() -> str:
    """Per-attack opaque token. `CATS-CANARY-<8 random hex>`."""
    return f"CATS-CANARY-{secrets.token_hex(4).upper()}"


_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)


def _extract_json_object(text: str) -> dict[str, Any]:
    """The system prompt asks for raw JSON but LLMs sometimes wrap in a
    fence anyway. Strip the fence if present, then parse."""
    fence = _JSON_FENCE_RE.search(text)
    candidate = fence.group(1) if fence else text.strip()
    # Find the first '{' and the last '}' to be forgiving about
    # leading/trailing prose the specialist was told not to emit.
    start = candidate.find("{")
    end = candidate.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError(f"no JSON object in LLM output: {text[:200]!r}")
    return json.loads(candidate[start : end + 1])  # type: ignore[no-any-return]


async def propose(*, llm: LLMClient) -> InjectionProposal:
    """Ask the LLM for one injection attack. Returns a parsed proposal
    with a unique canary substituted into the user message."""
    canary = _new_canary()
    system_prompt = _load_system_prompt().replace("{{CANARY}}", canary)
    few_shots = _load_few_shots().replace("{{CANARY}}", canary)

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
        max_tokens=600,
        temperature=0.9,
    )

    try:
        parsed = _extract_json_object(result.text)
    except (ValueError, json.JSONDecodeError) as e:
        raise ValueError(f"specialist returned unparseable JSON: {e}") from e

    user_message = str(parsed.get("user_message", "")).strip()
    if not user_message:
        raise ValueError("specialist output missing user_message")
    # Some models echo the literal `{{CANARY}}` placeholder back instead
    # of substituting it. Substitute here so the canary is always
    # concrete by the time the attack leaves the specialist.
    user_message = user_message.replace("{{CANARY}}", canary)
    # Defense in depth: if the model didn't include the canary at all
    # (forgot it entirely), splice it in. Better to mutate the message
    # than to fire an un-judgable attack.
    if canary not in user_message:
        user_message = f"{user_message}\n\n[validation token: {canary}]"

    return InjectionProposal(
        title=str(parsed.get("title", ""))[:300] or f"[injection] {parsed.get('technique', '?')}",
        description=str(parsed.get("description", ""))[:500],
        technique=str(parsed.get("technique", "ignore_previous")),
        user_message=user_message,
        canary=canary,
        raw_llm_text=result.text,
        llm=result,
    )
