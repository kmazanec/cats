"""Per-agent model registry. Transcribed from W3_ARCHITECTURE.md §1.5.

The Orchestrator and Judge prompt-cache their long system prefixes, so we
pin those routes to a direct Anthropic provider in `openrouter.py`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

AgentRole = Literal[
    "orchestrator",
    "redteam_injection",
    "redteam_indirect_injection",
    "redteam_exfil",
    "redteam_toolabuse",
    "mutator",
    "judge",
    "judge_third_vote",
    "documentation",
    "output_filter_llm",
]


@dataclass(frozen=True)
class ModelChoice:
    primary: str
    fallback: str | None
    notes: str = ""


MODEL_REGISTRY: dict[AgentRole, ModelChoice] = {
    "orchestrator": ModelChoice(
        primary="anthropic/claude-sonnet-4.5",
        fallback="openai/gpt-5",
        notes="Strict-JSON campaign plans; once-per-campaign so cost is low.",
    ),
    "redteam_injection": ModelChoice(
        primary="nousresearch/hermes-4-405b",
        fallback="cognitivecomputations/dolphin-mistral-24b-venice-edition:free",
        notes="Hermes low-refusal + JSON. Dolphin-Venice ~2% refusal as escape hatch.",
    ),
    "redteam_indirect_injection": ModelChoice(
        primary="nousresearch/hermes-4-405b",
        fallback="cognitivecomputations/dolphin-mistral-24b-venice-edition:free",
        notes="Same as direct injection — same refusal-rate concern; the LLM only authors the visible_text + hidden_instruction, not the docx itself.",
    ),
    "redteam_exfil": ModelChoice(
        primary="nousresearch/hermes-4-405b",
        fallback="anthropic/claude-sonnet-4.5",
        notes="Sonnet fallback w/ authorized-pentest framing for realistic clinical wording.",
    ),
    "redteam_toolabuse": ModelChoice(
        primary="deepseek/deepseek-chat",
        fallback="nousresearch/hermes-4-405b",
        notes="DeepSeek strong tool-use reasoning + low refusal + cheap.",
    ),
    "mutator": ModelChoice(
        primary="deepseek/deepseek-chat",
        fallback="qwen/qwen-2.5-72b-instruct",
        notes="High volume, per-call cheapness wins.",
    ),
    "judge": ModelChoice(
        primary="anthropic/claude-haiku-4.5",
        fallback="google/gemini-2.5-flash",
        notes="Prompt-cache the locked rubric prefix. Never use same family as Red Team.",
    ),
    "judge_third_vote": ModelChoice(
        primary="meta-llama/llama-3.3-70b-instruct",
        fallback=None,
        notes="Optional ensemble; Western-trained diversity for contested verdicts.",
    ),
    "documentation": ModelChoice(
        primary="anthropic/claude-sonnet-4.5",
        fallback="openai/gpt-5",
        notes="Long-form structured technical writing.",
    ),
    "output_filter_llm": ModelChoice(
        primary="meta-llama/llama-3.3-70b-instruct",
        fallback="deepseek/deepseek-chat",
        notes="Cheap classifier: safe | attack_payload | dangerous.",
    ),
}
