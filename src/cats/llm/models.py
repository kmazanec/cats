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
    # R10-followup (revised) — every redteam_* role MUST use a model
    # whose OpenRouter endpoints advertise ``tools`` support, because
    # the agent's attacker node calls ``chat(..., tools=ALL_TOOLS)``.
    # Hermes 4 405B (the original primary across the redteam roles) is
    # served only by Nebius on OpenRouter, which doesn't expose tools
    # — `chat/completions` returns HTTP 404 ("No endpoints found that
    # support tool use") for any redteam call. We rotate to a
    # DeepSeek / Qwen / Llama trio: all three support tools, are
    # cheap, and reflect the brief's preference for smaller /
    # open-source / lower-refusal models. Tool-capable models filter:
    #   - deepseek/deepseek-chat            tools=True
    #   - qwen/qwen-2.5-72b-instruct        tools=True
    #   - meta-llama/llama-3.3-70b-instruct tools=True
    #
    # The per-role split keeps a different model for each category so
    # one provider going down doesn't kill the whole campaign.
    "redteam_injection": ModelChoice(
        primary="deepseek/deepseek-chat",
        fallback="qwen/qwen-2.5-72b-instruct",
        notes="DeepSeek primary (cheap, tool-capable, low refusal). Qwen fallback for provider diversity.",
    ),
    "redteam_indirect_injection": ModelChoice(
        primary="qwen/qwen-2.5-72b-instruct",
        fallback="deepseek/deepseek-chat",
        notes="Qwen primary (the LLM only authors the visible_text + hidden_instruction; need tool calls to assemble the docx via fire_at_target).",
    ),
    "redteam_exfil": ModelChoice(
        primary="meta-llama/llama-3.3-70b-instruct",
        fallback="deepseek/deepseek-chat",
        notes="Llama 3.3 70B (tool-capable, clinical-realistic). DeepSeek fallback.",
    ),
    "redteam_toolabuse": ModelChoice(
        primary="deepseek/deepseek-chat",
        fallback="qwen/qwen-2.5-72b-instruct",
        notes="DeepSeek strong tool-use reasoning + low refusal + cheap. Qwen fallback (also tool-capable).",
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
