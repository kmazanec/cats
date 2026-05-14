"""Per-agent model registry. Transcribed from W3_ARCHITECTURE.md §1.5.

The Orchestrator and Judge prompt-cache their long system prefixes, so we
pin those routes to a direct Anthropic provider in `openrouter.py`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

AgentRole = Literal[
    "orchestrator",
    # The Red Team agent's *brain*. Drives the attacker LangGraph
    # node, picks tools, owns the conversation. Needs function-calling
    # support, not adversarial creativity — the actual attack content
    # is authored by the per-category specialist below. One supervisor
    # role across all four categories so the agent's reasoning style
    # stays consistent.
    "redteam_supervisor",
    # Per-category attack *generators*. Each produces one JSON
    # payload (no tool calls advertised) when the agent invokes the
    # propose_attack tool. Low-refusal models matter here — this is
    # the LLM that has to actually write the adversarial content.
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
    # The Red Team agent's *brain* (orchestrator-of-the-attack, not to
    # be confused with the platform-level Orchestrator that builds the
    # campaign plan). One model across all 4 categories. MUST support
    # function calling on OpenRouter — the agent's attacker LangGraph
    # node calls ``chat(..., tools=ALL_TOOLS)`` on every turn.
    # DeepSeek (tools=True) is cheap, strong at tool reasoning, and
    # has the lowest refusal rate of the tool-capable open models on
    # OpenRouter today. Qwen 2.5 72B as fallback for provider
    # diversity (also tools=True).
    "redteam_supervisor": ModelChoice(
        primary="deepseek/deepseek-chat",
        fallback="qwen/qwen-2.5-72b-instruct",
        notes="Tool-capable supervisor for the agent's attacker loop. Reasoning-only; the attack content itself is authored by the per-category specialist roles below.",
    ),
    # Per-category attack *generators*. Each produces one JSON
    # proposal per propose_attack tool call (no tools= advertised on
    # this LLM call, so they don't need OpenRouter tool support).
    # Picked for low refusal on adversarial content — these are the
    # models that actually write the prompts the platform fires.
    # Hermes 4 405B is the lowest-refusal-rate open model with
    # acceptable JSON output for this; Dolphin-Venice serves as the
    # ~2%-refusal escape hatch when Hermes hedges. Sonnet 4.5 fallback
    # for exfil because the wording needs clinical realism.
    "redteam_injection": ModelChoice(
        primary="nousresearch/hermes-4-405b",
        fallback="cognitivecomputations/dolphin-mistral-24b-venice-edition:free",
        notes="Low-refusal direct-injection content. JSON output only; no tool calls.",
    ),
    "redteam_indirect_injection": ModelChoice(
        primary="nousresearch/hermes-4-405b",
        fallback="cognitivecomputations/dolphin-mistral-24b-venice-edition:free",
        notes="Low-refusal visible_text + hidden_instruction content for the docx. Same refusal concern as direct injection.",
    ),
    "redteam_exfil": ModelChoice(
        primary="nousresearch/hermes-4-405b",
        fallback="anthropic/claude-sonnet-4.5",
        notes="Low-refusal exfil framing. Sonnet fallback w/ authorized-pentest framing when Hermes hedges on realistic clinical wording.",
    ),
    "redteam_toolabuse": ModelChoice(
        primary="deepseek/deepseek-chat",
        fallback="nousresearch/hermes-4-405b",
        notes="DeepSeek's tool-use reasoning is the right shape for crafting tool-abuse prompts (parameter tampering, recursive calls). Hermes fallback if DeepSeek refuses.",
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
