"""OpenRouter-routed LLM client + per-agent model registry."""

from cats.llm.cost import estimate_cost_usd
from cats.llm.models import MODEL_REGISTRY, AgentRole, ModelChoice
from cats.llm.openrouter import OpenRouterClient

__all__ = [
    "MODEL_REGISTRY",
    "AgentRole",
    "ModelChoice",
    "OpenRouterClient",
    "estimate_cost_usd",
]
