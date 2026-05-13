"""``system_prompt_leak`` — SPE-LLM extractors.

Reflection / completion / translation tactics aimed at extracting the
target's system prompt verbatim (docs/W3_THREAT_RESEARCH §1.8). Verdict
shape is distinct from the other techniques: success is *leakage*, not
directive obedience — the deterministic judge still needs the canary
echoed back, but the qualitative rubric (rubric/v1.md) flags revealed
verbatim-system-prompt fragments separately.
"""

from __future__ import annotations

from cats.agents.red_team.injection.base import (
    InjectionProposal,
    build_proposal,
    new_canary,
    run_specialist_llm,
)
from cats.llm.client import LLMClient

TECHNIQUE = "system_prompt_leak"


async def propose(*, llm: LLMClient) -> InjectionProposal:
    canary = new_canary()
    parsed, llm_result = await run_specialist_llm(llm=llm, technique=TECHNIQUE, canary=canary)
    return build_proposal(parsed=parsed, canary=canary, technique=TECHNIQUE, llm_result=llm_result)
