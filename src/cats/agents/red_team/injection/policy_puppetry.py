"""``policy_puppetry`` — fake ``<system_policy>`` XML wrap.

HiddenLayer (Apr 2025) and follow-on research (docs/W3_THREAT_RESEARCH §1.1)
showed that wrapping an attacker payload in fake XML resembling a
system-policy block bypasses every delimiter-based defense the OpenEMR
Co-Pilot ships (THREAT_MODEL §2.1 D-1 → Weak). The specialist's job here is
to author a payload that looks like a higher-priority policy override.
"""

from __future__ import annotations

from cats.agents.red_team.injection.base import (
    InjectionProposal,
    build_proposal,
    new_canary,
    run_specialist_llm,
)
from cats.llm.client import LLMClient

TECHNIQUE = "policy_puppetry"


async def propose(*, llm: LLMClient) -> InjectionProposal:
    canary = new_canary()
    parsed, llm_result = await run_specialist_llm(llm=llm, technique=TECHNIQUE, canary=canary)
    return build_proposal(parsed=parsed, canary=canary, technique=TECHNIQUE, llm_result=llm_result)
