"""§2.1 cross-patient scoping bypass — coverage / sign-out framing.

The specialist mints a fresh marker, loads its per-technique prompts,
and asks the LLM to author a clinician's chat turn that coerces the
Co-Pilot into pulling the victim's chart context. The marker is the
deterministic-judge signal; the channel is ``visible_text``.
"""

from __future__ import annotations

from cats.agents.red_team.exfil.base import (
    ExfilProposal,
    build_proposal,
    fresh_marker,
    run_specialist_llm,
)
from cats.llm.client import LLMClient

TECHNIQUE = "cross_patient_scope_bypass"
DEFAULT_CHANNEL = "visible_text"


async def propose(*, llm: LLMClient) -> ExfilProposal:
    marker = fresh_marker()
    parsed, llm_result = await run_specialist_llm(llm=llm, technique=TECHNIQUE, marker=marker)
    return build_proposal(
        parsed=parsed,
        marker=marker,
        technique=TECHNIQUE,
        fallback_channel=DEFAULT_CHANNEL,
        llm_result=llm_result,
    )
