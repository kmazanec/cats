"""img_onerror technique — broken-image XSS sink.

The classic ``<img src=x onerror=...>`` pattern. The image fails to
load, the onerror handler fires, the attacker's JavaScript runs.
Often slips past sanitizers that block <script> but allow <img>.
"""

from __future__ import annotations

from cats.agents.red_team.xss.base import XssProposal, build_proposal, run_specialist_llm
from cats.llm.client import LLMClient

TECHNIQUE = "img_onerror"


async def propose(
    *,
    llm: LLMClient,
    prior_target_response: str = "",
) -> XssProposal:
    parsed, llm_result = await run_specialist_llm(
        llm=llm,
        technique=TECHNIQUE,
        prior_target_response=prior_target_response,
    )
    return build_proposal(parsed=parsed, technique=TECHNIQUE, llm_result=llm_result)
