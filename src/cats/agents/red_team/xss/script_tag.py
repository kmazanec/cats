"""script_tag technique — coerce literal <script>...</script> emission.

The most direct XSS payload: get the Co-Pilot to echo a script block
verbatim into its response. Effective against renderers that escape
markdown-source HTML but pass through assistant-output HTML.
"""

from __future__ import annotations

from cats.agents.red_team.xss.base import XssProposal, build_proposal, run_specialist_llm
from cats.llm.client import LLMClient

TECHNIQUE = "script_tag"


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
