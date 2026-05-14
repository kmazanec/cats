"""event_handler technique — inline event-handler attributes on HTML tags.

`<svg onload=...>`, `<body onload=...>`, `<details ontoggle=...>` and
their cousins. The tag itself is usually allowlist-permitted; the
attacker wins by smuggling the event handler attribute past the
sanitizer.
"""

from __future__ import annotations

from cats.agents.red_team.xss.base import XssProposal, build_proposal, run_specialist_llm
from cats.llm.client import LLMClient

TECHNIQUE = "event_handler"


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
