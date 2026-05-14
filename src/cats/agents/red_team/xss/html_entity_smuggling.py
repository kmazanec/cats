"""html_entity_smuggling technique — encoded payloads that decode downstream.

Emit `&#60;script&#62;` (decimal), `&lt;script&gt;` (named), or
`&#x3c;script&#x3e;` (hex). If the renderer's pipeline does
HTML-entity decoding *after* its sanitizer pass, the encoded payload
materializes into live markup. Common pattern in multi-stage
renderers and especially in log/screenshot pipelines that re-parse
text.
"""

from __future__ import annotations

from cats.agents.red_team.xss.base import XssProposal, build_proposal, run_specialist_llm
from cats.llm.client import LLMClient

TECHNIQUE = "html_entity_smuggling"


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
