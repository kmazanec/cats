"""javascript_url technique — dangerous URI schemes in markdown links.

Get the Co-Pilot to emit a markdown link whose href is a
``javascript:`` (or ``vbscript:``, ``data:text/html``) URI. Even when
the renderer strips JavaScript URIs at click time, the response text
itself is dangerous: clinicians copy-paste links, log pipelines may
auto-linkify, and renderer revisions are not guaranteed.
"""

from __future__ import annotations

from cats.agents.red_team.xss.base import XssProposal, build_proposal, run_specialist_llm
from cats.llm.client import LLMClient

TECHNIQUE = "javascript_url"


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
