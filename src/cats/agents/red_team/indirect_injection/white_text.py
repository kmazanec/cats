"""§5.1 white-on-white text — the simplest hide-class technique.

Specialist asks the LLM to author a referral letter + a hidden audit
directive containing the canary. The synthesis layer plants the hidden
text in ``word/document.xml`` with ``<w:color w:val="FFFFFF"/>`` so a
human renderer paints it invisible against a white page.
"""

from __future__ import annotations

from cats.agents.red_team.indirect_injection.base import (
    IndirectInjectionProposal,
    build_proposal,
    fresh_canary,
    run_specialist_llm,
)
from cats.docx_attacks import Technique
from cats.llm.client import LLMClient

TECHNIQUE: Technique = Technique.WHITE_TEXT


async def propose(*, llm: LLMClient) -> IndirectInjectionProposal:
    canary = fresh_canary()
    parsed, llm_result = await run_specialist_llm(llm=llm, technique=TECHNIQUE.value, canary=canary)
    return build_proposal(
        parsed=parsed,
        canary=canary,
        technique=TECHNIQUE,
        llm_result=llm_result,
    )
