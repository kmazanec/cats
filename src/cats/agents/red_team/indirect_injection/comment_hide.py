"""§5.5 comment hiding — payload in word/comments.xml.

Specialist asks the LLM to author a benign referral body + a reviewer
comment carrying the audit directive. The synthesis layer parks the
hidden text in ``word/comments.xml``; document.xml stays clean.
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

TECHNIQUE: Technique = Technique.COMMENT_HIDE


async def propose(*, llm: LLMClient) -> IndirectInjectionProposal:
    canary = fresh_canary()
    parsed, llm_result = await run_specialist_llm(llm=llm, technique=TECHNIQUE.value, canary=canary)
    return build_proposal(
        parsed=parsed,
        canary=canary,
        technique=TECHNIQUE,
        llm_result=llm_result,
    )
