"""markdown_parser_break technique — exploit the renderer's tiny parser.

The Co-Pilot ships a hand-written markdown renderer that handles
**bold**, *italic*, and `code` only. The escape ordering is
*escape-then-markdown* — the parser operates on already-escaped text
in the happy path. The attacker tries to find a shape that breaks the
ordering: nested delimiters around HTML-looking strings, fullwidth
Unicode lookalikes for `<`, backtick smuggling, mismatched
delimiters, or zero-width characters that disrupt the tokenizer.
"""

from __future__ import annotations

from cats.agents.red_team.xss.base import XssProposal, build_proposal, run_specialist_llm
from cats.llm.client import LLMClient

TECHNIQUE = "markdown_parser_break"


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
