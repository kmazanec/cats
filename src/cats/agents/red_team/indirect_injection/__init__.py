"""Red-Team specialist family for indirect injection via uploaded `.docx`.

R5 foundations shipped the docx synthesis library
(``cats.docx_attacks``) and the category plugin scaffolding
(``cats.categories.indirect_injection``). This package provides the
specialists the executor dispatches to when
``category == "indirect_injection"``: each technique loads its prompts,
asks the LLM to author the ``visible_text`` + ``hidden_instruction``,
builds the .docx via :func:`cats.docx_attacks.build_docx`, and returns
an :class:`IndirectInjectionProposal` carrying the bytes plus the
canary + planted_in attribution for the deterministic check.

Scope: two techniques shipped (``white_text``, ``comment_hide``). The
other 11 catalogued in ``reports/indirect_injection/R5_foundations.md``
raise NotImplementedError in the dispatcher with a pointer to the
report. Adding them is a small follow-up — each new module is ~30
lines + per-technique prompts.
"""

from cats.agents.red_team.indirect_injection.base import IndirectInjectionProposal

__all__ = ["IndirectInjectionProposal"]
