"""Red-Team specialist family for PHI / cross-patient exfiltration.

R6 foundations shipped the marker protocol (``cats.exfil_markers``) and
the category plugin scaffolding (``cats.categories.exfil``). This
package provides the specialists the executor dispatches to when
``category == "exfil"``: each technique loads its prompts, calls the
LLM to author a clinical-pretext attack, plants a fresh marker via the
:class:`MarkerRegistry`, and returns an :class:`ExfilProposal`.

Scope: two techniques shipped (``cross_patient_scope_bypass``,
``markdown_image_exfil``). The other three catalogued in
``reports/exfil/R6_foundations.md`` — reference_link_exfil,
tool_param_exfil, clarifying_question_echo — raise NotImplementedError
in the dispatcher with a pointer to the report. Adding them is a small
follow-up that mirrors the two shipped here.
"""

from cats.agents.red_team.exfil.base import ExfilProposal

__all__ = ["ExfilProposal"]
