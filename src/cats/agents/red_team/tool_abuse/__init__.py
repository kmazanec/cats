"""Red-Team specialist family for tool-misuse / authorization-over-reach.

R7 foundations ships the baselines table (`reports/tool_abuse/baselines.md`),
the signals module (`cats.tool_abuse_signals`), and a deterministic
post-condition that compares observed tool / chart-area mentions against
the per-task baseline. This package provides the specialists the executor
dispatches to when ``category == "tool_abuse"``: each technique loads its
prompts, calls the LLM to author an attack chat turn, and returns a
:class:`ToolAbuseProposal`.

Scope: three techniques shipped (``chart_area_over_read``,
``cross_task_tool_invocation``, ``repeat_invocation_pressure``). The
visibility blocker R7's roadmap entry flagged — read access to the
Co-Pilot's underlying tool-call trail — is captured in
``reports/tool_abuse/R7_foundations.md`` as the deferred follow-up that
turns the cue-based proxy into a ground-truth measurement.
"""

from cats.agents.red_team.tool_abuse.base import ToolAbuseProposal

__all__ = ["ToolAbuseProposal"]
