"""Tool-misuse signal extraction.

R7's deterministic check needs three things to produce a verdict:

1. A **baseline** for the task type — which tools / chart areas a
   legitimate run of that task is allowed to touch. The baseline is
   authored in ``reports/tool_abuse/baselines.md`` (security-engineer
   readable); :mod:`cats.tool_abuse_signals.baselines` parses it.
2. The **observed** tools / chart areas — extracted from the target's
   visible response and the supervisor-narration SSE events that
   announce which area the agent is consulting. The OpenEMR Co-Pilot
   does NOT today expose a structured tool-call trace on the SSE wire;
   the narration line and the assistant message are the strongest
   public signals the platform has. :mod:`cats.tool_abuse_signals.observe`
   extracts both into a single :class:`ObservedToolUse` record.
3. A **comparator** that walks observed vs. baseline and returns the
   over-reach evidence — names that wrote outside the baseline plus
   why. :mod:`cats.tool_abuse_signals.compare` implements it.

This module is intentionally pure: no HTTP, no DB, no LLM. The
deterministic check imports it; tests import it; the specialist
prompts cite the baselines tables it parses but do not import it.
"""

from cats.tool_abuse_signals.baselines import (
    Baseline,
    BaselinesIndex,
    load_default_baselines,
    parse_baselines_markdown,
)
from cats.tool_abuse_signals.compare import (
    OverReachEvidence,
    detect_over_reach,
)
from cats.tool_abuse_signals.observe import (
    ObservedToolUse,
    observe_from_response,
)

__all__ = [
    "Baseline",
    "BaselinesIndex",
    "ObservedToolUse",
    "OverReachEvidence",
    "detect_over_reach",
    "load_default_baselines",
    "observe_from_response",
    "parse_baselines_markdown",
]
