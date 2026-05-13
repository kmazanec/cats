"""Mutator agent — variant generation on partial-success feedback (R3+).

R2 shipped the Mutator role as a passthrough that emits a visible event so
the dashboard reflects the seven-role topology. R3 wires real variant
generation: when the Judge rules ``partial`` on an attack, the Mutator
rewrites the payload using the verdict's rationale + evidence as a
prompt-engineering signal, and the graph loops back through the target
for re-evaluation. The loop is bounded at ``MAX_CONSECUTIVE_PARTIALS``
per attack to keep cost predictable.

Public surface:

- :data:`MAX_CONSECUTIVE_PARTIALS` — graph-level loop cap (3)
- :func:`generate_variant` — produce one mutated payload given the
  current state. LLM-driven primary path (DeepSeek V3.2 per
  ARCHITECTURE.md §4.1); deterministic fallback when the LLM call fails
  so the loop still produces *some* variant rather than stalling.
"""

from cats.agents.mutator.strategies import (
    MAX_CONSECUTIVE_PARTIALS,
    MutatorResult,
    generate_variant,
)

__all__ = ["MAX_CONSECUTIVE_PARTIALS", "MutatorResult", "generate_variant"]
