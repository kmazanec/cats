"""Red-Team specialist family for denial-of-service / cost amplification.

Specialists author chat turns intended to drive the OpenEMR Co-Pilot's
supervisor into runaway cost trajectories. Four techniques shipped:
``clawdrain_segmented_verification``, ``output_length_explosion``,
``recursive_task_expansion``, ``tokenizer_drift_amplification``. The
deterministic post-condition (``cats.categories.dos_cost.deterministic``)
measures the assembled SSE response against per-attack thresholds.
"""

from cats.agents.red_team.dos_cost.base import DosCostProposal

__all__ = ["DosCostProposal"]
