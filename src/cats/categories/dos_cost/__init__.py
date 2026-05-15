"""Denial-of-Service & Cost Amplification (THREAT_MODEL.md §2.5).

Specialists author chat turns intended to drive the OpenEMR Co-Pilot
into runaway cost trajectories — Clawdrain-style segmented-verification
loops, output-length explosion, recursive task expansion, and
tokenizer-drift amplification. The deterministic check is purely
quantitative: it scans the assembled SSE response for tool-call
event count and total response length against thresholds calibrated
from baseline benign briefings.

CATS coverage tier: Final (per §2.10 revised, LxI=12). The category
ships as a low-cost LLM specialist + cheap deterministic check rather
than the "no LLM specialist — deterministic generator" the original
plan called for: a Hermes-class generator gives the Orchestrator
language-level diversity for cost-amplification framings without
materially raising CATS-side spend.
"""
