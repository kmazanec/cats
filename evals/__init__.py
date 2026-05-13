"""R3 eval harness.

Runs the Judge against a hand-labeled answer key, computes accuracy, and
emits a per-technique confusion table. Used by the nightly CI job to
detect Judge drift (vendor-side model changes, rubric mismatch, etc.).
"""
