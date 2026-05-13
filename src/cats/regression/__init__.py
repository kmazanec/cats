"""R8 regression-verification harness.

Public surface:

- :func:`cats.regression.fingerprint.cosine_similarity` — gate-3 helper.
- :func:`cats.regression.runner.run_regression_case` — the triple-gate
  per-case evaluator.
- :func:`cats.regression.sweep.run_sweep` — orchestrate the per-case
  runner across all RegressionCases for a project (called from the
  webhook + CLI).

See ARCHITECTURE.md §6.4 for the gate semantics.
"""
