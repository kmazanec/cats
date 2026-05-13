"""Eval runners — one CLI per agent.

Each runner:

1. Loads every ``.md`` case from ``evals/cases/<agent>/``.
2. Calls an *injected* executor (``Callable[[Case], Actual]``) to
   produce the agent's output.
3. Scores it via the agent's scorer.
4. Emits a per-case pass/fail report and exits non-zero when the
   pass rate is below the per-runner threshold.

The default executor uses ``FakeLLMClient`` so the runner is
self-contained — no OpenRouter, no Postgres, no live target.
That makes the same harness usable from a unit test and from a
nightly CI job (the nightly substitutes a real-LLM executor).
"""
