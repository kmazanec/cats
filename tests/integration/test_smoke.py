"""R3 — smoke-path integration test (asked for by R2 retro).

``make smoke`` is the documented onboarding command. R2 had no test for it
and the bug it would have caught (double-persistence of Attack/Execution
rows when R1's CLI path was still in place) only surfaced when a human ran
the CLI. This test exercises ``run_smoke`` end-to-end against the real
Postgres truncated by ``conftest.py`` so a future regression of the same
shape bites in CI, not on someone's laptop.

No LLM is called — ``smoke_mode=True`` makes every node take its canned
path.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text

from cats.cli.smoke import run_smoke

pytestmark = [pytest.mark.integration, pytest.mark.smoke]


@pytest.mark.asyncio
async def test_run_smoke_writes_full_chain(client) -> None:
    """The smoke path must:

    1. Create a Project + ProjectVersion + Campaign + Run row.
    2. Run the graph in smoke mode (no LLM calls).
    3. Persist exactly one Attack + AttackExecution + JudgeVerdict.

    The canned target response refuses the canned attack. Under the
    LLM-first judge contract the FakeLLMClient (no scripted ``judge``
    responder in the smoke CLI) returns the default JSON which the
    verifier clamps to ``error`` — meaning "not evaluable", not a
    defensive win. Either ``fail`` or ``error`` is acceptable for a
    smoke-mode no-LLM run; the test pins the plumbing, not the
    verdict semantics."""
    _ = client  # ensures DB is truncated + lifespan ran

    from cats.db.engine import session_scope

    state = await run_smoke(target_url="http://fake-smoke-target.test")

    # Under the LLM-first judge, the smoke path's unscripted FakeLLM
    # call lands on the default response and clamps to ``error``. We
    # accept ``fail`` too in case someone later adds a smoke-mode
    # judge responder that produces a real verdict.
    assert state.last_verdict in ("fail", "error"), (
        f"smoke expected fail|error, got {state.last_verdict!r}"
    )
    assert state.finding_id is None, "smoke must not promote a Finding on non-pass"
    assert state.report_id is None

    async with session_scope() as session:
        for table, expected in (
            ("projects", 1),
            ("project_versions", 1),
            ("campaigns", 1),
            ("runs", 1),
            ("attacks", 1),
            ("attack_executions", 1),
            ("judge_verdicts", 1),
            ("findings", 0),
        ):
            count = (await session.execute(text(f"SELECT COUNT(*) FROM {table}"))).scalar()
            assert count == expected, f"{table}: expected {expected}, got {count}"


@pytest.mark.asyncio
async def test_run_smoke_is_idempotent_on_same_run_id(client) -> None:
    """Running smoke twice produces a fresh Project + Run each time — no
    crash, no duplicate-key violation. This protects the documented
    onboarding command from regressing when a developer wipes the DB and
    re-seeds."""
    _ = client
    s1 = await run_smoke()
    s2 = await run_smoke()
    assert s1.run_id != s2.run_id
    # Both runs must produce the same verdict (deterministic-ish) — the
    # exact value depends on the LLM-first judge's clamping, see the
    # other smoke test for the rationale.
    assert s1.last_verdict == s2.last_verdict
    assert s1.last_verdict in ("fail", "error")
