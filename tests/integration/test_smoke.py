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

    The canned target response refuses the canned attack, so the verdict
    is ``fail`` by design and no Finding is promoted — the test verifies
    the plumbing, not a confirmed-vuln outcome.
    """
    _ = client  # ensures DB is truncated + lifespan ran

    from cats.db.engine import session_scope

    state = await run_smoke(target_url="http://fake-smoke-target.test")

    # Smoke uses a canned target that refuses; deterministic judge rules fail.
    assert state.last_verdict == "fail", f"smoke expected fail, got {state.last_verdict!r}"
    assert state.finding_id is None, "smoke must not promote a Finding on fail"
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
    assert s1.last_verdict == s2.last_verdict == "fail"
