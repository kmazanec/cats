"""Tests for the per-run patient picker."""

from __future__ import annotations

from collections import Counter
from uuid import UUID, uuid4

from cats.agents.red_team.patient_selection import DEMO_PIDS, choose_pid_for_run


def test_choose_pid_for_run_returns_a_demo_pid() -> None:
    pid = choose_pid_for_run(uuid4())
    assert pid in DEMO_PIDS


def test_choose_pid_for_run_is_deterministic() -> None:
    # Same UUID → same PID across many invocations. Required so a
    # resumed/replayed run hits the same chart the original did.
    rid = UUID("11111111-2222-3333-4444-555555555555")
    pids = {choose_pid_for_run(rid) for _ in range(50)}
    assert len(pids) == 1


def test_choose_pid_for_run_distributes_across_pool() -> None:
    # 5000 distinct run_ids should hit every PID at least once and
    # land within a reasonable band of the uniform expectation. A
    # broken hash that always returned the same PID (the bug this
    # whole change fixes) would trivially fail this.
    counts: Counter[int] = Counter()
    for _ in range(5000):
        counts[choose_pid_for_run(uuid4())] += 1
    assert set(counts) == set(DEMO_PIDS), "every demo PID should be picked at least once"
    expected = 5000 / len(DEMO_PIDS)
    # Generous bounds — we're checking for catastrophic skew, not
    # certifying uniformity. 0.4..2.5x the expected share is wide
    # enough that flakes are essentially impossible for n=5000.
    for pid, count in counts.items():
        assert 0.4 * expected < count < 2.5 * expected, (
            f"pid {pid} got {count} hits; expected ~{expected:.0f}"
        )
