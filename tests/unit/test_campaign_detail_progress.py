"""Unit tests for the campaign-detail progress helpers.

These back the thin segment-bar + elapsed-clock strip on the campaign
detail page. The route hands the template a ``progress`` dict that
encodes one segment per planned attempt, plus the wall-clock anchors
that drive the elapsed-time readout.
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

from cats.api.routes.campaigns import _build_progress, _plan_attempts_from_row


def _run(*, status: str, started_at=None, ended_at=None, technique=None, category=None):
    return {
        "id": uuid4(),
        "status": status,
        "started_at": started_at,
        "ended_at": ended_at,
        "technique": technique,
        "category": category,
    }


def test_plan_attempts_prefers_approved_over_proposed() -> None:
    """When the operator edits the plan we want the edited shape to
    drive the segment count, not the original proposal."""
    row = SimpleNamespace(
        approved_plan={"attempts": [{"category": "injection", "technique": "x"}]},
        proposed_plan={"attempts": [{"a": 1}, {"a": 2}, {"a": 3}]},
    )
    attempts = _plan_attempts_from_row(row)
    assert len(attempts) == 1
    assert attempts[0]["technique"] == "x"


def test_plan_attempts_falls_back_to_proposed_when_approved_empty() -> None:
    row = SimpleNamespace(
        approved_plan=None,
        proposed_plan={"attempts": [{"category": "injection", "technique": "y"}]},
    )
    assert _plan_attempts_from_row(row) == [{"category": "injection", "technique": "y"}]


def test_plan_attempts_handles_missing_row() -> None:
    assert _plan_attempts_from_row(None) == []


def test_progress_paints_pending_segments_before_runs_materialize() -> None:
    """Plan authored, dispatch not yet — every segment is queued."""
    attempts = [{"category": "injection", "technique": f"t{i}"} for i in range(4)]
    progress = _build_progress(runs=[], plan_attempts=attempts, campaign_terminal=False)
    assert progress["planned_count"] == 4
    assert progress["pending_count"] == 4
    assert progress["completed_count"] == 0
    assert all(seg["status"] == "pending" for seg in progress["segments"])
    # No runs yet → clock has nothing to anchor on.
    assert progress["started_at"] is None
    assert progress["ended_at"] is None


def test_progress_running_segment_keeps_clock_open() -> None:
    """One run in flight: clock must not freeze even if the campaign
    report row hasn't landed."""
    started = datetime(2026, 5, 14, 21, 0, 0, tzinfo=UTC)
    # list_runs_for_campaign returns newest-first; the helper reverses.
    runs = [
        _run(status="running", started_at=started),
        _run(
            status="completed",
            started_at=datetime(2026, 5, 14, 20, 55, 0, tzinfo=UTC),
            ended_at=datetime(2026, 5, 14, 20, 59, 0, tzinfo=UTC),
        ),
    ]
    attempts = [{"category": "injection", "technique": "a"} for _ in range(3)]
    p = _build_progress(runs=runs, plan_attempts=attempts, campaign_terminal=False)
    statuses = [seg["status"] for seg in p["segments"]]
    # oldest-first reading: completed, running, pending
    assert statuses == ["completed", "running", "pending"]
    assert p["started_at"] is not None
    assert p["ended_at"] is None  # campaign not terminal → keep ticking


def test_progress_freezes_only_when_campaign_terminal_and_all_runs_ended() -> None:
    started = datetime(2026, 5, 14, 21, 0, 0, tzinfo=UTC)
    ended = datetime(2026, 5, 14, 21, 8, 30, tzinfo=UTC)
    runs = [
        _run(status="completed", started_at=started, ended_at=ended),
        _run(
            status="completed",
            started_at=datetime(2026, 5, 14, 20, 50, 0, tzinfo=UTC),
            ended_at=datetime(2026, 5, 14, 20, 58, 0, tzinfo=UTC),
        ),
    ]
    attempts = [{"category": "injection", "technique": "a"} for _ in range(2)]

    # All runs terminal but the rollup report hasn't finished yet — the
    # documenter is still writing, so we keep the clock open.
    live = _build_progress(runs=runs, plan_attempts=attempts, campaign_terminal=False)
    assert live["ended_at"] is None

    # Same data, but the report row is now completed → freeze.
    frozen = _build_progress(runs=runs, plan_attempts=attempts, campaign_terminal=True)
    assert frozen["ended_at"] == ended.isoformat()
    # Started anchor picks the earliest run.
    assert frozen["started_at"] == datetime(2026, 5, 14, 20, 50, 0, tzinfo=UTC).isoformat()


def test_progress_falls_back_to_run_count_without_plan() -> None:
    """If runs exist but the plan body is unreadable, the bar should
    still paint one segment per run rather than rendering empty."""
    runs = [
        _run(status="completed", started_at=datetime(2026, 5, 14, 21, 0, 0, tzinfo=UTC)),
        _run(status="completed", started_at=datetime(2026, 5, 14, 20, 55, 0, tzinfo=UTC)),
    ]
    p = _build_progress(runs=runs, plan_attempts=[], campaign_terminal=False)
    assert p["planned_count"] == 2
    assert p["completed_count"] == 2


def test_progress_failed_run_marked_red() -> None:
    runs = [_run(status="failed", started_at=datetime(2026, 5, 14, 21, 0, 0, tzinfo=UTC))]
    attempts = [{"category": "injection", "technique": "a"} for _ in range(2)]
    p = _build_progress(runs=runs, plan_attempts=attempts, campaign_terminal=False)
    assert p["failed_count"] == 1
    assert p["pending_count"] == 1
    statuses = [seg["status"] for seg in p["segments"]]
    assert statuses == ["failed", "pending"]
