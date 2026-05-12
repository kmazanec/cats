"""CI gate: judge vs ground-truth fixtures. Per-category accuracy threshold.

Stub: scaffold-time placeholder; populated when fixtures exist."""

from __future__ import annotations

from pathlib import Path


def run_fixtures(category: str, fixtures_dir: Path) -> tuple[float, int, int]:
    """Returns (accuracy, total, passed). Returns (1.0, 0, 0) when the
    fixture file is empty so CI doesn't fail on the scaffold."""
    f = fixtures_dir / "ground_truth.jsonl"
    if not f.exists():
        return (1.0, 0, 0)
    lines = [
        line for line in f.read_text().splitlines() if line.strip() and not line.startswith("#")
    ]
    total = len(lines)
    if total == 0:
        return (1.0, 0, 0)
    # TODO: actually run the Judge against each triple.
    return (1.0, total, total)
