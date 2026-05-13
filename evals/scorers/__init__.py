"""Per-agent scorers.

Each scorer turns ``(case, actual)`` into a ``ScoreResult``. The
runners depend only on these — they don't reach into agent
internals. Adding a new check to an agent's eval is a one-line
addition to the scorer + a new key under ``## Expected`` in the
case file.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Check:
    name: str
    passed: bool
    detail: str = ""


@dataclass
class ScoreResult:
    case_id: str
    checks: list[Check] = field(default_factory=list)
    error: str | None = None

    def add(self, name: str, passed: bool, detail: str = "") -> None:
        self.checks.append(Check(name=name, passed=passed, detail=detail))

    @property
    def passed_count(self) -> int:
        return sum(1 for c in self.checks if c.passed)

    @property
    def total(self) -> int:
        return len(self.checks)

    @property
    def passed(self) -> bool:
        return self.error is None and all(c.passed for c in self.checks) and self.total > 0
