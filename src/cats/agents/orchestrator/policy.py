"""Deterministic epsilon-greedy bandit for category selection.

Pure Python; fully unit-testable; no LLM cost. The meta-loop (Tier-2 LLM
proposes weight tunings) is implemented elsewhere.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field


@dataclass
class CategoryStats:
    runs: int = 0
    open_high_severity: int = 0
    recent_regression: bool = False
    last_seen_score: float = 0.0


@dataclass
class BanditConfig:
    epsilon: float = 0.10
    coverage_weight: float = 0.5
    severity_weight: float = 0.35
    recency_weight: float = 0.15
    seed: int | None = None


@dataclass
class Bandit:
    categories: dict[str, CategoryStats] = field(default_factory=dict)
    config: BanditConfig = field(default_factory=BanditConfig)

    def _rng(self) -> random.Random:
        return random.Random(self.config.seed)

    def score(self, name: str) -> float:
        s = self.categories.get(name, CategoryStats())
        coverage_gap = 1.0 / (1.0 + s.runs)
        severity = float(s.open_high_severity)
        recency = 1.0 if s.recent_regression else 0.0
        return (
            self.config.coverage_weight * coverage_gap
            + self.config.severity_weight * severity
            + self.config.recency_weight * recency
        )

    def choose(self, available: list[str]) -> str:
        if not available:
            raise ValueError("no categories available")
        rng = self._rng()
        if rng.random() < self.config.epsilon:
            return rng.choice(available)
        scored = sorted(available, key=self.score, reverse=True)
        return scored[0]
