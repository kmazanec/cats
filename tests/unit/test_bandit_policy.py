from __future__ import annotations

from cats.agents.orchestrator.policy import Bandit, BanditConfig, CategoryStats


def test_bandit_prefers_low_coverage_category() -> None:
    b = Bandit(
        categories={
            "injection": CategoryStats(runs=100),
            "exfil": CategoryStats(runs=1),
        },
        config=BanditConfig(epsilon=0.0, seed=42),
    )
    assert b.choose(["injection", "exfil"]) == "exfil"


def test_bandit_severity_outweighs_coverage_when_high() -> None:
    b = Bandit(
        categories={
            "injection": CategoryStats(runs=100, open_high_severity=5),
            "exfil": CategoryStats(runs=1, open_high_severity=0),
        },
        config=BanditConfig(epsilon=0.0, seed=42),
    )
    assert b.choose(["injection", "exfil"]) == "injection"


def test_bandit_handles_empty_categories() -> None:
    b = Bandit(config=BanditConfig(epsilon=0.0, seed=1))
    assert b.choose(["new_cat"]) == "new_cat"
