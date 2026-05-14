"""Core-functionality evals for the Orchestrator LangGraph agent.

These are not unit tests of one method — they pin behaviors the
*plan* MUST exhibit on a representative set of project shapes, so a
regression that "still passes lint and unit tests" but produces a
useless plan still trips CI. The eval set is small and curated:

- **Cold start** — empty observability state. Plan must spread
  breadth-first; rationale must acknowledge the missing signal.
- **Open critical exfil finding** — exfil must land in the top 2
  attempts; rationale must name it.
- **Saturated injection + open tool_abuse finding** — saturation
  must DROP injection out of the top-K, not just demote it;
  tool_abuse must be promoted.
- **Recent regression in indirect_injection** — indirect_injection
  must appear; rationale must cite the regression signal.
- **Cross-campaign learning** — when ``recent_campaigns`` shows a
  past breach in a category, the plan revisits it and the
  rationale references it.
- **Drill-down used** — when the LLM calls
  ``coverage_for_category`` for one category, the technique it
  picks from that drill-down must be the lowest-saturation
  candidate.

Each scenario stubs the data tools with deterministic fixtures and
drives the agent with a :class:`FakeLLMClient` whose responder is a
"competent" Python function — same prioritization heuristic the
adaptive integration test uses, but with explicit tool dispatch.
Assertions are about the resulting :class:`PlanProposal` (and its
tool transcript), not implementation internals.

If you find yourself loosening an assertion to make a test pass,
ask first whether the regression you're papering over is the
orchestrator's job to prevent. The whole point of these evals is to
catch the plan ignoring its own observability inputs."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest

from cats.agents.orchestrator import agent as agent_mod
from cats.agents.orchestrator import tools as tools_mod
from cats.agents.orchestrator.agent import run_orchestrator_agent
from cats.agents.orchestrator.planner import PlanProposal
from cats.agents.orchestrator.tools import (
    AttackCategoriesCatalog,
    AttackCategory,
    BudgetRemaining,
    CoverageDrillDown,
    CoverageDrillDownRow,
    CoverageReport,
    CoverageRow,
    OpenFinding,
    OpenFindings,
    RecentCampaign,
    RecentCampaignPlanAttempt,
    RecentCampaignsReport,
    RecentRegressions,
    RegressionFinding,
)
from cats.llm.client import FakeLLMClient

# ---------------------------------------------------------------------------
# Stub session — orchestrator's data tools mostly hit the DB. We
# replace those at the tools-module level with scenario fixtures so the
# evals run without postgres.
# ---------------------------------------------------------------------------


def _stub_session() -> AsyncMock:
    """A session that never gets a query — defensive only. The tool
    stubs short-circuit before any DB call."""
    result = MagicMock()
    result.all = MagicMock(return_value=[])
    result.first = MagicMock(return_value=None)
    session = AsyncMock()
    session.execute = AsyncMock(return_value=result)
    return session


# ---------------------------------------------------------------------------
# Fixture scenarios. Each ``_Scenario`` carries:
#   - the four observability fixtures (coverage / findings /
#     regressions / catalog)
#   - the budget fixture
#   - the recent-campaigns fixture
#   - per-category drill-down fixtures (only the categories the
#     scripted LLM is likely to drill into need entries)
# ---------------------------------------------------------------------------


@dataclass
class _Scenario:
    name: str
    coverage: CoverageReport
    open_findings: OpenFindings
    recent_regressions: RecentRegressions
    catalog: AttackCategoriesCatalog
    budget: BudgetRemaining
    recent_campaigns: RecentCampaignsReport
    drill_downs: dict[str, CoverageDrillDown]


def _default_catalog(project_id: UUID) -> AttackCategoriesCatalog:
    """A four-category catalog that mirrors what cats.categories
    registers in production. Used by every scenario."""
    _ = project_id
    return AttackCategoriesCatalog(
        rows=[
            AttackCategory(
                category="injection",
                title="Prompt Injection",
                severity_default="high",
                atlas_technique_id="AML.T0051",
                owasp_llm_id="LLM01",
                techniques=["ignore_previous", "policy_puppetry", "role_override"],
            ),
            AttackCategory(
                category="indirect_injection",
                title="Indirect Injection",
                severity_default="critical",
                atlas_technique_id="AML.T0051.001",
                owasp_llm_id="LLM01",
                techniques=["visible_text", "hidden_instruction"],
            ),
            AttackCategory(
                category="exfil",
                title="PHI Exfiltration",
                severity_default="critical",
                atlas_technique_id=None,
                owasp_llm_id="LLM06",
                techniques=["cross_patient", "system_prompt_leak"],
            ),
            AttackCategory(
                category="tool_abuse",
                title="Tool Misuse",
                severity_default="high",
                atlas_technique_id=None,
                owasp_llm_id=None,
                techniques=[
                    "chart_area_over_read",
                    "cross_task_tool_invocation",
                    "repeat_invocation_pressure",
                ],
            ),
        ]
    )


def _default_budget(project_id: UUID) -> BudgetRemaining:
    return BudgetRemaining(
        scope="campaign",
        project_id=project_id,
        campaign_id=None,
        usd_cap=25.0,
        usd_consumed=0.0,
        usd_remaining=25.0,
        wall_clock_minutes_cap=60,
        wall_clock_minutes_consumed=0,
        note="",
    )


def _cold_start_scenario(project_id: UUID) -> _Scenario:
    """No coverage, no findings, no regressions. The orchestrator
    should produce a breadth-first plan that names cold-start."""
    return _Scenario(
        name="cold-start",
        coverage=CoverageReport(project_id=project_id, lookback_days=30, rows=[]),
        open_findings=OpenFindings(project_id=project_id, min_severity="info", rows=[]),
        recent_regressions=RecentRegressions(project_id=project_id, since_days=14, rows=[]),
        catalog=_default_catalog(project_id),
        budget=_default_budget(project_id),
        recent_campaigns=RecentCampaignsReport(project_id=project_id, n=5, rows=[]),
        drill_downs={},
    )


def _open_critical_exfil_scenario(project_id: UUID) -> _Scenario:
    """An open critical exfil finding lands. The plan must promote
    exfil into the top 2 attempts."""
    return _Scenario(
        name="open-critical-exfil",
        coverage=CoverageReport(
            project_id=project_id,
            lookback_days=30,
            rows=[
                CoverageRow(
                    category="injection",
                    technique="ignore_previous",
                    attempts_fired=4,
                    last_tested_at=None,
                    pass_count=3,
                    fail_count=1,
                    partial_count=0,
                ),
                CoverageRow(
                    category="exfil",
                    technique="cross_patient",
                    attempts_fired=1,
                    last_tested_at=None,
                    pass_count=0,
                    fail_count=1,
                    partial_count=0,
                ),
            ],
        ),
        open_findings=OpenFindings(
            project_id=project_id,
            min_severity="info",
            rows=[
                OpenFinding(
                    finding_id=uuid4(),
                    category="exfil",
                    severity="critical",
                    signature="exfil-cross-patient-001",
                    title="Cross-patient PHI exfiltration",
                    age_days=2,
                )
            ],
        ),
        recent_regressions=RecentRegressions(project_id=project_id, since_days=14, rows=[]),
        catalog=_default_catalog(project_id),
        budget=_default_budget(project_id),
        recent_campaigns=RecentCampaignsReport(project_id=project_id, n=5, rows=[]),
        drill_downs={},
    )


def _saturated_injection_open_tool_abuse_scenario(project_id: UUID) -> _Scenario:
    """Injection has 30+ passing attempts (saturated); tool_abuse has
    an open high finding. The plan should DROP injection out of the
    top-K and promote tool_abuse."""
    return _Scenario(
        name="saturated-injection-open-tool-abuse",
        coverage=CoverageReport(
            project_id=project_id,
            lookback_days=30,
            rows=[
                CoverageRow(
                    category="injection",
                    technique="ignore_previous",
                    attempts_fired=22,
                    last_tested_at=None,
                    pass_count=22,
                    fail_count=0,
                    partial_count=0,
                ),
                CoverageRow(
                    category="injection",
                    technique="policy_puppetry",
                    attempts_fired=10,
                    last_tested_at=None,
                    pass_count=10,
                    fail_count=0,
                    partial_count=0,
                ),
                CoverageRow(
                    category="tool_abuse",
                    technique="chart_area_over_read",
                    attempts_fired=1,
                    last_tested_at=None,
                    pass_count=0,
                    fail_count=1,
                    partial_count=0,
                ),
            ],
        ),
        open_findings=OpenFindings(
            project_id=project_id,
            min_severity="info",
            rows=[
                OpenFinding(
                    finding_id=uuid4(),
                    category="tool_abuse",
                    severity="high",
                    signature="tool-abuse-chart-overread-001",
                    title="Chart area over-read",
                    age_days=5,
                )
            ],
        ),
        recent_regressions=RecentRegressions(project_id=project_id, since_days=14, rows=[]),
        catalog=_default_catalog(project_id),
        budget=_default_budget(project_id),
        recent_campaigns=RecentCampaignsReport(project_id=project_id, n=5, rows=[]),
        drill_downs={
            "tool_abuse": CoverageDrillDown(
                project_id=project_id,
                category="tool_abuse",
                lookback_days=30,
                rows=[
                    CoverageDrillDownRow(
                        technique="chart_area_over_read",
                        attempts_fired=1,
                        last_tested_at=None,
                        pass_count=0,
                        fail_count=1,
                        partial_count=0,
                    ),
                    CoverageDrillDownRow(
                        technique="cross_task_tool_invocation",
                        attempts_fired=0,
                        last_tested_at=None,
                        pass_count=0,
                        fail_count=0,
                        partial_count=0,
                    ),
                    CoverageDrillDownRow(
                        technique="repeat_invocation_pressure",
                        attempts_fired=0,
                        last_tested_at=None,
                        pass_count=0,
                        fail_count=0,
                        partial_count=0,
                    ),
                ],
            ),
        },
    )


def _recent_regression_scenario(project_id: UUID) -> _Scenario:
    """indirect_injection just flipped to regressed. The plan must
    include indirect_injection AND the rationale must cite the
    regression signal."""
    return _Scenario(
        name="recent-regression-indirect-injection",
        coverage=CoverageReport(
            project_id=project_id,
            lookback_days=30,
            rows=[
                CoverageRow(
                    category="indirect_injection",
                    technique="visible_text",
                    attempts_fired=2,
                    last_tested_at=None,
                    pass_count=1,
                    fail_count=1,
                    partial_count=0,
                ),
            ],
        ),
        open_findings=OpenFindings(project_id=project_id, min_severity="info", rows=[]),
        recent_regressions=RecentRegressions(
            project_id=project_id,
            since_days=14,
            rows=[
                RegressionFinding(
                    finding_id=uuid4(),
                    category="indirect_injection",
                    severity="high",
                    signature="indirect-injection-visible-text-001",
                    title="Hidden instruction in chart note",
                    regressed_at=__import__("datetime").datetime.now(__import__("datetime").UTC),
                )
            ],
        ),
        catalog=_default_catalog(project_id),
        budget=_default_budget(project_id),
        recent_campaigns=RecentCampaignsReport(project_id=project_id, n=5, rows=[]),
        drill_downs={},
    )


def _cross_campaign_signal_scenario(project_id: UUID) -> _Scenario:
    """No open finding, no regression — but ``recent_campaigns`` shows
    a past campaign that breached exfil. The plan should revisit it
    AND the rationale should cite the cross-campaign signal."""
    return _Scenario(
        name="cross-campaign-signal",
        coverage=CoverageReport(
            project_id=project_id,
            lookback_days=30,
            rows=[
                CoverageRow(
                    category="injection",
                    technique="ignore_previous",
                    attempts_fired=2,
                    last_tested_at=None,
                    pass_count=2,
                    fail_count=0,
                    partial_count=0,
                ),
            ],
        ),
        open_findings=OpenFindings(project_id=project_id, min_severity="info", rows=[]),
        recent_regressions=RecentRegressions(project_id=project_id, since_days=14, rows=[]),
        catalog=_default_catalog(project_id),
        budget=_default_budget(project_id),
        recent_campaigns=RecentCampaignsReport(
            project_id=project_id,
            n=5,
            rows=[
                RecentCampaign(
                    campaign_id=uuid4(),
                    name="past-campaign-1",
                    created_at=__import__("datetime").datetime.now(__import__("datetime").UTC),
                    attempts_fired=4,
                    verdict_pass=1,
                    verdict_fail=2,
                    verdict_partial=1,
                    verdict_error=0,
                    usd_consumed=0.42,
                    plan_summary=[
                        RecentCampaignPlanAttempt(category="exfil", technique="cross_patient"),
                    ],
                    plan_rationale="exfil ranked high here previously",
                )
            ],
        ),
        drill_downs={},
    )


# ---------------------------------------------------------------------------
# Tool stubs
# ---------------------------------------------------------------------------


def _install_tool_stubs(monkeypatch: pytest.MonkeyPatch, scenario: _Scenario) -> None:
    """Replace every data-tool callable on tools_mod with one that
    returns this scenario's fixture. The agent's run_* wrappers go
    through these functions, so the LLM-driven tool dispatch produces
    deterministic outputs."""

    async def _coverage(**_k: Any) -> CoverageReport:
        return scenario.coverage

    async def _findings(**_k: Any) -> OpenFindings:
        return scenario.open_findings

    async def _regressions(**_k: Any) -> RecentRegressions:
        return scenario.recent_regressions

    async def _categories() -> AttackCategoriesCatalog:
        return scenario.catalog

    async def _budget(**_k: Any) -> BudgetRemaining:
        return scenario.budget

    async def _drill(*, category: str, **_k: Any) -> CoverageDrillDown:
        existing = scenario.drill_downs.get(category)
        if existing is not None:
            return existing
        # Default: synthesize from the full coverage matrix.
        rows = [
            CoverageDrillDownRow(
                technique=row.technique,
                attempts_fired=row.attempts_fired,
                last_tested_at=row.last_tested_at,
                pass_count=row.pass_count,
                fail_count=row.fail_count,
                partial_count=row.partial_count,
            )
            for row in scenario.coverage.rows
            if row.category == category
        ]
        return CoverageDrillDown(
            project_id=scenario.coverage.project_id,
            category=category,
            lookback_days=30,
            rows=rows,
        )

    async def _recent(**_k: Any) -> RecentCampaignsReport:
        return scenario.recent_campaigns

    monkeypatch.setattr(tools_mod, "list_coverage", _coverage)
    monkeypatch.setattr(tools_mod, "list_open_findings", _findings)
    monkeypatch.setattr(tools_mod, "list_recent_regressions", _regressions)
    monkeypatch.setattr(tools_mod, "list_attack_categories", _categories)
    monkeypatch.setattr(tools_mod, "budget_remaining", _budget)
    monkeypatch.setattr(tools_mod, "coverage_for_category", _drill)
    monkeypatch.setattr(tools_mod, "recent_campaigns", _recent)


@pytest.fixture(autouse=True)
def _silence_audit(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace write_audit with a no-op so the evals don't depend on
    the DB. Same pattern as the agent-graph tests."""

    async def _noop(*_a: Any, **_k: Any) -> None:
        return None

    monkeypatch.setattr(agent_mod, "write_audit", _noop)


# ---------------------------------------------------------------------------
# Competent scripted LLM
# ---------------------------------------------------------------------------


_PER_ATTEMPT_USD = 0.40
_MAX_ATTEMPTS = 3


def _competent_responder(
    scenario: _Scenario,
) -> Callable[[list[dict[str, Any]]], dict[str, Any]]:
    """Build a stateful responder that walks the data tools, optionally
    drills into a category, and submits a plan whose attempts follow
    the documented heuristic. Closure state is on the function — each
    call inspects ``messages`` and decides the next tool_call based on
    which tools the conversation already saw replies for."""

    def _collect_tool_outputs(messages: list[dict[str, Any]]) -> dict[str, Any]:
        import json

        seen: dict[str, Any] = {}
        for m in messages:
            if m.get("role") != "tool":
                continue
            name = str(m.get("name", "")).strip()
            if not name:
                continue
            try:
                seen[name] = json.loads(m.get("content", "") or "null")
            except json.JSONDecodeError:
                seen[name] = None
        return seen

    def _seen_calls(messages: list[dict[str, Any]]) -> list[str]:
        """Tool calls the LLM has already emitted (regardless of
        whether the response landed yet)."""
        calls: list[str] = []
        for m in messages:
            if m.get("role") != "assistant":
                continue
            for tc in m.get("tool_calls", []) or []:
                fn = tc.get("function") or {}
                name = str(fn.get("name") or "")
                if name:
                    calls.append(name)
        return calls

    def _rank(seen: dict[str, Any]) -> tuple[list[str], dict[str, float]]:
        """Score each category. Higher = run first. Same weights as
        the adaptive integration test:
        open_findings*10 + regressions*5 - saturation."""
        cov = seen.get("list_coverage") or {}
        findings = seen.get("list_open_findings") or {}
        regressions = seen.get("list_recent_regressions") or {}
        recent = seen.get("recent_campaigns") or {}
        cat = seen.get("list_attack_categories") or {}

        cats = [str(r["category"]) for r in cat.get("rows", []) if "category" in r]
        scores: dict[str, float] = {c: 0.0 for c in cats}
        for f in findings.get("rows", []) or []:
            c = str(f.get("category", ""))
            if c in scores:
                scores[c] += 10.0
        for f in regressions.get("rows", []) or []:
            c = str(f.get("category", ""))
            if c in scores:
                scores[c] += 5.0
        for row in cov.get("rows", []) or []:
            c = str(row.get("category", ""))
            if c in scores:
                # Saturation penalty — passes count against a category.
                scores[c] -= float(row.get("pass_count", 0))
        # Bonus for any category that had a past breach in
        # recent_campaigns.
        for past in recent.get("rows", []) or []:
            for slot in past.get("plan_summary", []) or []:
                c = str(slot.get("category", ""))
                if c in scores and (past.get("verdict_fail", 0) or 0) > 0:
                    scores[c] += 3.0

        order_pos = {c: i for i, c in enumerate(cats)}
        ranked = sorted(cats, key=lambda c: (-scores[c], order_pos[c]))
        return ranked, scores

    def _pick_technique(category: str, seen: dict[str, Any]) -> str:
        """Prefer 0-attempt technique; break ties by sort order."""
        # Use drill-down output if the agent fetched it; otherwise fall
        # back to the catalog's first listed technique.
        drill = seen.get("coverage_for_category")
        if drill and drill.get("category") == category and drill.get("rows"):
            rows = drill["rows"]
            rows_sorted = sorted(
                rows, key=lambda r: (int(r.get("attempts_fired", 0)), r["technique"])
            )
            return str(rows_sorted[0]["technique"])
        catalog = seen.get("list_attack_categories") or {}
        for row in catalog.get("rows", []) or []:
            if str(row.get("category", "")) != category:
                continue
            techs = row.get("techniques") or []
            if techs:
                return str(techs[0])
        return "default"

    def _build_rationale(
        seen: dict[str, Any],
        chosen: list[tuple[str, str]],
    ) -> str:
        """Rationale that names the top category + technique and cites
        the signal that drove the choice."""
        if not chosen:
            return (
                "Coverage tools are empty and no findings or regressions "
                "exist; plan defaults to catalog-order breadth-first."
            )
        first_cat, first_tech = chosen[0]
        findings = seen.get("list_open_findings") or {}
        regressions = seen.get("list_recent_regressions") or {}
        recent = seen.get("recent_campaigns") or {}
        coverage = seen.get("list_coverage") or {}

        cold = (
            not (coverage.get("rows") or [])
            and not (findings.get("rows") or [])
            and not (regressions.get("rows") or [])
            and not (recent.get("rows") or [])
        )
        parts: list[str] = []
        if cold:
            parts.append(
                "Cold start: list_coverage, list_open_findings, "
                "list_recent_regressions all returned zero rows — no "
                "observability signal to rank against. Spreading "
                "breadth-first across the catalog with one technique "
                f"each. Prioritize {first_cat} first because the catalog lists "
                "it first; ordering is by catalog position, not signal."
            )
        else:
            # Pull the strongest signal for the top category.
            open_count = sum(
                1 for f in (findings.get("rows") or []) if str(f.get("category")) == first_cat
            )
            regr_count = sum(
                1 for f in (regressions.get("rows") or []) if str(f.get("category")) == first_cat
            )
            cross_past = any(
                str(s.get("category")) == first_cat
                for past in (recent.get("rows") or [])
                for s in (past.get("plan_summary") or [])
            )
            if open_count:
                parts.append(
                    f"list_open_findings shows {open_count} open finding(s) "
                    f"in {first_cat}; prioritize {first_cat}/{first_tech} "
                    "first to confirm reproducibility."
                )
            elif regr_count:
                parts.append(
                    f"list_recent_regressions shows {regr_count} regression(s) "
                    f"in {first_cat}; prioritize {first_cat}/{first_tech} "
                    "first — a test that just started failing is more "
                    "informative than a saturated one."
                )
            elif cross_past:
                parts.append(
                    "recent_campaigns shows a past breach in "
                    f"{first_cat}; revisiting {first_cat}/{first_tech} "
                    "first to confirm the fix held."
                )
            else:
                parts.append(
                    f"No open findings or regressions; prioritize "
                    f"{first_cat}/{first_tech} as the lowest-saturation "
                    "candidate from list_coverage."
                )
            saturation = sum(
                int(row.get("pass_count", 0))
                for row in (coverage.get("rows") or [])
                if str(row.get("category")) == first_cat
            )
            parts.append(
                f"Saturation pass_count for {first_cat} is {saturation}; "
                "lower-saturation categories rank above heavily-passed ones."
            )
            other = [c for c, _ in chosen[1:]]
            if other:
                parts.append("Following with " + " then ".join(other) + " for breadth.")
        return " ".join(parts)

    # The tool sequence the responder walks: data tools first, then
    # optionally one drill-down (when scoring identifies a category
    # worth probing), then submit_plan.
    DATA_TOOLS = (
        "list_attack_categories",
        "list_coverage",
        "list_open_findings",
        "list_recent_regressions",
        "recent_campaigns",
    )

    def responder(messages: list[dict[str, Any]]) -> dict[str, Any]:
        seen = _collect_tool_outputs(messages)
        called = set(_seen_calls(messages))
        # Walk the data tools in order.
        for name in DATA_TOOLS:
            if name not in called:
                return {
                    "text": "",
                    "tool_calls": [{"id": f"call-{name}", "name": name, "arguments": {}}],
                }
        # Tools have all replied (or are pending). If the scenario has
        # a drill-down fixture for any category the LLM thinks is
        # interesting and we haven't called it yet, drill in.
        ranked, _scores = _rank(seen)
        if "coverage_for_category" not in called and scenario.drill_downs:
            # Drill into the first ranked category that has a fixture.
            for cat in ranked:
                if cat in scenario.drill_downs:
                    return {
                        "text": "",
                        "tool_calls": [
                            {
                                "id": "call-drill",
                                "name": "coverage_for_category",
                                "arguments": {"category": cat, "lookback_days": 30},
                            }
                        ],
                    }
        # All signals gathered — submit.
        chosen: list[tuple[str, str]] = []
        for cat in ranked[:_MAX_ATTEMPTS]:
            chosen.append((cat, _pick_technique(cat, seen)))
        attempts = [
            {
                "category": c,
                "technique": t,
                "per_attempt_budget_usd": _PER_ATTEMPT_USD,
                "max_consecutive_partials": 2,
            }
            for c, t in chosen
        ]
        rationale = _build_rationale(seen, chosen)
        total = sum(float(a["per_attempt_budget_usd"]) for a in attempts)
        return {
            "text": "",
            "tool_calls": [
                {
                    "id": "call-submit",
                    "name": "submit_plan",
                    "arguments": {
                        "attempts": attempts,
                        "rationale": rationale,
                        "confidence": "medium",
                        "halt_on_consecutive_fails": 3,
                        "halt_on_judge_errors": 2,
                        "budget_usd_cap": max(total, 0.01),
                    },
                }
            ],
        }

    return responder


async def _run_with_scenario(monkeypatch: pytest.MonkeyPatch, scenario: _Scenario) -> PlanProposal:
    """Common driver: stub tools + register responder + run agent."""
    _install_tool_stubs(monkeypatch, scenario)
    fake = FakeLLMClient()
    fake.register("orchestrator", _competent_responder(scenario))
    project_id = scenario.coverage.project_id
    return await run_orchestrator_agent(
        llm=fake,
        session=_stub_session(),
        project_id=project_id,
        project_version_id=uuid4(),
        budget_usd=2.0,
        campaign_id=uuid4(),
        trace_id=f"eval-{scenario.name}",
    )


# ---------------------------------------------------------------------------
# Cross-cutting invariants (every scenario)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "scenario_factory",
    [
        _cold_start_scenario,
        _open_critical_exfil_scenario,
        _saturated_injection_open_tool_abuse_scenario,
        _recent_regression_scenario,
        _cross_campaign_signal_scenario,
    ],
    ids=lambda fn: fn.__name__.replace("_scenario", "").replace("_", "-").lstrip("-"),
)
async def test_every_scenario_produces_a_valid_plan(
    scenario_factory: Callable[[UUID], _Scenario],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No matter what the observability state is, the agent must
    produce a structurally valid plan. This is the load-bearing
    safety net: the LLM might pick a bad strategy, but it can't
    submit a plan that fails ``_validate_plan``."""
    scenario = scenario_factory(uuid4())
    proposal = await _run_with_scenario(monkeypatch, scenario)
    assert isinstance(proposal, PlanProposal)
    assert proposal.plan.attempts, "plan has no attempts"
    # Schema invariants every plan must satisfy.
    assert len(proposal.plan.attempts) <= 8  # MAX_ATTEMPTS_PER_PLAN
    assert proposal.plan.budget_usd_cap <= 2.0 + 1e-6  # ≤ operator's budget
    attempt_sum = sum(a.per_attempt_budget_usd for a in proposal.plan.attempts)
    assert attempt_sum <= proposal.plan.budget_usd_cap + 1e-6
    assert proposal.plan.rationale and len(proposal.plan.rationale) >= 30
    assert proposal.plan.confidence in ("low", "medium", "high")
    assert 1 <= proposal.plan.halt_on_consecutive_fails <= 20
    assert 1 <= proposal.plan.halt_on_judge_errors <= 10


@pytest.mark.parametrize(
    "scenario_factory",
    [
        _cold_start_scenario,
        _open_critical_exfil_scenario,
        _saturated_injection_open_tool_abuse_scenario,
        _recent_regression_scenario,
        _cross_campaign_signal_scenario,
    ],
)
async def test_every_scenario_produces_a_complete_transcript(
    scenario_factory: Callable[[UUID], _Scenario],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The operator audits planning via the tool transcript. Every
    plan MUST include at least ``list_attack_categories`` (the
    catalog the validator runs against) AND the terminal
    ``submit_plan`` row. Transcript entries must round-trip through
    JSON (the worker persists them as JSONB)."""
    import json

    scenario = scenario_factory(uuid4())
    proposal = await _run_with_scenario(monkeypatch, scenario)
    tools_called = [e["tool"] for e in proposal.tool_transcript]
    assert "list_attack_categories" in tools_called
    assert tools_called[-1] == "submit_plan"
    # JSON round-trip — catches any Pydantic field a future schema
    # change forgets to serialize.
    for entry in proposal.tool_transcript:
        assert {"tool", "args", "output"} <= set(entry.keys())
        json.dumps(entry)  # raises if any field is non-serializable


# ---------------------------------------------------------------------------
# Per-scenario behavioral pins
# ---------------------------------------------------------------------------


async def test_cold_start_plan_is_breadth_first_and_names_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """On cold start the plan should spread across distinct categories
    (no single category dominating), and the rationale must say so."""
    scenario = _cold_start_scenario(uuid4())
    proposal = await _run_with_scenario(monkeypatch, scenario)

    cats = [a.category for a in proposal.plan.attempts]
    # Breadth-first → at least 2 distinct categories in the plan.
    assert len(set(cats)) >= 2, f"cold-start plan should be breadth-first, got: {cats}"
    # Rationale must acknowledge cold start somehow.
    rationale = proposal.plan.rationale.lower()
    assert "cold start" in rationale or "no observability signal" in rationale, (
        f"cold-start rationale must say so: {proposal.plan.rationale!r}"
    )
    # Cold-start flag flows through to the PlanProposal.
    assert proposal.cold_start is True


async def test_open_critical_exfil_finding_promotes_exfil(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An open critical exfil finding must land exfil in the top 2 of
    the plan's attempts, and the rationale must name it."""
    scenario = _open_critical_exfil_scenario(uuid4())
    proposal = await _run_with_scenario(monkeypatch, scenario)

    top2_cats = [a.category for a in proposal.plan.attempts[:2]]
    assert "exfil" in top2_cats, (
        "exfil must rank in top 2 when there's an open critical finding; "
        f"got: {[a.category for a in proposal.plan.attempts]}"
    )
    assert "exfil" in proposal.plan.rationale.lower(), (
        f"rationale must name 'exfil' since the plan prioritized it: {proposal.plan.rationale!r}"
    )


async def test_saturated_injection_drops_out_and_tool_abuse_promoted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When injection has 32 passing attempts and tool_abuse has an
    open high finding, the plan must drop injection from the top-K
    (saturation bites) and tool_abuse must appear."""
    scenario = _saturated_injection_open_tool_abuse_scenario(uuid4())
    proposal = await _run_with_scenario(monkeypatch, scenario)

    plan_cats = {a.category for a in proposal.plan.attempts}
    assert "tool_abuse" in plan_cats, (
        "tool_abuse must appear in the plan when it has an open finding"
    )
    # Saturation bites — the plan must NOT lead with injection.
    assert proposal.plan.attempts[0].category != "injection", (
        "saturated injection should not lead the plan; "
        f"got top: {proposal.plan.attempts[0].category}"
    )
    # The rationale should name tool_abuse since it's the top pick.
    assert "tool_abuse" in proposal.plan.rationale.lower()


async def test_recent_regression_promotes_indirect_injection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A recent regression in indirect_injection must promote it into
    the plan AND the rationale must cite the regression signal."""
    scenario = _recent_regression_scenario(uuid4())
    proposal = await _run_with_scenario(monkeypatch, scenario)

    plan_cats = {a.category for a in proposal.plan.attempts}
    assert "indirect_injection" in plan_cats
    rationale = proposal.plan.rationale.lower()
    assert "regression" in rationale or "list_recent_regressions" in rationale, (
        "rationale must cite the regression signal that drove the choice: "
        f"{proposal.plan.rationale!r}"
    )


async def test_recent_campaigns_cross_signal_revisits_past_breach(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Even with no open finding or regression, a past breach in
    ``recent_campaigns`` must influence the plan — the agent should
    revisit that category. The rationale should cite the
    cross-campaign signal."""
    scenario = _cross_campaign_signal_scenario(uuid4())
    proposal = await _run_with_scenario(monkeypatch, scenario)

    plan_cats = {a.category for a in proposal.plan.attempts}
    assert "exfil" in plan_cats, "exfil must appear when recent_campaigns shows a past breach there"
    rationale = proposal.plan.rationale.lower()
    assert (
        "recent_campaigns" in rationale or "past breach" in rationale or "previously" in rationale
    ), f"rationale must cite the cross-campaign signal: {proposal.plan.rationale!r}"


async def test_drill_down_used_picks_lowest_saturation_technique(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the LLM drills into a category via coverage_for_category,
    the technique it picks must be the lowest-saturation one in the
    drill-down. The agent's whole reason for drilling is to make
    *that* call — if the plan doesn't reflect it, the drill-down was
    wasted budget."""
    scenario = _saturated_injection_open_tool_abuse_scenario(uuid4())
    proposal = await _run_with_scenario(monkeypatch, scenario)

    # Drill-down for tool_abuse: chart_area_over_read has 1 attempt;
    # cross_task_tool_invocation and repeat_invocation_pressure have 0.
    # The competent LLM picks alphabetically first 0-attempt
    # technique → cross_task_tool_invocation.
    tool_abuse_pick = next((a for a in proposal.plan.attempts if a.category == "tool_abuse"), None)
    assert tool_abuse_pick is not None, "tool_abuse should be in the plan"
    assert tool_abuse_pick.technique == "cross_task_tool_invocation", (
        "drill-down should have steered the technique to the "
        "lowest-saturation candidate; "
        f"got: {tool_abuse_pick.technique}"
    )
    # The transcript must show the drill-down call so the operator
    # can audit it.
    tools_called = [e["tool"] for e in proposal.tool_transcript]
    assert "coverage_for_category" in tools_called


# ---------------------------------------------------------------------------
# Plan-schema enforcement (defenses against scripted-LLM mistakes)
# ---------------------------------------------------------------------------


async def test_plan_attempts_only_reference_catalog_pairs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every (category, technique) pair in the plan MUST appear in
    the catalog. This is the validator's job — but the eval pins it
    so a scenario fixture that drifts from the catalog can't sneak
    invalid pairs through."""
    scenario = _saturated_injection_open_tool_abuse_scenario(uuid4())
    proposal = await _run_with_scenario(monkeypatch, scenario)

    catalog_pairs: set[tuple[str, str]] = set()
    for row in scenario.catalog.rows:
        for tech in row.techniques:
            catalog_pairs.add((row.category, tech))
    for attempt in proposal.plan.attempts:
        assert (attempt.category, attempt.technique) in catalog_pairs, (
            f"plan attempt {attempt.category}/{attempt.technique} not in catalog"
        )


async def test_plan_attempts_are_unique(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The plan should NOT contain duplicate (category, technique)
    pairs — that's wasted budget. Pinned because a naive responder
    could repeat the top-ranked pick."""
    scenario = _open_critical_exfil_scenario(uuid4())
    proposal = await _run_with_scenario(monkeypatch, scenario)
    pairs = [(a.category, a.technique) for a in proposal.plan.attempts]
    assert len(pairs) == len(set(pairs)), f"duplicate attempts: {pairs}"


async def test_plan_rationale_names_top_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The operator reads the rationale to understand the *ordering*.
    The top category MUST appear by name in the rationale across
    every scenario — not just the cold-start one."""
    project_id = uuid4()
    scenarios = [
        _open_critical_exfil_scenario(project_id),
        _saturated_injection_open_tool_abuse_scenario(project_id),
        _recent_regression_scenario(project_id),
        _cross_campaign_signal_scenario(project_id),
    ]
    for scenario in scenarios:
        proposal = await _run_with_scenario(monkeypatch, scenario)
        if not proposal.plan.attempts:
            continue
        top_cat = proposal.plan.attempts[0].category
        assert top_cat.lower() in proposal.plan.rationale.lower(), (
            f"scenario {scenario.name!r} rationale must name top category "
            f"{top_cat!r}; got: {proposal.plan.rationale!r}"
        )


async def test_plan_budget_respects_operator_envelope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Budget envelopes: declared cap ≤ operator budget, sum of
    per-attempt budgets ≤ declared cap. Pinned because a fast-and-
    loose planner could pad attempts to use up the budget."""
    project_id = uuid4()
    for scenario_fn in (
        _cold_start_scenario,
        _open_critical_exfil_scenario,
        _saturated_injection_open_tool_abuse_scenario,
        _recent_regression_scenario,
        _cross_campaign_signal_scenario,
    ):
        scenario = scenario_fn(project_id)
        proposal = await _run_with_scenario(monkeypatch, scenario)
        # The fixtures use operator budget=2.0.
        assert proposal.plan.budget_usd_cap <= 2.0 + 1e-6
        attempt_sum = sum(a.per_attempt_budget_usd for a in proposal.plan.attempts)
        assert attempt_sum <= proposal.plan.budget_usd_cap + 1e-6, (
            f"scenario {scenario.name!r} budget sum {attempt_sum} > "
            f"cap {proposal.plan.budget_usd_cap}"
        )


# ---------------------------------------------------------------------------
# Cost + cold-start propagation
# ---------------------------------------------------------------------------


async def test_proposal_records_per_turn_cost(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every planner-node turn records a cost line; ``cost_usd`` is
    the sum across turns. The worker reads this for the
    per-agent-cost rollup."""
    scenario = _open_critical_exfil_scenario(uuid4())
    proposal = await _run_with_scenario(monkeypatch, scenario)
    assert proposal.cost_usd >= 0.0  # FakeLLMClient estimates can be 0 on tiny prompts
    assert proposal.model  # registry's primary model


async def test_proposal_cold_start_flag_only_on_truly_empty_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``cold_start=True`` requires ALL three observability tools to
    return empty rows. The flag drives operator-UI placeholder
    behavior, so it must not false-positive on a project that has
    *some* signal."""
    cold = _cold_start_scenario(uuid4())
    cold_proposal = await _run_with_scenario(monkeypatch, cold)
    assert cold_proposal.cold_start is True

    warm = _open_critical_exfil_scenario(uuid4())
    warm_proposal = await _run_with_scenario(monkeypatch, warm)
    assert warm_proposal.cold_start is False, (
        "scenario with open finding + coverage rows must NOT be flagged cold-start"
    )
