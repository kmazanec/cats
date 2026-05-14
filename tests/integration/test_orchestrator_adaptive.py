"""R4 DoD: Orchestrator's plan visibly evolves across consecutive campaigns.

Simulates ten consecutive campaigns against the same project by driving
:func:`propose_plan` directly and synthetically seeding the platform's
observability tables (``attacks``, ``attack_executions``,
``judge_verdicts``, ``findings``) between iterations.

After the R10-followup-2 refactor the Orchestrator is a LangGraph
agent: it calls tools, reads their results from the conversation, and
emits a plan via the ``submit_plan`` terminal tool. The scripted
:class:`FakeLLMClient` here plays that agent's role — it walks a
fixed call sequence (categories → coverage → findings → regressions →
submit_plan), reads the tool-result messages from the conversation,
applies a deterministic ranking heuristic, and submits a plan whose
``rationale`` cites the signals driving the choice.

The test never spins up a worker, never touches the target, and never
calls a real LLM. It is the cheapest possible end-to-end proof that
the planner reads observability state and that the contract between
the planner and the operator UI (the ``rationale``) names the signals
a human can trace.

Seeded scenario per iteration:

- 1-3   : most attempts pass; the platform looks 'well defended'.
- 4     : a high-severity ``exfil`` open finding lands (real vuln found).
- 5-7   : repeated injection passes continue to saturate that category.
- 8     : a ``tool_abuse`` finding flips to status='regressed'.
- 9-10  : free-form — saturation + regression signals carry forward.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from typing import Any
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from sqlalchemy import insert
from sqlalchemy.ext.asyncio import AsyncSession

from cats.agents.orchestrator.planner import PlanProposal, propose_plan
from cats.db.engine import session_scope
from cats.db.repositories.run_repo import record_execution, record_verdict, upsert_attack
from cats.db.schema import campaigns, findings, project_versions, projects, runs
from cats.llm.client import FakeLLMClient, install_override
from cats.messaging.envelopes import PlannedCampaign

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Scripted Orchestrator LLM
# ---------------------------------------------------------------------------


# Default per-attempt budget; the planner caps the sum against
# ``budget_usd_cap`` so 3 * 0.50 stays comfortably inside the operator's
# $2.00 envelope used by this test.
_PER_ATTEMPT_USD: float = 0.50

# Maximum number of attempts the scripted planner emits per campaign.
# Four categories ship today (injection, indirect_injection, exfil,
# tool_abuse); cap at 3 so the assertion 'priority >= 2' is meaningful.
_MAX_ATTEMPTS: int = 3


@dataclass(frozen=True)
class _ToolOutputs:
    """Parsed snapshot of the planner's tool-call transcript pulled out
    of the prompt. Carries only the fields the scripted heuristic looks
    at — keeps the assertion logic in this test legible."""

    cold_start: bool
    operator_budget_usd: float
    catalog_categories: list[str]
    # category -> sorted technique names from list_attack_categories.
    techniques_by_category: dict[str, list[str]]
    # (category, technique) -> coverage stats from list_coverage.
    coverage: dict[tuple[str, str], dict[str, int]]
    # category -> count of open findings (severity floor: info).
    open_finding_categories: dict[str, int]
    # category -> count of recent regressions.
    regression_categories: dict[str, int]


# Fixed sequence of read-only tool calls the scripted agent makes
# before submitting. Walking them deterministically gives us the same
# observability snapshot the pre-LangGraph planner had.
_DATA_TOOLS_IN_ORDER: tuple[str, ...] = (
    "list_attack_categories",
    "list_coverage",
    "list_open_findings",
    "list_recent_regressions",
)


def _collect_tool_outputs(messages: list[dict[str, Any]]) -> dict[str, Any]:
    """Read every prior ``role=tool`` message in the conversation and
    return a name→output dict. Each tool message's ``content`` is the
    JSON-serialized tool payload (the same payload the agent's
    tool_executor node appended)."""
    by_tool: dict[str, Any] = {}
    for m in messages:
        if m.get("role") != "tool":
            continue
        name = str(m.get("name", "")).strip()
        if not name:
            continue
        try:
            payload = json.loads(m.get("content", "") or "null")
        except json.JSONDecodeError:
            payload = None
        by_tool[name] = payload
    return by_tool


def _next_data_tool(seen: dict[str, Any]) -> str | None:
    """Return the next read-only data tool the scripted agent should
    call, or ``None`` if all of them have results in the conversation."""
    for name in _DATA_TOOLS_IN_ORDER:
        if name not in seen:
            return name
    return None


def _snapshot_from_tool_results(seen: dict[str, Any]) -> _ToolOutputs:
    """Distill the four data-tool results into the
    :class:`_ToolOutputs` shape the heuristic reads."""
    catalog_payload = seen.get("list_attack_categories") or {}
    catalog_rows = catalog_payload.get("rows", []) if isinstance(catalog_payload, dict) else []
    catalog_categories = [str(r["category"]) for r in catalog_rows if "category" in r]
    techniques_by_category: dict[str, list[str]] = {
        str(r["category"]): list(r.get("techniques", [])) for r in catalog_rows
    }

    coverage: dict[tuple[str, str], dict[str, int]] = {}
    cov_payload = seen.get("list_coverage") or {}
    for row in cov_payload.get("rows", []) if isinstance(cov_payload, dict) else []:
        key = (str(row["category"]), str(row["technique"]))
        coverage[key] = {
            "attempts_fired": int(row.get("attempts_fired", 0)),
            "pass_count": int(row.get("pass_count", 0)),
            "fail_count": int(row.get("fail_count", 0)),
            "partial_count": int(row.get("partial_count", 0)),
        }

    open_finding_categories: dict[str, int] = {}
    of_payload = seen.get("list_open_findings") or {}
    for row in of_payload.get("rows", []) if isinstance(of_payload, dict) else []:
        cat = str(row.get("category", ""))
        if cat:
            open_finding_categories[cat] = open_finding_categories.get(cat, 0) + 1

    regression_categories: dict[str, int] = {}
    rr_payload = seen.get("list_recent_regressions") or {}
    for row in rr_payload.get("rows", []) if isinstance(rr_payload, dict) else []:
        cat = str(row.get("category", ""))
        if cat:
            regression_categories[cat] = regression_categories.get(cat, 0) + 1

    cold_start = not coverage and not open_finding_categories and not regression_categories

    return _ToolOutputs(
        cold_start=cold_start,
        operator_budget_usd=2.0,
        catalog_categories=catalog_categories,
        techniques_by_category=techniques_by_category,
        coverage=coverage,
        open_finding_categories=open_finding_categories,
        regression_categories=regression_categories,
    )


def _orchestrator_responder(messages: list[dict[str, Any]]) -> dict[str, Any]:
    """Scripted LangGraph agent. Walks the data tools in a fixed order,
    then submits a plan whose attempts follow the iteration-N heuristic.

    Returns the LLM-response shape FakeLLMClient expects:
    ``{"text": "", "tool_calls": [{"id", "name", "arguments"}]}``."""
    seen = _collect_tool_outputs(messages)
    next_tool = _next_data_tool(seen)
    if next_tool is not None:
        return {
            "text": "",
            "tool_calls": [
                {
                    "id": f"call-{next_tool}",
                    "name": next_tool,
                    "arguments": {},
                }
            ],
        }

    snap = _snapshot_from_tool_results(seen)

    # Cold-start branch: one technique per catalogued category, in
    # catalog order. Rationale acknowledges no prior signal.
    if snap.cold_start:
        attempts: list[dict[str, Any]] = []
        for cat in snap.catalog_categories[:_MAX_ATTEMPTS]:
            techs = snap.techniques_by_category.get(cat, ["default"])
            if not techs:
                continue
            attempts.append(_attempt(cat, techs[0]))
        rationale = (
            "cold start: list_coverage rows is empty and list_open_findings is "
            "empty — no observability signal to rank against. Spreading "
            "breadth-first across "
            + ", ".join(snap.catalog_categories[:_MAX_ATTEMPTS])
            + " with one technique each. "
            + "Prioritize "
            + (snap.catalog_categories[0] if snap.catalog_categories else "injection")
            + " first because the catalog lists it first; ordering is by "
            "catalog position, not by signal."
        )
        return _submit_plan_call(attempts, rationale)

    # Adaptive branch: rank categories by signal score, then drop any
    # category whose score is materially worse than the leader once we
    # have an open finding or regression to anchor on.
    ranked, scores = _rank_categories_with_scores(snap)
    has_strong_signal = bool(snap.open_finding_categories or snap.regression_categories)
    chosen: list[tuple[str, str]] = []
    if has_strong_signal:
        leader_score = scores[ranked[0]]
        for cat in ranked:
            if leader_score - scores[cat] <= 5.0 and len(chosen) < _MAX_ATTEMPTS:
                chosen.append((cat, _pick_technique(cat, snap)))
    else:
        for cat in ranked[:_MAX_ATTEMPTS]:
            chosen.append((cat, _pick_technique(cat, snap)))

    attempts = [_attempt(c, t) for c, t in chosen]
    rationale = _adaptive_rationale(snap, chosen)
    return _submit_plan_call(attempts, rationale)


def _rank_categories_with_scores(
    snap: _ToolOutputs,
) -> tuple[list[str], dict[str, float]]:
    """Score each catalogued category. Higher = run first. Returns
    (ranked-category-list, score-by-category)."""
    scores: dict[str, float] = {}
    for cat in snap.catalog_categories:
        open_count = snap.open_finding_categories.get(cat, 0)
        regr_count = snap.regression_categories.get(cat, 0)
        saturation = sum(
            row["pass_count"] for (rcat, _t), row in snap.coverage.items() if rcat == cat
        )
        scores[cat] = open_count * 10.0 + regr_count * 5.0 - float(saturation)

    # Sort by score desc, then catalog position for determinism.
    catalog_position = {c: i for i, c in enumerate(snap.catalog_categories)}
    ranked = sorted(
        snap.catalog_categories,
        key=lambda c: (-scores[c], catalog_position[c]),
    )
    return ranked, scores


def _pick_technique(cat: str, snap: _ToolOutputs) -> str:
    """Prefer a technique with zero attempts fired; fall back to the
    least-fired technique. Deterministic by sorted technique name."""
    techs = snap.techniques_by_category.get(cat, ["default"])
    if not techs:
        return "default"
    fired = {t: snap.coverage.get((cat, t), {}).get("attempts_fired", 0) for t in techs}
    # Sort by (attempts_fired asc, name asc) so 0 wins, then alpha tie-break.
    return sorted(techs, key=lambda t: (fired[t], t))[0]


def _adaptive_rationale(snap: _ToolOutputs, chosen: list[tuple[str, str]]) -> str:
    """Produce a rationale that mentions the top category, its
    technique, the signal that promoted it, and an ordering word.

    Required by :func:`cats.agents.orchestrator.planner._validate_plan`:
    rationale must be >= 30 chars, name a category, and ideally cite a
    tool output. We over-satisfy all three."""
    if not chosen:
        return (
            "list_coverage empty after observation; falling back to default "
            "ordering — no attempts can be ranked."
        )
    first_cat, first_tech = chosen[0]
    parts: list[str] = []
    open_count = snap.open_finding_categories.get(first_cat, 0)
    regr_count = snap.regression_categories.get(first_cat, 0)
    saturation = sum(
        row["pass_count"] for (rcat, _t), row in snap.coverage.items() if rcat == first_cat
    )
    if open_count:
        parts.append(
            f"list_open_findings shows {open_count} open finding(s) in {first_cat}; "
            f"prioritize {first_cat}/{first_tech} first to confirm reproducibility."
        )
    elif regr_count:
        parts.append(
            f"list_recent_regressions shows {regr_count} regression(s) in "
            f"{first_cat}; prioritize {first_cat}/{first_tech} first."
        )
    else:
        parts.append(
            f"No open findings yet; prioritize {first_cat}/{first_tech} first "
            f"because list_coverage shows the lowest saturation here."
        )
    parts.append(
        f"Saturation pass_count for {first_cat} is {saturation}; "
        "lower-saturation categories rank above heavily-passed ones."
    )
    other_cats = [c for c, _ in chosen[1:]]
    if other_cats:
        parts.append("Following with " + " then ".join(other_cats) + " to maintain breadth.")
    return " ".join(parts)


def _attempt(category: str, technique: str) -> dict[str, Any]:
    return {
        "category": category,
        "technique": technique,
        "per_attempt_budget_usd": _PER_ATTEMPT_USD,
        "max_consecutive_partials": 2,
    }


def _submit_plan_call(attempts: list[dict[str, Any]], rationale: str) -> dict[str, Any]:
    """Wrap the plan in a ``submit_plan`` tool_call envelope. Returns
    the LLM-response shape FakeLLMClient expects."""
    total = sum(float(a["per_attempt_budget_usd"]) for a in attempts)
    return {
        "text": "",
        "tool_calls": [
            {
                "id": "call-submit_plan",
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


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _install_orchestrator_llm() -> Iterator[FakeLLMClient]:
    """Install the scripted FakeLLMClient for the orchestrator role."""
    fake = FakeLLMClient()
    fake.register("orchestrator", _orchestrator_responder)
    install_override(fake)
    try:
        yield fake
    finally:
        install_override(None)


@pytest_asyncio.fixture
async def project_ids(client: Any) -> AsyncIterator[tuple[UUID, UUID]]:
    """Seed one Project + ProjectVersion and yield their UUIDs. The
    ``client`` fixture handles DB truncation and engine binding."""
    _ = client  # depend on the conftest fixture for DB lifecycle
    project_id = uuid4()
    project_version_id = uuid4()
    async with session_scope() as s:
        await s.execute(
            insert(projects).values(
                id=project_id,
                name=f"orchestrator-adaptive-{project_id}",
                base_url="http://fake-target.invalid",
                env="local",
                allow_run_against=False,
            )
        )
        await s.execute(
            insert(project_versions).values(
                id=project_version_id,
                project_id=project_id,
                label="v1",
            )
        )
    yield project_id, project_version_id


# ---------------------------------------------------------------------------
# Synthetic history seeding
# ---------------------------------------------------------------------------


async def _seed_iteration(
    session: AsyncSession,
    *,
    project_id: UUID,
    project_version_id: UUID,
    plan: PlannedCampaign,
    iteration: int,
) -> None:
    """Apply the iteration-N scenario: create a Campaign + Run for this
    iteration, then write one Attack + AttackExecution + JudgeVerdict
    per plan attempt. Plus the scripted Finding rows on iterations 4
    (open exfil) and 8 (regressed tool_abuse)."""
    campaign_id = uuid4()
    run_id = uuid4()
    await session.execute(
        insert(campaigns).values(
            id=campaign_id,
            name=f"adaptive-iter-{iteration}",
            project_id=project_id,
            mode="blackhat",
            trigger="on_demand",
            budget={"usd": 2.0},
        )
    )
    await session.execute(
        insert(runs).values(
            id=run_id,
            campaign_id=campaign_id,
            project_version_id=project_version_id,
            status="completed",
        )
    )

    # Walk each planned attempt and stamp the verdict per the scenario.
    for idx, attempt in enumerate(plan.attempts):
        verdict_label = _verdict_for(iteration, attempt.category)
        attack_id = await upsert_attack(
            session,
            category=attempt.category,
            title=f"{attempt.category}/{attempt.technique} iter {iteration}",
            description="seeded by test",
            payload={"technique": attempt.technique},
            signature=f"sig-{iteration}-{idx}-{attempt.category}-{attempt.technique}",
            source="seed",
            run_id=run_id,
        )
        verdict_id = await record_verdict(
            session,
            verdict=verdict_label,
            is_deterministic=True,
            rationale=f"seeded for iteration {iteration}",
            evidence={},
            judge_model="seed",
        )
        await record_execution(
            session,
            run_id=run_id,
            attack_id=attack_id,
            project_version_id=project_version_id,
            target_response={"seeded": True},
            target_status_code=200,
            target_latency_ms=1,
            output_filter_verdict="safe",
            output_filter_reason="",
            judge_verdict_id=verdict_id,
            model="seed-model",
            agent_role="redteam_injection",
            tokens_in=10,
            tokens_out=10,
            usd_estimate=0.0,
            langsmith_trace_id=None,
        )

    # Scripted findings per the scenario.
    if iteration == 4:
        await session.execute(
            insert(findings).values(
                run_id=run_id,
                category="exfil",
                signature=f"exfil-open-{iteration}",
                title="Synthetic open exfil finding (test fixture)",
                severity="high",
                status="open",
                summary="Test fixture: exfil category should rise in priority.",
            )
        )
    if iteration == 8:
        await session.execute(
            insert(findings).values(
                run_id=run_id,
                category="tool_abuse",
                signature=f"tool-abuse-regressed-{iteration}",
                title="Synthetic regressed tool_abuse finding (test fixture)",
                severity="high",
                status="regressed",
                summary="Test fixture: tool_abuse should rise via regressions.",
            )
        )


def _verdict_for(iteration: int, category: str) -> str:
    """Iteration 1-3 + 5-7 mostly pass (saturating defenses). Other
    iterations alternate slightly so we don't degenerate to all-pass."""
    if iteration in (1, 2, 3, 5, 6, 7):
        return "pass"
    if iteration == 4 and category == "exfil":
        # Real vuln found — verdict is fail.
        return "fail"
    if iteration == 8 and category == "tool_abuse":
        return "fail"
    return "pass"


# ---------------------------------------------------------------------------
# The test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_plan_evolves_across_ten_consecutive_campaigns(
    project_ids: tuple[UUID, UUID],
) -> None:
    """R4 DoD: across ten campaigns the plan's priorities visibly
    follow observability signals and the rationale names them."""
    project_id, project_version_id = project_ids
    proposals: list[PlanProposal] = []

    for iteration in range(1, 11):
        proposal = await propose_plan(
            project_id=project_id,
            project_version_id=project_version_id,
            budget_usd=2.0,
        )
        proposals.append(proposal)
        async with session_scope() as s:
            await _seed_iteration(
                s,
                project_id=project_id,
                project_version_id=project_version_id,
                plan=proposal.plan,
                iteration=iteration,
            )

    assert len(proposals) == 10

    # --- Assertion 1: iteration 1 is cold-start, iteration 10 is not.
    assert proposals[0].cold_start is True, "iteration 1 should be cold-start"
    assert proposals[9].cold_start is False, (
        "iteration 10 should not be cold-start after 9 iterations of history"
    )

    # --- Assertion 2: after iter 4 (open exfil finding), exfil ranks high.
    exfil_promoted = False
    for idx in range(4, 10):  # proposals indexes 4..9 == iterations 5..10
        plan = proposals[idx].plan
        cats_in_order = [a.category for a in plan.attempts]
        if "exfil" in cats_in_order[:2]:
            exfil_promoted = True
            # Rationale must name the category it prioritized.
            assert "exfil" in proposals[idx].plan.rationale.lower(), (
                f"iteration {idx + 1} promoted exfil but the rationale doesn't name it: "
                f"{proposals[idx].plan.rationale!r}"
            )
            break
    assert exfil_promoted, (
        "no iteration after the open exfil finding ranked exfil in the top 2: "
        + repr([[a.category for a in p.plan.attempts] for p in proposals])
    )

    # --- Assertion 3: after iter 8 (regressed tool_abuse), tool_abuse appears.
    tool_abuse_appeared = False
    for idx in range(8, 10):  # iterations 9 and 10
        cats_in_plan = {a.category for a in proposals[idx].plan.attempts}
        if "tool_abuse" in cats_in_plan:
            tool_abuse_appeared = True
            assert "tool_abuse" in proposals[idx].plan.rationale.lower(), (
                f"iteration {idx + 1} included tool_abuse but the rationale "
                f"doesn't name it: {proposals[idx].plan.rationale!r}"
            )
            break
    assert tool_abuse_appeared, "tool_abuse did not appear in any plan after the regression landed"

    # --- Assertion 4: saturation pushes injection out of at least one plan.
    # Iterations 1-7 should hammer injection repeatedly; by 8-10 the
    # heuristic's saturation penalty should drop it at least once.
    injection_dropped_at_least_once = False
    for idx in range(4, 10):
        cats_in_plan = {a.category for a in proposals[idx].plan.attempts}
        if "injection" not in cats_in_plan:
            injection_dropped_at_least_once = True
            break
    assert injection_dropped_at_least_once, (
        "injection appeared in every adaptive plan; saturation signal had no effect: "
        + repr([[a.category for a in p.plan.attempts] for p in proposals[4:]])
    )

    # --- Assertion 5: every rationale names the top category it picked.
    for idx, proposal in enumerate(proposals):
        plan = proposal.plan
        if not plan.attempts:
            continue
        top_cat = plan.attempts[0].category
        assert top_cat.lower() in plan.rationale.lower(), (
            f"iteration {idx + 1} rationale does not name top category "
            f"{top_cat!r}: {plan.rationale!r}"
        )

    # --- Assertion 6: cold-start rationale acknowledges the empty state.
    assert "cold start" in proposals[0].plan.rationale.lower(), (
        f"iteration 1 rationale should acknowledge cold-start: {proposals[0].plan.rationale!r}"
    )
