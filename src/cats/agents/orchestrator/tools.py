"""Orchestrator tool surface — the typed read-only window the LangGraph
planner agent uses to reason about platform state.

Eight tools, each a pure async function with a Pydantic input + output
schema:

- :func:`list_coverage` — per-(category, technique) attempt counts +
  pass/fail/partial mix + last-tested timestamp over a lookback window.
- :func:`list_open_findings` — outstanding (un-fixed) findings filtered
  by minimum severity.
- :func:`list_recent_regressions` — findings whose status is currently
  ``regressed`` (best-effort, see docstring).
- :func:`list_attack_categories` — the catalogued attack-surface map
  (in-code taxonomy, no DB call).
- :func:`budget_remaining` — wall-clock / dollar budget remaining for a
  campaign (or project-level defaults, currently fixed).
- :func:`coverage_for_category` — drill-down: per-technique coverage
  state for one category. Lets the agent zoom in instead of dragging
  the full matrix through the context window.
- :func:`recent_campaigns` — past N campaigns for this project: their
  plans + outcomes (verdict mix, USD spend). The cross-campaign
  learning channel — what was tried before and how it went.
- :func:`run_submit_plan` (terminal) — validate + commit the candidate
  plan via the existing :func:`_validate_plan` in ``planner.py``.
  Returns a tool-error payload on invalid plans so the agent can
  self-correct in the loop.

The first 7 are read-only data tools; ``submit_plan`` is the terminal
write-into-context tool that ends the loop.

Design rules (do not break without explicit user direction):

- Every read-only function is safe on an empty DB. Empty inputs return
  empty collections / zero counts, never raise.
- Functions accept either an ``AsyncSession`` (for tests / when a
  caller already holds one) or fall back to opening their own via
  :func:`cats.db.engine.session_scope`.
- No LLM calls happen here. These tools are pure DB reads + an in-code
  taxonomy walk.
- No imports from agent workers. The point of the tool surface is that
  the strategic layer reads observability, not agent state.

The :data:`ALL_TOOLS` tuple at the bottom of this module is what the
agent advertises to its LLM. :data:`TOOL_DESCRIPTORS` is retained as a
JSON-schema-style descriptor list derived from ``ALL_TOOLS`` for
back-compat with any external consumers (audit panels, docs).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from cats.agents.red_team.clinical_misinformation.dispatcher import (
    KNOWN_TECHNIQUES as CLINICAL_MISINFORMATION_TECHNIQUES,
)
from cats.agents.red_team.dos_cost.dispatcher import (
    KNOWN_TECHNIQUES as DOS_COST_TECHNIQUES,
)
from cats.agents.red_team.exfil.dispatcher import (
    KNOWN_TECHNIQUES as EXFIL_TECHNIQUES,
)
from cats.agents.red_team.indirect_injection.dispatcher import (
    KNOWN_TECHNIQUES as INDIRECT_INJECTION_TECHNIQUES,
)
from cats.agents.red_team.injection.dispatcher import (
    KNOWN_TECHNIQUES as INJECTION_TECHNIQUES,
)
from cats.agents.red_team.tool_abuse.dispatcher import (
    KNOWN_TECHNIQUES as TOOL_ABUSE_TECHNIQUES,
)
from cats.agents.red_team.xss.dispatcher import (
    KNOWN_TECHNIQUES as XSS_TECHNIQUES,
)
from cats.categories import REGISTERED_CATEGORIES
from cats.categories import taxonomy as taxonomy_lookup
from cats.db.engine import session_scope
from cats.db.schema import (
    attack_executions,
    attacks,
    campaign_plans,
    campaigns,
    findings,
    judge_verdicts,
    runs,
)
from cats.llm.client import LLMClient, LLMResult, ToolSpec
from cats.logging import get_logger

log = get_logger(__name__)

# Severity rank — local constant rather than a library so the import
# surface stays small and the comparison is auditable.
_SEVERITY_RANK: Mapping[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

# Technique catalogue. Each category exposes only the techniques it
# actually has a specialist module for — the dispatchers raise
# NotImplementedError on deferred techniques, so emitting an unshipped
# technique in a plan would crash the worker. R7 foundations added the
# tool_abuse specialist family; the Orchestrator can now plan against
# its three techniques (`chart_area_over_read`,
# `cross_task_tool_invocation`, `repeat_invocation_pressure`).
_KNOWN_TECHNIQUES_BY_CATEGORY: Mapping[str, tuple[str, ...]] = {
    "injection": tuple(sorted(INJECTION_TECHNIQUES)),
    "indirect_injection": tuple(sorted(INDIRECT_INJECTION_TECHNIQUES)),
    "exfil": tuple(sorted(EXFIL_TECHNIQUES)),
    "tool_abuse": tuple(sorted(TOOL_ABUSE_TECHNIQUES)),
    "clinical_misinformation": tuple(sorted(CLINICAL_MISINFORMATION_TECHNIQUES)),
    "xss": tuple(sorted(XSS_TECHNIQUES)),
    "dos_cost": tuple(sorted(DOS_COST_TECHNIQUES)),
}

# Project-level budget defaults (TODO R5+: replace with a real
# per-project budget table; today campaigns own budgets, not projects).
_PROJECT_DEFAULT_USD_CAP = 25.0
_PROJECT_DEFAULT_WALL_CLOCK_MINUTES_CAP = 60


# ---------------------------------------------------------------------------
# Output schemas
# ---------------------------------------------------------------------------


class CoverageRow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    category: str
    technique: str
    attempts_fired: int
    last_tested_at: datetime | None
    pass_count: int
    fail_count: int
    partial_count: int


class CoverageReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_id: UUID
    lookback_days: int
    rows: list[CoverageRow] = Field(default_factory=list)


class OpenFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: UUID
    category: str
    severity: str
    signature: str
    title: str
    age_days: int


class OpenFindings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_id: UUID
    min_severity: str
    rows: list[OpenFinding] = Field(default_factory=list)


class RegressionFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: UUID
    category: str
    severity: str
    signature: str
    title: str
    regressed_at: datetime


class RecentRegressions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_id: UUID
    since_days: int
    rows: list[RegressionFinding] = Field(default_factory=list)
    # R4 limitation: we don't yet track status transitions explicitly
    # (see :func:`list_recent_regressions`). Surface that as a note the
    # Orchestrator prompt can quote.
    note: str = (
        "R4 limitation: regression detection currently filters on "
        "status='regressed' + updated_at window; explicit status-transition "
        "history is a planned R8 follow-up."
    )


class AttackCategory(BaseModel):
    model_config = ConfigDict(extra="forbid")

    category: str
    title: str
    severity_default: str
    atlas_technique_id: str | None
    owasp_llm_id: str | None
    techniques: list[str] = Field(default_factory=list)


class AttackCategoriesCatalog(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rows: list[AttackCategory] = Field(default_factory=list)


class BudgetRemaining(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scope: str  # "campaign" | "project_default"
    project_id: UUID
    campaign_id: UUID | None = None
    usd_cap: float
    usd_consumed: float
    usd_remaining: float
    wall_clock_minutes_cap: int
    wall_clock_minutes_consumed: int
    note: str = ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _meets_min_severity(severity: str, min_severity: str) -> bool:
    """``True`` iff ``severity`` is ``>=`` ``min_severity`` per
    :data:`_SEVERITY_RANK`. Unknown levels are treated as ``info`` so a
    bad input never silently filters everything out."""
    return _SEVERITY_RANK.get(severity, 0) >= _SEVERITY_RANK.get(min_severity, 0)


async def _with_session[T](
    session: AsyncSession | None,
    runner: Callable[[AsyncSession], Awaitable[T]],
) -> T:
    """Either reuse the caller's session or open a fresh
    :func:`session_scope` for the duration of one query. Keeps each tool
    callable two ways without duplicating the boilerplate."""
    if session is not None:
        return await runner(session)
    async with session_scope() as fresh:
        return await runner(fresh)


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


async def list_coverage(
    *,
    project_id: UUID,
    lookback_days: int = 30,
    session: AsyncSession | None = None,
) -> CoverageReport:
    """Per-(category, technique) attempt counts within ``lookback_days``.

    Joins ``attack_executions`` → ``attacks`` → ``runs`` → ``campaigns``,
    filtered to the requested project and a creation cutoff. Pass / fail
    / partial counts come from the joined ``judge_verdicts`` row when
    one exists; rows without a judge verdict contribute to
    ``attempts_fired`` but to none of the verdict counters.

    The ``technique`` is read from ``attacks.payload->>'technique'``
    (the convention every Red Team specialist follows when stamping an
    attack — see ``cats.graph.nodes.red_team_router``). Attacks missing
    that key are bucketed under the literal string ``"default"`` so the
    category is still represented.

    Empty DB → empty ``rows`` list. Never raises on missing data.
    """
    cutoff = _utcnow() - timedelta(days=lookback_days)

    technique_expr = func.coalesce(attacks.c.payload["technique"].astext, "default").label(
        "technique"
    )

    stmt = (
        select(
            attacks.c.category.label("category"),
            technique_expr,
            func.count(attack_executions.c.id).label("attempts_fired"),
            func.max(attack_executions.c.created_at).label("last_tested_at"),
            judge_verdicts.c.verdict.label("verdict"),
        )
        .select_from(
            attack_executions.join(attacks, attack_executions.c.attack_id == attacks.c.id)
            .join(runs, attack_executions.c.run_id == runs.c.id)
            .join(campaigns, runs.c.campaign_id == campaigns.c.id)
            .outerjoin(
                judge_verdicts,
                attack_executions.c.judge_verdict_id == judge_verdicts.c.id,
            )
        )
        .where(campaigns.c.project_id == project_id)
        .where(attack_executions.c.created_at > cutoff)
        .group_by(attacks.c.category, technique_expr, judge_verdicts.c.verdict)
    )

    async def _run(s: AsyncSession) -> CoverageReport:
        raw = (await s.execute(stmt)).all()
        # Fold per-(category, technique, verdict) groups back into one
        # row per (category, technique). SQL-side counts the buckets;
        # we sum into the right column based on the verdict label.
        bucket: dict[tuple[str, str], dict[str, Any]] = {}
        for row in raw:
            key = (row.category, row.technique)
            cell = bucket.setdefault(
                key,
                {
                    "attempts_fired": 0,
                    "last_tested_at": None,
                    "pass_count": 0,
                    "fail_count": 0,
                    "partial_count": 0,
                },
            )
            cell["attempts_fired"] += int(row.attempts_fired or 0)
            if row.last_tested_at is not None and (
                cell["last_tested_at"] is None or row.last_tested_at > cell["last_tested_at"]
            ):
                cell["last_tested_at"] = row.last_tested_at
            if row.verdict == "pass":
                cell["pass_count"] += int(row.attempts_fired or 0)
            elif row.verdict == "fail":
                cell["fail_count"] += int(row.attempts_fired or 0)
            elif row.verdict == "partial":
                cell["partial_count"] += int(row.attempts_fired or 0)
            # verdict == "error" or None: contributes to attempts only.

        rows = [
            CoverageRow(
                category=cat,
                technique=tech,
                attempts_fired=cell["attempts_fired"],
                last_tested_at=cell["last_tested_at"],
                pass_count=cell["pass_count"],
                fail_count=cell["fail_count"],
                partial_count=cell["partial_count"],
            )
            for (cat, tech), cell in sorted(bucket.items())
        ]
        return CoverageReport(project_id=project_id, lookback_days=lookback_days, rows=rows)

    return await _with_session(session, _run)


async def list_open_findings(
    *,
    project_id: UUID,
    min_severity: str = "info",
    session: AsyncSession | None = None,
) -> OpenFindings:
    """Open findings for the project, filtered by minimum severity.

    Joins ``findings`` → ``runs`` → ``campaigns`` on
    ``project_id == project_id`` and ``findings.status == 'open'``. The
    severity floor is enforced in Python against :data:`_SEVERITY_RANK`
    so the comparison is auditable and stable across DB locales.

    Empty DB → empty ``rows``. Never raises on a missing project.
    """
    stmt = (
        select(
            findings.c.id,
            findings.c.category,
            findings.c.severity,
            findings.c.signature,
            findings.c.title,
            findings.c.created_at,
        )
        .select_from(
            findings.join(runs, findings.c.run_id == runs.c.id).join(
                campaigns, runs.c.campaign_id == campaigns.c.id
            )
        )
        .where(campaigns.c.project_id == project_id)
        .where(findings.c.status == "open")
        .order_by(findings.c.created_at.desc())
    )

    async def _run(s: AsyncSession) -> OpenFindings:
        raw = (await s.execute(stmt)).all()
        now = _utcnow()
        rows: list[OpenFinding] = []
        for r in raw:
            if not _meets_min_severity(r.severity, min_severity):
                continue
            age = (now - r.created_at).days if r.created_at else 0
            rows.append(
                OpenFinding(
                    finding_id=r.id,
                    category=r.category,
                    severity=r.severity,
                    signature=r.signature,
                    title=r.title,
                    age_days=max(age, 0),
                )
            )
        return OpenFindings(project_id=project_id, min_severity=min_severity, rows=rows)

    return await _with_session(session, _run)


async def list_recent_regressions(
    *,
    project_id: UUID,
    since_days: int = 14,
    session: AsyncSession | None = None,
) -> RecentRegressions:
    """Findings whose current status is ``regressed`` with ``updated_at``
    inside the requested window.

    R4 limitation: the schema today doesn't carry an explicit status-
    transition history (no ``finding_status_events`` table). The best
    we can do is "current status == regressed and recently updated"
    which approximates "regressed since the last deploy" for the
    typical case but misses anything that regressed and was already
    re-fixed. Tracked as an R8 follow-up. See :class:`RecentRegressions`
    for the surfaced ``note`` the Orchestrator can quote.

    Empty DB → empty ``rows``.
    """
    cutoff = _utcnow() - timedelta(days=since_days)

    stmt = (
        select(
            findings.c.id,
            findings.c.category,
            findings.c.severity,
            findings.c.signature,
            findings.c.title,
            findings.c.updated_at,
        )
        .select_from(
            findings.join(runs, findings.c.run_id == runs.c.id).join(
                campaigns, runs.c.campaign_id == campaigns.c.id
            )
        )
        .where(campaigns.c.project_id == project_id)
        .where(findings.c.status == "regressed")
        .where(findings.c.updated_at > cutoff)
        .order_by(findings.c.updated_at.desc())
    )

    async def _run(s: AsyncSession) -> RecentRegressions:
        raw = (await s.execute(stmt)).all()
        rows = [
            RegressionFinding(
                finding_id=r.id,
                category=r.category,
                severity=r.severity,
                signature=r.signature,
                title=r.title,
                regressed_at=r.updated_at,
            )
            for r in raw
        ]
        return RecentRegressions(project_id=project_id, since_days=since_days, rows=rows)

    return await _with_session(session, _run)


async def list_attack_categories() -> AttackCategoriesCatalog:
    """The catalogued attack-surface map.

    Pure in-code helper — walks :data:`REGISTERED_CATEGORIES` and the
    per-category taxonomy (``cats/categories/<cat>/taxonomy.toml``). Async
    only for signature consistency with the other tools so a single
    tool dispatcher can ``await`` every entry uniformly.
    """
    rows: list[AttackCategory] = []
    for category in REGISTERED_CATEGORIES:
        label = taxonomy_lookup.lookup(category)
        techniques = list(_KNOWN_TECHNIQUES_BY_CATEGORY.get(category, ("default",)))
        rows.append(
            AttackCategory(
                category=category,
                title=label.description or category,
                severity_default=_default_severity_for(category),
                atlas_technique_id=label.atlas_technique_id,
                owasp_llm_id=label.owasp_llm_id,
                techniques=techniques,
            )
        )
    return AttackCategoriesCatalog(rows=rows)


def _default_severity_for(category: str) -> str:
    """Hard-coded severity floor per registered category — matches each
    category's manifest.toml. Kept in-code instead of re-parsing TOML at
    every tool call (this list is short and stable)."""
    return {
        "injection": "high",
        "indirect_injection": "critical",
        "exfil": "critical",
        "tool_abuse": "high",
        "clinical_misinformation": "critical",
        "xss": "critical",
        "dos_cost": "medium",
    }.get(category, "medium")


async def budget_remaining(
    *,
    project_id: UUID,
    campaign_id: UUID | None = None,
    session: AsyncSession | None = None,
) -> BudgetRemaining:
    """Remaining budget for a specific campaign, or project defaults.

    When ``campaign_id`` is provided, reads the campaign's ``budget``
    JSONB (today: ``{"usd": <cap>, "categories": [...]}``) and sums
    ``runs.budget_consumed_usd`` across all that campaign's runs. The
    wall-clock figures come from ``runs.started_at``/``ended_at`` (and
    the cap from ``budget.wall_clock_minutes`` if present, else a
    sensible default).

    When ``campaign_id`` is ``None``, returns hard-coded project-level
    defaults. The schema doesn't yet carry per-project budget rows
    (TODO R5+); the returned ``note`` surfaces that to the Orchestrator.

    Empty DB / unknown campaign → returns zeros with the budget cap set
    to the campaign's declared cap (or default 0 if the campaign is
    missing). Never raises.
    """
    if campaign_id is None:
        return BudgetRemaining(
            scope="project_default",
            project_id=project_id,
            campaign_id=None,
            usd_cap=_PROJECT_DEFAULT_USD_CAP,
            usd_consumed=0.0,
            usd_remaining=_PROJECT_DEFAULT_USD_CAP,
            wall_clock_minutes_cap=_PROJECT_DEFAULT_WALL_CLOCK_MINUTES_CAP,
            wall_clock_minutes_consumed=0,
            note=(
                "Project-level budgets are not yet a first-class entity; "
                "these are fixed defaults. TODO R5+: per-project budget rows."
            ),
        )

    async def _run(s: AsyncSession) -> BudgetRemaining:
        cam_row = (
            await s.execute(select(campaigns.c.budget).where(campaigns.c.id == campaign_id))
        ).first()
        budget_blob: dict[str, Any] = {}
        if cam_row is not None and isinstance(cam_row.budget, dict):
            budget_blob = cam_row.budget

        usd_cap = float(budget_blob.get("usd", 0.0) or 0.0)
        wall_cap = int(
            budget_blob.get("wall_clock_minutes", _PROJECT_DEFAULT_WALL_CLOCK_MINUTES_CAP)
            or _PROJECT_DEFAULT_WALL_CLOCK_MINUTES_CAP
        )

        spend_row = (
            await s.execute(
                select(
                    func.coalesce(func.sum(runs.c.budget_consumed_usd), 0.0).label("usd_consumed"),
                    func.coalesce(
                        func.sum(func.extract("epoch", runs.c.ended_at - runs.c.started_at)),
                        0.0,
                    ).label("wall_seconds_consumed"),
                ).where(runs.c.campaign_id == campaign_id)
            )
        ).first()
        usd_consumed = float(spend_row.usd_consumed) if spend_row else 0.0
        wall_seconds = float(spend_row.wall_seconds_consumed) if spend_row else 0.0
        wall_minutes_consumed = int(wall_seconds // 60) if wall_seconds > 0 else 0

        return BudgetRemaining(
            scope="campaign",
            project_id=project_id,
            campaign_id=campaign_id,
            usd_cap=usd_cap,
            usd_consumed=usd_consumed,
            usd_remaining=max(usd_cap - usd_consumed, 0.0),
            wall_clock_minutes_cap=wall_cap,
            wall_clock_minutes_consumed=wall_minutes_consumed,
            note="" if cam_row is not None else "campaign_id not found; returning zeros.",
        )

    return await _with_session(session, _run)


# ---------------------------------------------------------------------------
# Drill-down tools — new in the LangGraph orchestrator
# ---------------------------------------------------------------------------


class CoverageDrillDownRow(BaseModel):
    """One row of :class:`CoverageDrillDown` — the per-technique slice
    for the requested category. Same shape as :class:`CoverageRow` but
    omits ``category`` since it's pinned to the request."""

    model_config = ConfigDict(extra="forbid")

    technique: str
    attempts_fired: int
    last_tested_at: datetime | None
    pass_count: int
    fail_count: int
    partial_count: int


class CoverageDrillDown(BaseModel):
    """The per-technique coverage state for one category."""

    model_config = ConfigDict(extra="forbid")

    project_id: UUID
    category: str
    lookback_days: int
    rows: list[CoverageDrillDownRow] = Field(default_factory=list)


async def coverage_for_category(
    *,
    project_id: UUID,
    category: str,
    lookback_days: int = 30,
    session: AsyncSession | None = None,
) -> CoverageDrillDown:
    """Per-technique coverage for one category. Sibling of
    :func:`list_coverage` but filtered by ``category`` so the agent can
    drill into a specific category without re-loading the full matrix.

    Empty DB → empty ``rows``. Never raises.
    """
    cutoff = _utcnow() - timedelta(days=lookback_days)
    technique_expr = func.coalesce(attacks.c.payload["technique"].astext, "default").label(
        "technique"
    )
    stmt = (
        select(
            technique_expr,
            func.count(attack_executions.c.id).label("attempts_fired"),
            func.max(attack_executions.c.created_at).label("last_tested_at"),
            judge_verdicts.c.verdict.label("verdict"),
        )
        .select_from(
            attack_executions.join(attacks, attack_executions.c.attack_id == attacks.c.id)
            .join(runs, attack_executions.c.run_id == runs.c.id)
            .join(campaigns, runs.c.campaign_id == campaigns.c.id)
            .outerjoin(
                judge_verdicts,
                attack_executions.c.judge_verdict_id == judge_verdicts.c.id,
            )
        )
        .where(campaigns.c.project_id == project_id)
        .where(attacks.c.category == category)
        .where(attack_executions.c.created_at > cutoff)
        .group_by(technique_expr, judge_verdicts.c.verdict)
    )

    async def _run(s: AsyncSession) -> CoverageDrillDown:
        raw = (await s.execute(stmt)).all()
        bucket: dict[str, dict[str, Any]] = {}
        for row in raw:
            cell = bucket.setdefault(
                row.technique,
                {
                    "attempts_fired": 0,
                    "last_tested_at": None,
                    "pass_count": 0,
                    "fail_count": 0,
                    "partial_count": 0,
                },
            )
            cell["attempts_fired"] += int(row.attempts_fired or 0)
            if row.last_tested_at is not None and (
                cell["last_tested_at"] is None or row.last_tested_at > cell["last_tested_at"]
            ):
                cell["last_tested_at"] = row.last_tested_at
            if row.verdict == "pass":
                cell["pass_count"] += int(row.attempts_fired or 0)
            elif row.verdict == "fail":
                cell["fail_count"] += int(row.attempts_fired or 0)
            elif row.verdict == "partial":
                cell["partial_count"] += int(row.attempts_fired or 0)
        rows = [
            CoverageDrillDownRow(
                technique=tech,
                attempts_fired=cell["attempts_fired"],
                last_tested_at=cell["last_tested_at"],
                pass_count=cell["pass_count"],
                fail_count=cell["fail_count"],
                partial_count=cell["partial_count"],
            )
            for tech, cell in sorted(bucket.items())
        ]
        return CoverageDrillDown(
            project_id=project_id,
            category=category,
            lookback_days=lookback_days,
            rows=rows,
        )

    return await _with_session(session, _run)


class RecentCampaignPlanAttempt(BaseModel):
    """One (category, technique) slot from a past campaign's plan."""

    model_config = ConfigDict(extra="forbid")

    category: str
    technique: str


class RecentCampaign(BaseModel):
    """One past campaign's plan + outcome summary."""

    model_config = ConfigDict(extra="forbid")

    campaign_id: UUID
    name: str
    created_at: datetime
    attempts_fired: int
    verdict_pass: int
    verdict_fail: int
    verdict_partial: int
    verdict_error: int
    usd_consumed: float
    plan_summary: list[RecentCampaignPlanAttempt] = Field(default_factory=list)
    plan_rationale: str = ""


class RecentCampaignsReport(BaseModel):
    """The previous campaigns for this project, newest first."""

    model_config = ConfigDict(extra="forbid")

    project_id: UUID
    n: int
    rows: list[RecentCampaign] = Field(default_factory=list)


async def recent_campaigns(
    *,
    project_id: UUID,
    n: int = 5,
    session: AsyncSession | None = None,
) -> RecentCampaignsReport:
    """Most recent N campaigns for this project, with plan summary +
    aggregate outcome stats. Lets the orchestrator agent learn from
    what was tried before: which scenarios were planned, how many
    attacks they fired, and the verdict mix.

    Plan summary comes from the latest ``campaign_plans`` row per
    campaign (``approved_plan`` if set, otherwise ``proposed_plan``).
    Verdict counts join ``attack_executions`` → ``judge_verdicts``.

    Empty DB → empty ``rows``. Never raises.
    """
    n = max(1, min(n, 20))

    async def _run(s: AsyncSession) -> RecentCampaignsReport:
        # 1) Pick the N most recent campaigns for this project.
        campaign_rows = (
            await s.execute(
                select(
                    campaigns.c.id,
                    campaigns.c.name,
                    campaigns.c.created_at,
                )
                .where(campaigns.c.project_id == project_id)
                .order_by(desc(campaigns.c.created_at))
                .limit(n)
            )
        ).all()
        if not campaign_rows:
            return RecentCampaignsReport(project_id=project_id, n=n, rows=[])

        out: list[RecentCampaign] = []
        for cam in campaign_rows:
            # 2) Verdict-mix + attempts_fired + usd_consumed in one
            #    aggregate query per campaign.
            stats = (
                await s.execute(
                    select(
                        func.count(attack_executions.c.id).label("attempts_fired"),
                        func.coalesce(func.sum(runs.c.budget_consumed_usd), 0.0).label(
                            "usd_consumed_unique"
                        ),
                        judge_verdicts.c.verdict.label("verdict"),
                    )
                    .select_from(
                        attack_executions.join(
                            runs, attack_executions.c.run_id == runs.c.id
                        ).outerjoin(
                            judge_verdicts,
                            attack_executions.c.judge_verdict_id == judge_verdicts.c.id,
                        )
                    )
                    .where(runs.c.campaign_id == cam.id)
                    .group_by(judge_verdicts.c.verdict)
                )
            ).all()
            attempts_fired = 0
            verdict_counts = {"pass": 0, "fail": 0, "partial": 0, "error": 0}
            for sr in stats:
                attempts_fired += int(sr.attempts_fired or 0)
                if sr.verdict in verdict_counts:
                    verdict_counts[sr.verdict] += int(sr.attempts_fired or 0)

            # Spend separately (one row sum, not multiplied by verdict groups).
            spend_row = (
                await s.execute(
                    select(
                        func.coalesce(func.sum(runs.c.budget_consumed_usd), 0.0).label(
                            "usd_consumed"
                        )
                    ).where(runs.c.campaign_id == cam.id)
                )
            ).first()
            usd_consumed = float(spend_row.usd_consumed) if spend_row else 0.0

            # 3) Latest plan for this campaign (approved if any, else proposed).
            plan_row = (
                await s.execute(
                    select(
                        campaign_plans.c.proposed_plan,
                        campaign_plans.c.approved_plan,
                        campaign_plans.c.rationale,
                    )
                    .where(campaign_plans.c.campaign_id == cam.id)
                    .order_by(desc(campaign_plans.c.created_at))
                    .limit(1)
                )
            ).first()
            plan_summary: list[RecentCampaignPlanAttempt] = []
            plan_rationale = ""
            if plan_row is not None:
                blob = plan_row.approved_plan or plan_row.proposed_plan or {}
                if isinstance(blob, dict):
                    for entry in blob.get("attempts", []) or []:
                        if not isinstance(entry, dict):
                            continue
                        cat = str(entry.get("category", "")).strip()
                        tech = str(entry.get("technique", "")).strip()
                        if not cat or not tech:
                            continue
                        plan_summary.append(RecentCampaignPlanAttempt(category=cat, technique=tech))
                plan_rationale = (plan_row.rationale or "")[:600]

            out.append(
                RecentCampaign(
                    campaign_id=cam.id,
                    name=cam.name,
                    created_at=cam.created_at,
                    attempts_fired=attempts_fired,
                    verdict_pass=verdict_counts["pass"],
                    verdict_fail=verdict_counts["fail"],
                    verdict_partial=verdict_counts["partial"],
                    verdict_error=verdict_counts["error"],
                    usd_consumed=usd_consumed,
                    plan_summary=plan_summary,
                    plan_rationale=plan_rationale,
                )
            )
        return RecentCampaignsReport(project_id=project_id, n=n, rows=out)

    return await _with_session(session, _run)


# ---------------------------------------------------------------------------
# Submit-plan terminal tool
# ---------------------------------------------------------------------------


class PlanAttemptArg(BaseModel):
    """One (category, technique) slot the agent proposes via
    :func:`run_submit_plan`. Same shape as
    :class:`cats.messaging.envelopes.PlanAttempt` but trimmed to the
    fields the validator reads."""

    model_config = ConfigDict(extra="forbid")

    category: str
    technique: str
    per_attempt_budget_usd: float = Field(default=0.50, ge=0.0)
    max_consecutive_partials: int = Field(default=2, ge=0, le=10)


class SubmitPlanArgs(BaseModel):
    """Arguments to the terminal :func:`run_submit_plan` tool. The agent
    builds the plan, calls this, and the platform validates."""

    model_config = ConfigDict(extra="forbid")

    attempts: list[PlanAttemptArg]
    rationale: str
    confidence: Literal["low", "medium", "high"] = "medium"
    halt_on_consecutive_fails: int = Field(default=3, ge=1, le=20)
    halt_on_judge_errors: int = Field(default=2, ge=1, le=10)
    budget_usd_cap: float = Field(default=0.0, ge=0.0)


# ---------------------------------------------------------------------------
# ToolOutcome + AgentTurnCost — the LangGraph contract
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ToolOutcome:
    """What an executed tool returns to the LangGraph node. The dict
    payload becomes the ``content`` of the tool message the next LLM
    turn sees; ``terminal`` short-circuits the loop when the agent
    submits a valid plan."""

    payload: dict[str, Any]
    terminal: bool = False


@dataclass(frozen=True)
class AgentTurnCost:
    """Per-LLM-call cost line for the orchestrator agent. Each
    planner-node turn appends one entry; the entrypoint sums them into
    the ``PlanProposal.cost_usd`` total."""

    role: str
    model: str
    tokens_in: int
    tokens_out: int
    usd: float
    trace_id: str


# ---------------------------------------------------------------------------
# OrchestratorContext + dispatch
# ---------------------------------------------------------------------------


@dataclass
class OrchestratorContext:
    """Mutable per-session state shared by all tools. Held in the
    process-global ``_CTX_HOLDER`` in ``agent.py`` so ``AsyncSession``
    never round-trips through the LangGraph checkpointer.

    The agent reads ``budget_usd`` (the operator's campaign budget — what
    it's *planning against*) and ``budget_usd_cap`` (its OWN LLM-loop
    spend ceiling) and is expected to call :func:`run_submit_plan`
    before either cap trips."""

    session: AsyncSession | None
    llm: LLMClient
    project_id: UUID
    project_version_id: UUID
    trace_id: str
    # The operator's campaign budget (what we plan against).
    budget_usd: float
    # The agent's own LLM-loop budget — defense-in-depth.
    budget_usd_cap: float
    # Defense-in-depth turn caps.
    max_agent_turns: int
    max_tool_calls: int
    # Optional context for budget_remaining + audit rows.
    campaign_id: UUID | None = None
    # Running state.
    budget_consumed_usd: float = 0.0
    tool_call_count: int = 0
    costs: list[AgentTurnCost] = field(default_factory=list)
    tool_transcript: list[dict[str, Any]] = field(default_factory=list)
    # Cached catalog populated lazily by run_list_attack_categories;
    # run_submit_plan validates against it without re-querying.
    cached_catalog: AttackCategoriesCatalog | None = None
    # Result slots set by run_submit_plan.
    submitted_plan: Any = None  # PlannedCampaign — typed as Any to avoid a circular import
    submission_attempts: int = 0
    model: str = ""
    stop_reason: str = ""

    def record_cost(self, *, role: str, result: LLMResult) -> None:
        """Append one LLM call's cost + bump the running total. Same
        shape the Red Team's :class:`AgentContext` uses."""
        self.costs.append(
            AgentTurnCost(
                role=role,
                model=result.model,
                tokens_in=result.tokens_in,
                tokens_out=result.tokens_out,
                usd=result.usd_estimate,
                trace_id=result.trace_id,
            )
        )
        self.budget_consumed_usd += result.usd_estimate
        if not self.model:
            self.model = result.model

    @property
    def cost_usd(self) -> float:
        return sum(c.usd for c in self.costs)

    def record_transcript(self, *, tool: str, args: dict[str, Any], output: Any) -> None:
        """Append one ``{tool, args, output}`` row to the transcript the
        worker persists to ``campaign_plans.tool_transcript``. The
        output is serialized via Pydantic's ``model_dump`` when
        possible so the JSONB column round-trips losslessly."""
        if hasattr(output, "model_dump"):
            serialized: Any = output.model_dump(mode="json")
        elif isinstance(output, dict):
            serialized = output
        else:
            serialized = str(output)
        self.tool_transcript.append({"tool": tool, "args": args, "output": serialized})


# ---------------------------------------------------------------------------
# Tool wrappers — each tool call runs through one of these
# ---------------------------------------------------------------------------


def _truncate_args(args: dict[str, Any]) -> dict[str, Any]:
    """Audit / transcript payloads should not balloon — truncate long
    string values defensively."""
    out: dict[str, Any] = {}
    for k, v in args.items():
        if isinstance(v, str) and len(v) > 400:
            out[k] = v[:400] + "..."
        else:
            out[k] = v
    return out


async def run_list_coverage(ctx: OrchestratorContext, *, args: dict[str, Any]) -> ToolOutcome:
    lookback = int(args.get("lookback_days", 30) or 30)
    report = await list_coverage(
        project_id=ctx.project_id,
        lookback_days=lookback,
        session=ctx.session,
    )
    ctx.record_transcript(
        tool="list_coverage",
        args={"lookback_days": lookback},
        output=report,
    )
    return ToolOutcome(payload=report.model_dump(mode="json"))


async def run_list_open_findings(ctx: OrchestratorContext, *, args: dict[str, Any]) -> ToolOutcome:
    min_sev = str(args.get("min_severity", "info") or "info")
    report = await list_open_findings(
        project_id=ctx.project_id,
        min_severity=min_sev,
        session=ctx.session,
    )
    ctx.record_transcript(
        tool="list_open_findings",
        args={"min_severity": min_sev},
        output=report,
    )
    return ToolOutcome(payload=report.model_dump(mode="json"))


async def run_list_recent_regressions(
    ctx: OrchestratorContext, *, args: dict[str, Any]
) -> ToolOutcome:
    since = int(args.get("since_days", 14) or 14)
    report = await list_recent_regressions(
        project_id=ctx.project_id,
        since_days=since,
        session=ctx.session,
    )
    ctx.record_transcript(
        tool="list_recent_regressions",
        args={"since_days": since},
        output=report,
    )
    return ToolOutcome(payload=report.model_dump(mode="json"))


async def run_list_attack_categories(
    ctx: OrchestratorContext, *, args: dict[str, Any]
) -> ToolOutcome:
    _ = args
    catalog = await list_attack_categories()
    ctx.cached_catalog = catalog
    ctx.record_transcript(tool="list_attack_categories", args={}, output=catalog)
    return ToolOutcome(payload=catalog.model_dump(mode="json"))


async def run_budget_remaining(ctx: OrchestratorContext, *, args: dict[str, Any]) -> ToolOutcome:
    _ = args
    report = await budget_remaining(
        project_id=ctx.project_id,
        campaign_id=ctx.campaign_id,
        session=ctx.session,
    )
    ctx.record_transcript(
        tool="budget_remaining",
        args={"campaign_id": str(ctx.campaign_id) if ctx.campaign_id else None},
        output=report,
    )
    return ToolOutcome(payload=report.model_dump(mode="json"))


async def run_coverage_for_category(
    ctx: OrchestratorContext, *, args: dict[str, Any]
) -> ToolOutcome:
    category = str(args.get("category", "")).strip()
    if not category:
        payload = {
            "error": "coverage_for_category requires a non-empty 'category' argument.",
        }
        ctx.record_transcript(
            tool="coverage_for_category", args=_truncate_args(args), output=payload
        )
        return ToolOutcome(payload=payload)
    lookback = int(args.get("lookback_days", 30) or 30)
    report = await coverage_for_category(
        project_id=ctx.project_id,
        category=category,
        lookback_days=lookback,
        session=ctx.session,
    )
    ctx.record_transcript(
        tool="coverage_for_category",
        args={"category": category, "lookback_days": lookback},
        output=report,
    )
    return ToolOutcome(payload=report.model_dump(mode="json"))


async def run_recent_campaigns(ctx: OrchestratorContext, *, args: dict[str, Any]) -> ToolOutcome:
    n = int(args.get("n", 5) or 5)
    report = await recent_campaigns(
        project_id=ctx.project_id,
        n=n,
        session=ctx.session,
    )
    ctx.record_transcript(
        tool="recent_campaigns",
        args={"n": n},
        output=report,
    )
    return ToolOutcome(payload=report.model_dump(mode="json"))


async def run_submit_plan(ctx: OrchestratorContext, *, args: dict[str, Any]) -> ToolOutcome:
    """Terminal: validate the proposed plan + commit it to ctx. On
    invalid plans, return a tool-error payload so the next agent turn
    sees the validator's message and self-corrects."""
    # Imported here to avoid a circular import — planner.py imports
    # from tools.py for the ToolSpec catalog and validators.
    from cats.agents.orchestrator.planner import PlanStructuralError, _validate_plan

    ctx.submission_attempts += 1
    # Pre-validate the argument shape via Pydantic — gives a clearer
    # error than the structural validator's own keying.
    try:
        parsed = SubmitPlanArgs.model_validate(args)
    except Exception as exc:
        payload = {
            "error": f"submit_plan args malformed: {exc}",
            "hint": (
                "submit_plan expects {attempts: [{category, technique, "
                "per_attempt_budget_usd, max_consecutive_partials}], "
                "rationale, confidence, halt_on_consecutive_fails, "
                "halt_on_judge_errors, budget_usd_cap}. Fix and resubmit."
            ),
            "submission_attempts": ctx.submission_attempts,
        }
        ctx.record_transcript(
            tool="submit_plan",
            args=_truncate_args(args),
            output=payload,
        )
        return ToolOutcome(payload=payload)

    # The catalog must be loaded so the validator knows the valid pairs.
    # If the agent didn't call list_attack_categories, we load it now —
    # a missed prerequisite shouldn't fail the submission deterministically.
    if ctx.cached_catalog is None:
        ctx.cached_catalog = await list_attack_categories()

    # Default budget_usd_cap to the operator's budget when the agent
    # leaves it at 0 — strict validation would otherwise reject "sum of
    # attempts > 0" against "cap = 0".
    raw_plan: dict[str, Any] = parsed.model_dump(mode="json")
    if raw_plan.get("budget_usd_cap", 0.0) <= 0.0:
        raw_plan["budget_usd_cap"] = ctx.budget_usd

    try:
        plan = _validate_plan(
            raw=raw_plan,
            budget_usd_cap=ctx.budget_usd,
            catalog=ctx.cached_catalog,
        )
    except PlanStructuralError as exc:
        # Build a hint that names the valid pairs so the agent doesn't
        # guess. Mirrors the R4-era retry message but delivered via the
        # tool-result channel so the model sees it inline.
        valid_pairs = sorted(
            f"{cat.category}/{tech}" for cat in ctx.cached_catalog.rows for tech in cat.techniques
        )
        payload = {
            "error": str(exc),
            "hint": (
                "Fix the named issue and call submit_plan again. Valid "
                "(category, technique) pairs: " + ", ".join(valid_pairs)
            ),
            "submission_attempts": ctx.submission_attempts,
        }
        ctx.record_transcript(
            tool="submit_plan",
            args=_truncate_args(args),
            output=payload,
        )
        return ToolOutcome(payload=payload)

    ctx.submitted_plan = plan
    ctx.stop_reason = "agent_submitted"
    payload = {
        "ok": True,
        "attempts": len(plan.attempts),
        "budget_usd_cap": plan.budget_usd_cap,
    }
    ctx.record_transcript(
        tool="submit_plan",
        args=_truncate_args(args),
        output=payload,
    )
    return ToolOutcome(payload=payload, terminal=True)


# ---------------------------------------------------------------------------
# ToolSpec catalog — advertised to the LLM
# ---------------------------------------------------------------------------


LIST_COVERAGE = ToolSpec(
    name="list_coverage",
    description=(
        "Return per-(category, technique) counts of attacks fired against "
        "this project in the last lookback_days days, plus the current "
        "pass/fail/partial verdict mix and last-tested timestamp. The "
        "project is fixed for this session — do not pass project_id."
    ),
    parameters={
        "type": "object",
        "properties": {
            "lookback_days": {
                "type": "integer",
                "minimum": 1,
                "default": 30,
                "description": "Window of attack history to include.",
            },
        },
        "required": [],
    },
)


LIST_OPEN_FINDINGS = ToolSpec(
    name="list_open_findings",
    description=(
        "Return outstanding (status='open') findings for this project "
        "filtered to severity >= min_severity. Use to drive 'probe this "
        "category to confirm the vulnerability is reproducible' planning."
    ),
    parameters={
        "type": "object",
        "properties": {
            "min_severity": {
                "type": "string",
                "enum": ["info", "low", "medium", "high", "critical"],
                "default": "info",
            },
        },
        "required": [],
    },
)


LIST_RECENT_REGRESSIONS = ToolSpec(
    name="list_recent_regressions",
    description=(
        "Findings currently marked 'regressed' whose updated_at is within "
        "since_days. Recent regressions outrank saturated coverage — a "
        "test that just started failing is more informative than one "
        "that's passed 30 times."
    ),
    parameters={
        "type": "object",
        "properties": {
            "since_days": {
                "type": "integer",
                "minimum": 1,
                "default": 14,
            },
        },
        "required": [],
    },
)


LIST_ATTACK_CATEGORIES = ToolSpec(
    name="list_attack_categories",
    description=(
        "Return the catalogued attack-surface map: each registered "
        "category, its default severity, ATLAS / OWASP labels, and the "
        "techniques the platform currently knows how to run. Call this "
        "BEFORE submit_plan — every (category, technique) pair you "
        "submit must come from this catalog."
    ),
    parameters={
        "type": "object",
        "properties": {},
        "required": [],
    },
)


BUDGET_REMAINING = ToolSpec(
    name="budget_remaining",
    description=(
        "Return remaining USD and wall-clock budget for the current "
        "campaign. Use to size budget_usd_cap and per_attempt_budget_usd "
        "in the plan."
    ),
    parameters={
        "type": "object",
        "properties": {},
        "required": [],
    },
)


COVERAGE_FOR_CATEGORY = ToolSpec(
    name="coverage_for_category",
    description=(
        "Drill down: per-technique coverage for ONE category. Use when "
        "you've identified a category worth prioritizing and want to pick "
        "the specific technique with the lowest saturation or most stale "
        "last_tested_at. Cheaper on the context window than dragging the "
        "full list_coverage matrix into every turn."
    ),
    parameters={
        "type": "object",
        "properties": {
            "category": {
                "type": "string",
                "description": "Category name (must come from list_attack_categories).",
            },
            "lookback_days": {
                "type": "integer",
                "minimum": 1,
                "default": 30,
            },
        },
        "required": ["category"],
    },
)


RECENT_CAMPAIGNS = ToolSpec(
    name="recent_campaigns",
    description=(
        "Return the most recent N campaigns for this project: each "
        "campaign's plan summary (the (category, technique) pairs that "
        "were tried), aggregate verdict mix, and USD consumed. The "
        "cross-campaign learning channel — use it to avoid re-trying a "
        "saturated strategy or to confirm whether a past breach has "
        "stayed reproducible."
    ),
    parameters={
        "type": "object",
        "properties": {
            "n": {
                "type": "integer",
                "minimum": 1,
                "maximum": 20,
                "default": 5,
            },
        },
        "required": [],
    },
)


SUBMIT_PLAN = ToolSpec(
    name="submit_plan",
    description=(
        "Terminal. Commit the candidate campaign plan. The platform "
        "validates: every (category, technique) pair must come from "
        "list_attack_categories; the sum of per_attempt_budget_usd must "
        "be <= budget_usd_cap; budget_usd_cap must be <= the operator's "
        "budget; rationale must be substantive (>=30 chars, name a "
        "specific category, cite a tool output). On validation failure "
        "this tool returns {error, hint} — read the error, fix the "
        "plan, and call submit_plan again. The conversation ends only "
        "on a SUCCESSFUL submit."
    ),
    parameters=SubmitPlanArgs.model_json_schema(),
)


ALL_TOOLS: tuple[ToolSpec, ...] = (
    LIST_ATTACK_CATEGORIES,
    LIST_COVERAGE,
    LIST_OPEN_FINDINGS,
    LIST_RECENT_REGRESSIONS,
    BUDGET_REMAINING,
    COVERAGE_FOR_CATEGORY,
    RECENT_CAMPAIGNS,
    SUBMIT_PLAN,
)


TOOL_NAMES: frozenset[str] = frozenset({t.name for t in ALL_TOOLS})


async def dispatch(
    ctx: OrchestratorContext,
    *,
    name: str,
    args: dict[str, Any],
    llm: LLMClient,
) -> ToolOutcome:
    """Run one tool. Unknown names return an error payload the next
    LLM turn can read and recover from. Increments ``tool_call_count``
    so the agent's tool-call cap fires when the model loops."""
    _ = llm  # signature mirrors red_team.dispatch; orchestrator tools don't recurse into the LLM
    ctx.tool_call_count += 1
    args = args or {}
    if name == LIST_COVERAGE.name:
        return await run_list_coverage(ctx, args=args)
    if name == LIST_OPEN_FINDINGS.name:
        return await run_list_open_findings(ctx, args=args)
    if name == LIST_RECENT_REGRESSIONS.name:
        return await run_list_recent_regressions(ctx, args=args)
    if name == LIST_ATTACK_CATEGORIES.name:
        return await run_list_attack_categories(ctx, args=args)
    if name == BUDGET_REMAINING.name:
        return await run_budget_remaining(ctx, args=args)
    if name == COVERAGE_FOR_CATEGORY.name:
        return await run_coverage_for_category(ctx, args=args)
    if name == RECENT_CAMPAIGNS.name:
        return await run_recent_campaigns(ctx, args=args)
    if name == SUBMIT_PLAN.name:
        return await run_submit_plan(ctx, args=args)
    payload = {
        "error": f"unknown tool {name!r}; valid: {sorted(TOOL_NAMES)}",
    }
    ctx.record_transcript(tool=name, args=_truncate_args(args), output=payload)
    return ToolOutcome(payload=payload)


# ---------------------------------------------------------------------------
# Back-compat: descriptor list derived from ALL_TOOLS.
# Kept so external consumers (audit panels, doc tooling) that read the
# tool surface from this module continue to work. New code should
# advertise ALL_TOOLS to the LLM, not TOOL_DESCRIPTORS.
# ---------------------------------------------------------------------------


TOOL_DESCRIPTORS: list[dict[str, Any]] = [
    {
        "name": t.name,
        "description": t.description,
        "parameters": t.parameters,
    }
    for t in ALL_TOOLS
]


__all__ = [
    "ALL_TOOLS",
    "BUDGET_REMAINING",
    "COVERAGE_FOR_CATEGORY",
    "LIST_ATTACK_CATEGORIES",
    "LIST_COVERAGE",
    "LIST_OPEN_FINDINGS",
    "LIST_RECENT_REGRESSIONS",
    "RECENT_CAMPAIGNS",
    "SUBMIT_PLAN",
    "TOOL_DESCRIPTORS",
    "TOOL_NAMES",
    "AgentTurnCost",
    "AttackCategoriesCatalog",
    "AttackCategory",
    "BudgetRemaining",
    "CoverageDrillDown",
    "CoverageDrillDownRow",
    "CoverageReport",
    "CoverageRow",
    "OpenFinding",
    "OpenFindings",
    "OrchestratorContext",
    "PlanAttemptArg",
    "RecentCampaign",
    "RecentCampaignPlanAttempt",
    "RecentCampaignsReport",
    "RecentRegressions",
    "RegressionFinding",
    "SubmitPlanArgs",
    "ToolOutcome",
    "budget_remaining",
    "coverage_for_category",
    "dispatch",
    "list_attack_categories",
    "list_coverage",
    "list_open_findings",
    "list_recent_regressions",
    "recent_campaigns",
    "run_budget_remaining",
    "run_coverage_for_category",
    "run_list_attack_categories",
    "run_list_coverage",
    "run_list_open_findings",
    "run_list_recent_regressions",
    "run_recent_campaigns",
    "run_submit_plan",
]
