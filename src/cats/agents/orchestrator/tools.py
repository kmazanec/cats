"""Orchestrator tool surface — the typed read-only window the LLM planner
uses to reason about platform state.

Five tools, each a pure async function with a Pydantic input + output
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

Design rules (do not break without explicit user direction):

- Every function is safe on an empty DB. Empty inputs return empty
  collections / zero counts, never raise.
- Functions accept either an ``AsyncSession`` (for tests / when a
  caller already holds one) or fall back to opening their own via
  :func:`cats.db.engine.session_scope`.
- No LLM calls happen here. These tools are pure DB reads + an in-code
  taxonomy walk.
- No imports from agent workers. The point of the tool surface is that
  the strategic layer reads observability, not agent state.

The :data:`TOOL_DESCRIPTORS` constant at the bottom of this module is the
JSON-schema-style descriptor list the LLM tool-call adapter serializes
into the Orchestrator prompt.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

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
from cats.categories import REGISTERED_CATEGORIES
from cats.categories import taxonomy as taxonomy_lookup
from cats.db.engine import session_scope
from cats.db.schema import (
    attack_executions,
    attacks,
    campaigns,
    findings,
    judge_verdicts,
    runs,
)

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
# Tool descriptor export (consumed by the LLM tool-call adapter)
# ---------------------------------------------------------------------------


TOOL_DESCRIPTORS: list[dict[str, Any]] = [
    {
        "name": "list_coverage",
        "description": (
            "Return per-(category, technique) counts of attacks fired against "
            "this project in the last lookback_days days, plus the current "
            "pass/fail/partial verdict mix and last-tested timestamp."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "project_id": {
                    "type": "string",
                    "format": "uuid",
                    "description": "Target project UUID.",
                },
                "lookback_days": {
                    "type": "integer",
                    "minimum": 1,
                    "default": 30,
                    "description": "Window of attack history to include.",
                },
            },
            "required": ["project_id"],
        },
    },
    {
        "name": "list_open_findings",
        "description": (
            "Return outstanding (status='open') findings for the project "
            "filtered to severity >= min_severity. Includes signature, age, "
            "and category so the Orchestrator can re-prioritise."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "project_id": {
                    "type": "string",
                    "format": "uuid",
                },
                "min_severity": {
                    "type": "string",
                    "enum": ["info", "low", "medium", "high", "critical"],
                    "default": "info",
                },
            },
            "required": ["project_id"],
        },
    },
    {
        "name": "list_recent_regressions",
        "description": (
            "Return findings currently marked 'regressed' whose updated_at "
            "is within since_days. Best-effort approximation of "
            "'regressed since last deploy' until a status-transition log lands."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "project_id": {
                    "type": "string",
                    "format": "uuid",
                },
                "since_days": {
                    "type": "integer",
                    "minimum": 1,
                    "default": 14,
                },
            },
            "required": ["project_id"],
        },
    },
    {
        "name": "list_attack_categories",
        "description": (
            "Return the catalogued attack-surface map: each registered "
            "category, its default severity, ATLAS / OWASP labels, and the "
            "techniques the platform currently knows how to run for it."
        ),
        "parameters": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "budget_remaining",
        "description": (
            "Return remaining USD and wall-clock budget for a given "
            "campaign. When campaign_id is omitted, return project-level "
            "defaults (no per-project budget table yet)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "project_id": {
                    "type": "string",
                    "format": "uuid",
                },
                "campaign_id": {
                    "type": ["string", "null"],
                    "format": "uuid",
                    "default": None,
                },
            },
            "required": ["project_id"],
        },
    },
]


__all__ = [
    "TOOL_DESCRIPTORS",
    "AttackCategoriesCatalog",
    "AttackCategory",
    "BudgetRemaining",
    "CoverageReport",
    "CoverageRow",
    "OpenFinding",
    "OpenFindings",
    "RecentRegressions",
    "RegressionFinding",
    "budget_remaining",
    "list_attack_categories",
    "list_coverage",
    "list_open_findings",
    "list_recent_regressions",
]
