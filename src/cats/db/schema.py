"""Core SQL schema. Tables defined with SQLAlchemy Core (not declarative ORM)
because most reads/writes go through hand-written async queries — we want a
thin layer, not an object graph.

Append-only enforcement on audit_log is applied via a Postgres trigger in a
follow-up migration (see migrations/versions/*_audit_log_append_only.py).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID

metadata = MetaData()


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _ts() -> Column[datetime]:
    return Column("created_at", DateTime(timezone=True), nullable=False, default=_utcnow)


def _uuid_pk() -> Column[Any]:
    return Column(
        "id", UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )


# ---------------------------------------------------------------------------
# Users (R1 — role-gated dashboard)
# ---------------------------------------------------------------------------

users = Table(
    "users",
    metadata,
    _uuid_pk(),
    Column("email", String(320), nullable=False, unique=True),
    Column("password_hash", Text, nullable=False),
    Column("role", String(32), nullable=False, server_default="viewer"),
    Column("is_active", Boolean, nullable=False, server_default=text("true")),
    _ts(),
    CheckConstraint(
        "role IN ('viewer','operator','senior_operator','admin')",
        name="ck_users_role",
    ),
)


# ---------------------------------------------------------------------------
# Projects + versions
# ---------------------------------------------------------------------------

projects = Table(
    "projects",
    metadata,
    _uuid_pk(),
    Column("name", String(200), nullable=False, unique=True),
    Column("description", Text, nullable=False, server_default=""),
    Column("base_url", Text, nullable=False),
    Column("env", String(16), nullable=False, server_default="local"),
    Column("api_contract", JSONB, nullable=False, server_default=text("'{}'::jsonb")),
    Column("auth_material_encrypted", Text, nullable=True),
    Column("allow_run_against", Boolean, nullable=False, server_default=text("false")),
    _ts(),
    CheckConstraint("env IN ('local','staging','prod')", name="ck_projects_env"),
)

project_versions = Table(
    "project_versions",
    metadata,
    _uuid_pk(),
    Column(
        "project_id",
        UUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column("git_sha", String(64), nullable=True),
    Column("label", String(200), nullable=False, server_default=""),
    Column("deployed_at", DateTime(timezone=True), nullable=False, default=_utcnow),
    _ts(),
    Index("ix_project_versions_project_id", "project_id"),
)


# ---------------------------------------------------------------------------
# Campaigns + runs
# ---------------------------------------------------------------------------

campaigns = Table(
    "campaigns",
    metadata,
    _uuid_pk(),
    Column("name", String(200), nullable=False),
    Column("project_id", UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False),
    Column("mode", String(16), nullable=False, server_default="blackhat"),
    Column("trigger", String(16), nullable=False, server_default="on_demand"),
    Column("category_weights", JSONB, nullable=False, server_default=text("'{}'::jsonb")),
    Column("budget", JSONB, nullable=False, server_default=text("'{}'::jsonb")),
    _ts(),
    CheckConstraint("mode IN ('blackhat','whitehat','both')", name="ck_campaigns_mode"),
    CheckConstraint(
        "trigger IN ('on_demand','nightly','deploy')",
        name="ck_campaigns_trigger",
    ),
)

runs = Table(
    "runs",
    metadata,
    _uuid_pk(),
    Column("campaign_id", UUID(as_uuid=True), ForeignKey("campaigns.id"), nullable=False),
    Column(
        "project_version_id",
        UUID(as_uuid=True),
        ForeignKey("project_versions.id"),
        nullable=False,
    ),
    Column("status", String(16), nullable=False, server_default="pending"),
    Column("started_at", DateTime(timezone=True), nullable=True),
    Column("ended_at", DateTime(timezone=True), nullable=True),
    Column("budget_consumed_usd", Float, nullable=False, server_default="0"),
    Column("attacks_fired", Integer, nullable=False, server_default="0"),
    _ts(),
    Index("ix_runs_campaign_id", "campaign_id"),
    CheckConstraint(
        "status IN ('pending','running','completed','failed','halted')",
        name="ck_runs_status",
    ),
)


# ---------------------------------------------------------------------------
# Attacks + executions (the reusable-vs-firing split)
# ---------------------------------------------------------------------------

attacks = Table(
    "attacks",
    metadata,
    _uuid_pk(),
    Column("category", String(64), nullable=False),
    Column("title", String(300), nullable=False),
    Column("description", Text, nullable=False, server_default=""),
    Column("payload", JSONB, nullable=False, server_default=text("'{}'::jsonb")),
    Column("signature", String(64), nullable=False),
    Column("parent_attack_id", UUID(as_uuid=True), ForeignKey("attacks.id"), nullable=True),
    Column("source", String(16), nullable=False, server_default="seed"),
    Column("created_in_run_id", UUID(as_uuid=True), ForeignKey("runs.id"), nullable=True),
    _ts(),
    Index("ix_attacks_category", "category"),
    Index("ix_attacks_signature", "signature"),
    CheckConstraint(
        "source IN ('seed','red_team','mutator','regression')",
        name="ck_attacks_source",
    ),
)

rubric_versions = Table(
    "rubric_versions",
    metadata,
    _uuid_pk(),
    Column("category", String(64), nullable=False),
    Column("version", Integer, nullable=False),
    Column("prompt_text", Text, nullable=False),
    Column("locked_at", DateTime(timezone=True), nullable=False, default=_utcnow),
    _ts(),
    UniqueConstraint("category", "version", name="uq_rubric_versions_category_version"),
)

judge_verdicts = Table(
    "judge_verdicts",
    metadata,
    _uuid_pk(),
    Column("verdict", String(16), nullable=False),
    Column("mode", String(16), nullable=False, server_default="blackhat"),
    Column("exploitability", String(16), nullable=False, server_default="confirmed"),
    Column(
        "rubric_version_id",
        UUID(as_uuid=True),
        ForeignKey("rubric_versions.id"),
        nullable=True,
    ),
    Column("judge_model", String(120), nullable=False, server_default=""),
    Column("is_deterministic", Boolean, nullable=False, server_default=text("false")),
    Column("evidence", JSONB, nullable=False, server_default=text("'{}'::jsonb")),
    Column("rationale", Text, nullable=False, server_default=""),
    _ts(),
    CheckConstraint(
        "verdict IN ('pass','fail','partial','error')",
        name="ck_judge_verdicts_verdict",
    ),
    CheckConstraint(
        "exploitability IN ('confirmed','plausible','theoretical')",
        name="ck_judge_verdicts_exploit",
    ),
    CheckConstraint("mode IN ('blackhat','whitehat')", name="ck_judge_verdicts_mode"),
)

attack_executions = Table(
    "attack_executions",
    metadata,
    _uuid_pk(),
    Column("run_id", UUID(as_uuid=True), ForeignKey("runs.id"), nullable=False),
    Column("attack_id", UUID(as_uuid=True), ForeignKey("attacks.id"), nullable=False),
    Column(
        "project_version_id",
        UUID(as_uuid=True),
        ForeignKey("project_versions.id"),
        nullable=False,
    ),
    Column("target_response", JSONB, nullable=False, server_default=text("'{}'::jsonb")),
    Column("target_latency_ms", Integer, nullable=True),
    Column("target_status_code", Integer, nullable=True),
    Column(
        "output_filter_verdict",
        String(20),
        nullable=False,
        server_default="safe",
    ),
    Column("output_filter_reason", Text, nullable=False, server_default=""),
    Column(
        "judge_verdict_id",
        UUID(as_uuid=True),
        ForeignKey("judge_verdicts.id"),
        nullable=True,
    ),
    Column("tokens_in", Integer, nullable=False, server_default="0"),
    Column("tokens_out", Integer, nullable=False, server_default="0"),
    Column("model", String(120), nullable=False, server_default=""),
    Column("usd_estimate", Float, nullable=False, server_default="0"),
    Column("langsmith_trace_id", String(120), nullable=True),
    Column("error", Text, nullable=True),
    Column("started_at", DateTime(timezone=True), nullable=True),
    Column("ended_at", DateTime(timezone=True), nullable=True),
    _ts(),
    Index("ix_attack_executions_run_id", "run_id"),
    Index("ix_attack_executions_attack_id", "attack_id"),
    CheckConstraint(
        "output_filter_verdict IN ('safe','attack_payload','dangerous')",
        name="ck_attack_executions_filter",
    ),
)


# ---------------------------------------------------------------------------
# Findings + reports + regression
# ---------------------------------------------------------------------------

findings = Table(
    "findings",
    metadata,
    _uuid_pk(),
    Column("run_id", UUID(as_uuid=True), ForeignKey("runs.id"), nullable=False),
    Column("category", String(64), nullable=False),
    Column("signature", String(64), nullable=False),
    Column("severity", String(16), nullable=False, server_default="medium"),
    Column("status", String(16), nullable=False, server_default="open"),
    Column("title", String(300), nullable=False),
    Column("summary", Text, nullable=False, server_default=""),
    Column("atlas_technique_id", String(64), nullable=True),
    Column("owasp_llm_id", String(32), nullable=True),
    _ts(),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=_utcnow),
    UniqueConstraint("run_id", "category", "signature", name="uq_findings_run_cat_sig"),
    CheckConstraint(
        "severity IN ('info','low','medium','high','critical')",
        name="ck_findings_severity",
    ),
    CheckConstraint(
        "status IN ('open','triaged','fixed','regressed','wont_fix')",
        name="ck_findings_status",
    ),
)

finding_executions = Table(
    "finding_executions",
    metadata,
    Column(
        "finding_id",
        UUID(as_uuid=True),
        ForeignKey("findings.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "attack_execution_id",
        UUID(as_uuid=True),
        ForeignKey("attack_executions.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    _ts(),
)

vulnerability_reports = Table(
    "vulnerability_reports",
    metadata,
    _uuid_pk(),
    Column(
        "run_id",
        UUID(as_uuid=True),
        ForeignKey("runs.id"),
        nullable=False,
        unique=True,
    ),
    Column("title", String(300), nullable=False),
    Column("body_markdown", Text, nullable=False),
    Column("requires_approval", Boolean, nullable=False, server_default=text("false")),
    Column("approved_by", String(120), nullable=True),
    Column("approved_at", DateTime(timezone=True), nullable=True),
    _ts(),
)

regression_cases = Table(
    "regression_cases",
    metadata,
    _uuid_pk(),
    Column(
        "source_finding_id",
        UUID(as_uuid=True),
        ForeignKey("findings.id"),
        nullable=False,
    ),
    Column(
        "canonical_attack_ids",
        JSON,
        nullable=False,
        server_default=text("'[]'::json"),
    ),
    Column("refusal_exemplar_text", Text, nullable=False, server_default=""),
    Column("refusal_exemplar_embedding", JSON, nullable=True),
    Column(
        "locked_rubric_version_id",
        UUID(as_uuid=True),
        ForeignKey("rubric_versions.id"),
        nullable=True,
    ),
    _ts(),
)


# ---------------------------------------------------------------------------
# Audit + source-access logs
# ---------------------------------------------------------------------------

audit_log = Table(
    "audit_log",
    metadata,
    _uuid_pk(),
    Column("actor", String(200), nullable=False),
    Column("action", String(200), nullable=False),
    Column("target_kind", String(64), nullable=False),
    Column("target_id", UUID(as_uuid=True), nullable=True),
    Column("payload", JSONB, nullable=False, server_default=text("'{}'::jsonb")),
    Column("trace_id", String(120), nullable=True),
    Column(
        "at",
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        server_default=text("now()"),
    ),
)

source_access_log = Table(
    "source_access_log",
    metadata,
    _uuid_pk(),
    Column("specialist", String(64), nullable=False),
    Column("campaign_id", UUID(as_uuid=True), ForeignKey("campaigns.id"), nullable=True),
    Column("run_id", UUID(as_uuid=True), ForeignKey("runs.id"), nullable=True),
    Column("path", Text, nullable=False),
    Column("tool", String(64), nullable=False),
    Column("payload", JSONB, nullable=False, server_default=text("'{}'::jsonb")),
    Column(
        "at",
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        server_default=text("now()"),
    ),
)


__all__ = [
    "attack_executions",
    "attacks",
    "audit_log",
    "campaigns",
    "finding_executions",
    "findings",
    "judge_verdicts",
    "metadata",
    "project_versions",
    "projects",
    "regression_cases",
    "rubric_versions",
    "runs",
    "source_access_log",
    "users",
    "vulnerability_reports",
]
