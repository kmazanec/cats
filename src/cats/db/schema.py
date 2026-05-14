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
    # R2 — target authentication for the PHP proxy on OpenEMR (kind=copilot_proxy)
    # or direct internal access for local docker (kind=copilot_internal).
    Column("target_kind", String(32), nullable=False, server_default="copilot_proxy"),
    Column("target_username", String(200), nullable=True),
    Column("target_password_encrypted", Text, nullable=True),
    # R8 followup — per-project HMAC secret for the deploy webhook. Fernet
    # encrypted at rest. NULL means the project has not opted into
    # webhook-driven sweeps; the route returns 503 in that state.
    Column("deploy_webhook_secret_encrypted", Text, nullable=True),
    _ts(),
    CheckConstraint("env IN ('local','staging','prod')", name="ck_projects_env"),
    CheckConstraint(
        "target_kind IN ('copilot_proxy','copilot_internal')",
        name="ck_projects_target_kind",
    ),
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
    # R2 — which agent role's LLM call produced this row, for per-role cost
    # breakdown ('redteam_injection', 'judge', 'documentation', etc.).
    Column("agent_role", String(64), nullable=False, server_default=""),
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
    ),
    # R2: attach to a specific Finding so multiple findings in one run each
    # get their own report.
    Column(
        "finding_id",
        UUID(as_uuid=True),
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=True,
    ),
    Column("title", String(300), nullable=False),
    Column("body_markdown", Text, nullable=False),
    Column("requires_approval", Boolean, nullable=False, server_default=text("false")),
    Column("approved_by", String(120), nullable=True),
    Column("approved_at", DateTime(timezone=True), nullable=True),
    _ts(),
    Index("ix_vulnerability_reports_finding_id", "finding_id"),
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
    UniqueConstraint("source_finding_id", name="uq_regression_cases_source_finding"),
)

# R8 — regression sweep + per-case runs. One sweep per webhook firing
# (or manual CLI invocation); one regression_runs row per case it touches.
regression_sweeps = Table(
    "regression_sweeps",
    metadata,
    _uuid_pk(),
    Column("project_id", UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False),
    # Free-form identifier of the Co-Pilot version that triggered the sweep
    # (commit SHA, image tag, "manual"). Surfaces in the UI so an operator
    # can correlate a regression to a specific deploy.
    Column("version_tag", String(120), nullable=False, server_default=""),
    # 'deploy_webhook' | 'manual_cli' | 'scheduled'. Audit-trail signal,
    # not load-bearing in the runner.
    Column("triggered_by", String(32), nullable=False, server_default="manual_cli"),
    Column("status", String(20), nullable=False, server_default="running"),
    Column("num_cases", Integer, nullable=False, server_default=text("0")),
    Column("num_fixed", Integer, nullable=False, server_default=text("0")),
    Column("num_regressed", Integer, nullable=False, server_default=text("0")),
    Column("num_needs_review", Integer, nullable=False, server_default=text("0")),
    Column("num_errored", Integer, nullable=False, server_default=text("0")),
    Column(
        "started_at",
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        server_default=text("now()"),
    ),
    Column("finished_at", DateTime(timezone=True), nullable=True),
    _ts(),
    CheckConstraint(
        "status IN ('running','completed','failed')",
        name="ck_regression_sweeps_status",
    ),
)

regression_runs = Table(
    "regression_runs",
    metadata,
    _uuid_pk(),
    Column(
        "regression_case_id",
        UUID(as_uuid=True),
        ForeignKey("regression_cases.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column(
        "sweep_id",
        UUID(as_uuid=True),
        ForeignKey("regression_sweeps.id", ondelete="CASCADE"),
        nullable=True,
    ),
    # Overall verdict: fixed_held | regressed | needs_review | error.
    Column("status", String(20), nullable=False),
    # Per-gate result. NULL means the gate didn't run (e.g. earlier gate
    # produced 'error', or fingerprint exemplar was empty so the gate is
    # explicitly 'unclear' — encoded as null + status=needs_review).
    Column("gate_deterministic", Boolean, nullable=True),
    Column("gate_judge", Boolean, nullable=True),
    Column("gate_fingerprint", Boolean, nullable=True),
    Column("reason", Text, nullable=False, server_default=""),
    # The Co-Pilot response we evaluated, trimmed at ingest for storage
    # sanity. Full SSE payloads can run to megabytes; we keep a 32k-char
    # head so the UI can show the response and the Judge can be re-run.
    Column("response_text", Text, nullable=False, server_default=""),
    Column("trace_id", String(120), nullable=False, server_default=""),
    Column(
        "started_at",
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        server_default=text("now()"),
    ),
    Column("finished_at", DateTime(timezone=True), nullable=True),
    Column("triggered_by", String(32), nullable=False, server_default="manual_cli"),
    _ts(),
    CheckConstraint(
        "status IN ('fixed_held','regressed','needs_review','error')",
        name="ck_regression_runs_status",
    ),
    Index("ix_regression_runs_case_id", "regression_case_id"),
    Index("ix_regression_runs_sweep_id", "sweep_id"),
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


# ---------------------------------------------------------------------------
# R4 — agent message bus + per-agent durable state
# ---------------------------------------------------------------------------

agent_messages = Table(
    "agent_messages",
    metadata,
    _uuid_pk(),
    Column("from_agent", String(32), nullable=False),
    Column("to_agent", String(32), nullable=False),
    Column("kind", String(64), nullable=False),
    Column("payload_json", JSONB, nullable=False, server_default=text("'{}'::jsonb")),
    Column("trace_id", String(120), nullable=False, server_default=""),
    Column("campaign_id", UUID(as_uuid=True), nullable=True),
    Column("attack_id", UUID(as_uuid=True), nullable=True),
    Column("idempotency_key", Text, nullable=False),
    Column(
        "created_at",
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        server_default=text("now()"),
    ),
    Column(
        "visible_after",
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        server_default=text("now()"),
    ),
    Column("consumed_at", DateTime(timezone=True), nullable=True),
    Column("consumed_by", String(200), nullable=True),
    Column("attempts", Integer, nullable=False, server_default="0"),
    Column("last_error", Text, nullable=True),
    CheckConstraint(
        "from_agent IN ('trigger','orchestrator','red_team','judge',"
        "'documentation','operator','system')",
        name="ck_agent_messages_from",
    ),
    CheckConstraint(
        "to_agent IN ('orchestrator','red_team','judge','documentation','operator','system')",
        name="ck_agent_messages_to",
    ),
    Index(
        "uq_agent_messages_idempotency_key",
        "idempotency_key",
        unique=True,
    ),
    Index(
        "ix_agent_messages_inbox",
        "to_agent",
        "visible_after",
        postgresql_where=text("consumed_at IS NULL"),
    ),
    Index("ix_agent_messages_campaign_id", "campaign_id"),
    Index("ix_agent_messages_attack_id", "attack_id"),
)

agent_dead_letters = Table(
    "agent_dead_letters",
    metadata,
    _uuid_pk(),
    Column(
        "message_id",
        UUID(as_uuid=True),
        ForeignKey("agent_messages.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column("to_agent", String(32), nullable=False),
    Column("kind", String(64), nullable=False),
    Column("last_error", Text, nullable=False, server_default=""),
    Column(
        "dead_lettered_at",
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        server_default=text("now()"),
    ),
    Column("requeued_at", DateTime(timezone=True), nullable=True),
    Column("requeued_by", String(200), nullable=True),
    Index(
        "ix_agent_dead_letters_to_agent",
        "to_agent",
        postgresql_where=text("requeued_at IS NULL"),
    ),
)

red_team_attempts = Table(
    "red_team_attempts",
    metadata,
    Column(
        "attack_id",
        UUID(as_uuid=True),
        ForeignKey("attacks.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column("iteration", Integer, nullable=False, server_default="0"),
    Column("max_iterations", Integer, nullable=False, server_default="2"),
    Column("status", String(16), nullable=False, server_default="active"),
    Column(
        "updated_at",
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        server_default=text("now()"),
    ),
    CheckConstraint(
        "status IN ('active','exhausted','complete','failed')",
        name="ck_red_team_attempts_status",
    ),
)

documentation_drafts = Table(
    "documentation_drafts",
    metadata,
    Column(
        "finding_id",
        UUID(as_uuid=True),
        ForeignKey("findings.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column("status", String(16), nullable=False, server_default="draft"),
    Column(
        "awaiting_approval",
        Boolean,
        nullable=False,
        server_default=text("false"),
    ),
    Column(
        "updated_at",
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        server_default=text("now()"),
    ),
    CheckConstraint(
        "status IN ('draft','published','rejected')",
        name="ck_documentation_drafts_status",
    ),
)

worker_heartbeats = Table(
    "worker_heartbeats",
    metadata,
    Column("worker_name", String(64), nullable=False, primary_key=True),
    Column("host_pid", String(200), nullable=False, primary_key=True),
    Column(
        "last_beat_at",
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        server_default=text("now()"),
    ),
    Index("ix_worker_heartbeats_worker_name", "worker_name", "last_beat_at"),
)

campaign_plans = Table(
    "campaign_plans",
    metadata,
    _uuid_pk(),
    Column(
        "campaign_id",
        UUID(as_uuid=True),
        ForeignKey("campaigns.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column("status", String(20), nullable=False, server_default="proposed"),
    Column("proposed_plan", JSONB, nullable=False, server_default=text("'{}'::jsonb")),
    Column("approved_plan", JSONB, nullable=True),
    Column("tool_transcript", JSONB, nullable=False, server_default=text("'[]'::jsonb")),
    Column("rationale", Text, nullable=False, server_default=""),
    Column("approver_user_id", UUID(as_uuid=True), nullable=True),
    Column("approved_at", DateTime(timezone=True), nullable=True),
    Column("diff_summary", JSONB, nullable=False, server_default=text("'{}'::jsonb")),
    Column(
        "created_at",
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        server_default=text("now()"),
    ),
    CheckConstraint(
        "status IN ('proposed','approved','edited','rejected','dispatched','failed')",
        name="ck_campaign_plans_status",
    ),
    Index("ix_campaign_plans_campaign_id", "campaign_id"),
)


campaign_reports = Table(
    "campaign_reports",
    metadata,
    _uuid_pk(),
    Column(
        "campaign_id",
        UUID(as_uuid=True),
        ForeignKey("campaigns.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    ),
    Column("status", String(20), nullable=False, server_default="pending"),
    Column("body_markdown", Text, nullable=False, server_default=""),
    # ``artifacts`` carries the list of visual artifacts the report
    # generator rendered: ``[{name, kind, path, alt}, ...]`` where path
    # is relative to the on-disk reports directory. Stored as JSON so
    # callers can re-render the page without re-running the LLM.
    Column("artifacts", JSONB, nullable=False, server_default=text("'[]'::jsonb")),
    Column("model", String(120), nullable=False, server_default=""),
    Column("tokens_in", Integer, nullable=False, server_default=text("0")),
    Column("tokens_out", Integer, nullable=False, server_default=text("0")),
    Column("usd_estimate", Float, nullable=False, server_default=text("0")),
    Column("tool_transcript", JSONB, nullable=False, server_default=text("'[]'::jsonb")),
    Column("generated_at", DateTime(timezone=True), nullable=True),
    _ts(),
    CheckConstraint(
        "status IN ('pending','generating','completed','failed')",
        name="ck_campaign_reports_status",
    ),
    Index("ix_campaign_reports_campaign_id", "campaign_id"),
)


__all__ = [
    "agent_dead_letters",
    "agent_messages",
    "attack_executions",
    "attacks",
    "audit_log",
    "campaign_plans",
    "campaign_reports",
    "campaigns",
    "documentation_drafts",
    "finding_executions",
    "findings",
    "judge_verdicts",
    "metadata",
    "project_versions",
    "projects",
    "red_team_attempts",
    "regression_cases",
    "regression_runs",
    "regression_sweeps",
    "rubric_versions",
    "runs",
    "source_access_log",
    "users",
    "vulnerability_reports",
    "worker_heartbeats",
]
