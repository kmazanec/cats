"""initial schema + audit_log append-only enforcement.

Revision ID: 20260511_0001
Revises:
Create Date: 2026-05-11

Originally this migration ran `metadata.create_all()`, which created the
*current* schema (including columns and tables added by later revisions).
That worked when nothing came after it, but caused DuplicateTableError /
DuplicateColumnError once 0003 and 0004 landed. Rewritten to create only
the tables that existed at 0001 — `users` (added by 0003) is excluded,
and the R2 columns added by 0004 (projects.target_*, attack_executions.
agent_role, vulnerability_reports.finding_id) are absent from this
revision's column lists. 0003/0004 layer those on as deltas.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision: str = "20260511_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _uuid_pk() -> sa.Column:
    return sa.Column(
        "id",
        UUID(as_uuid=True),
        primary_key=True,
        server_default=sa.text("gen_random_uuid()"),
    )


def _ts() -> sa.Column:
    return sa.Column("created_at", sa.DateTime(timezone=True), nullable=False)


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")  # gen_random_uuid()

    op.create_table(
        "projects",
        _uuid_pk(),
        sa.Column("name", sa.String(200), nullable=False, unique=True),
        sa.Column("description", sa.Text, nullable=False, server_default=""),
        sa.Column("base_url", sa.Text, nullable=False),
        sa.Column("env", sa.String(16), nullable=False, server_default="local"),
        sa.Column("api_contract", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("auth_material_encrypted", sa.Text, nullable=True),
        sa.Column(
            "allow_run_against",
            sa.Boolean,
            nullable=False,
            server_default=sa.text("false"),
        ),
        _ts(),
        sa.CheckConstraint("env IN ('local','staging','prod')", name="ck_projects_env"),
    )

    op.create_table(
        "project_versions",
        _uuid_pk(),
        sa.Column(
            "project_id",
            UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("git_sha", sa.String(64), nullable=True),
        sa.Column("label", sa.String(200), nullable=False, server_default=""),
        sa.Column("deployed_at", sa.DateTime(timezone=True), nullable=False),
        _ts(),
    )
    op.create_index("ix_project_versions_project_id", "project_versions", ["project_id"])

    op.create_table(
        "campaigns",
        _uuid_pk(),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column(
            "project_id",
            UUID(as_uuid=True),
            sa.ForeignKey("projects.id"),
            nullable=False,
        ),
        sa.Column("mode", sa.String(16), nullable=False, server_default="blackhat"),
        sa.Column("trigger", sa.String(16), nullable=False, server_default="on_demand"),
        sa.Column(
            "category_weights",
            JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("budget", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        _ts(),
        sa.CheckConstraint("mode IN ('blackhat','whitehat','both')", name="ck_campaigns_mode"),
        sa.CheckConstraint(
            "trigger IN ('on_demand','nightly','deploy')",
            name="ck_campaigns_trigger",
        ),
    )

    op.create_table(
        "runs",
        _uuid_pk(),
        sa.Column(
            "campaign_id",
            UUID(as_uuid=True),
            sa.ForeignKey("campaigns.id"),
            nullable=False,
        ),
        sa.Column(
            "project_version_id",
            UUID(as_uuid=True),
            sa.ForeignKey("project_versions.id"),
            nullable=False,
        ),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("budget_consumed_usd", sa.Float, nullable=False, server_default="0"),
        sa.Column("attacks_fired", sa.Integer, nullable=False, server_default="0"),
        _ts(),
        sa.CheckConstraint(
            "status IN ('pending','running','completed','failed','halted')",
            name="ck_runs_status",
        ),
    )
    op.create_index("ix_runs_campaign_id", "runs", ["campaign_id"])

    op.create_table(
        "attacks",
        _uuid_pk(),
        sa.Column("category", sa.String(64), nullable=False),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("description", sa.Text, nullable=False, server_default=""),
        sa.Column("payload", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("signature", sa.String(64), nullable=False),
        sa.Column(
            "parent_attack_id",
            UUID(as_uuid=True),
            sa.ForeignKey("attacks.id"),
            nullable=True,
        ),
        sa.Column("source", sa.String(16), nullable=False, server_default="seed"),
        sa.Column(
            "created_in_run_id",
            UUID(as_uuid=True),
            sa.ForeignKey("runs.id"),
            nullable=True,
        ),
        _ts(),
        sa.CheckConstraint(
            "source IN ('seed','red_team','mutator','regression')",
            name="ck_attacks_source",
        ),
    )
    op.create_index("ix_attacks_category", "attacks", ["category"])
    op.create_index("ix_attacks_signature", "attacks", ["signature"])

    op.create_table(
        "rubric_versions",
        _uuid_pk(),
        sa.Column("category", sa.String(64), nullable=False),
        sa.Column("version", sa.Integer, nullable=False),
        sa.Column("prompt_text", sa.Text, nullable=False),
        sa.Column("locked_at", sa.DateTime(timezone=True), nullable=False),
        _ts(),
        sa.UniqueConstraint(
            "category",
            "version",
            name="uq_rubric_versions_category_version",
        ),
    )

    op.create_table(
        "judge_verdicts",
        _uuid_pk(),
        sa.Column("verdict", sa.String(16), nullable=False),
        sa.Column("mode", sa.String(16), nullable=False, server_default="blackhat"),
        sa.Column(
            "exploitability",
            sa.String(16),
            nullable=False,
            server_default="confirmed",
        ),
        sa.Column(
            "rubric_version_id",
            UUID(as_uuid=True),
            sa.ForeignKey("rubric_versions.id"),
            nullable=True,
        ),
        sa.Column("judge_model", sa.String(120), nullable=False, server_default=""),
        sa.Column(
            "is_deterministic",
            sa.Boolean,
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("evidence", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("rationale", sa.Text, nullable=False, server_default=""),
        _ts(),
        sa.CheckConstraint(
            "verdict IN ('pass','fail','partial','error')",
            name="ck_judge_verdicts_verdict",
        ),
        sa.CheckConstraint(
            "exploitability IN ('confirmed','plausible','theoretical')",
            name="ck_judge_verdicts_exploit",
        ),
        sa.CheckConstraint("mode IN ('blackhat','whitehat')", name="ck_judge_verdicts_mode"),
    )

    op.create_table(
        "attack_executions",
        _uuid_pk(),
        sa.Column("run_id", UUID(as_uuid=True), sa.ForeignKey("runs.id"), nullable=False),
        sa.Column(
            "attack_id",
            UUID(as_uuid=True),
            sa.ForeignKey("attacks.id"),
            nullable=False,
        ),
        sa.Column(
            "project_version_id",
            UUID(as_uuid=True),
            sa.ForeignKey("project_versions.id"),
            nullable=False,
        ),
        sa.Column(
            "target_response",
            JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("target_latency_ms", sa.Integer, nullable=True),
        sa.Column("target_status_code", sa.Integer, nullable=True),
        sa.Column(
            "output_filter_verdict",
            sa.String(20),
            nullable=False,
            server_default="safe",
        ),
        sa.Column("output_filter_reason", sa.Text, nullable=False, server_default=""),
        sa.Column(
            "judge_verdict_id",
            UUID(as_uuid=True),
            sa.ForeignKey("judge_verdicts.id"),
            nullable=True,
        ),
        sa.Column("tokens_in", sa.Integer, nullable=False, server_default="0"),
        sa.Column("tokens_out", sa.Integer, nullable=False, server_default="0"),
        sa.Column("model", sa.String(120), nullable=False, server_default=""),
        sa.Column("usd_estimate", sa.Float, nullable=False, server_default="0"),
        sa.Column("langsmith_trace_id", sa.String(120), nullable=True),
        sa.Column("error", sa.Text, nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        _ts(),
        sa.CheckConstraint(
            "output_filter_verdict IN ('safe','attack_payload','dangerous')",
            name="ck_attack_executions_filter",
        ),
    )
    op.create_index("ix_attack_executions_run_id", "attack_executions", ["run_id"])
    op.create_index("ix_attack_executions_attack_id", "attack_executions", ["attack_id"])

    op.create_table(
        "findings",
        _uuid_pk(),
        sa.Column("run_id", UUID(as_uuid=True), sa.ForeignKey("runs.id"), nullable=False),
        sa.Column("category", sa.String(64), nullable=False),
        sa.Column("signature", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False, server_default="medium"),
        sa.Column("status", sa.String(16), nullable=False, server_default="open"),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("summary", sa.Text, nullable=False, server_default=""),
        sa.Column("atlas_technique_id", sa.String(64), nullable=True),
        sa.Column("owasp_llm_id", sa.String(32), nullable=True),
        _ts(),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "run_id",
            "category",
            "signature",
            name="uq_findings_run_cat_sig",
        ),
        sa.CheckConstraint(
            "severity IN ('info','low','medium','high','critical')",
            name="ck_findings_severity",
        ),
        sa.CheckConstraint(
            "status IN ('open','triaged','fixed','regressed','wont_fix')",
            name="ck_findings_status",
        ),
    )

    op.create_table(
        "finding_executions",
        sa.Column(
            "finding_id",
            UUID(as_uuid=True),
            sa.ForeignKey("findings.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "attack_execution_id",
            UUID(as_uuid=True),
            sa.ForeignKey("attack_executions.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        _ts(),
    )

    # 0001's vulnerability_reports has the run_id uniqueness that 0004 will
    # later drop. The constraint name was autogenerated by SQLAlchemy
    # originally; we pin it explicitly here so 0004's drop logic finds it
    # via information_schema regardless of dialect autogen quirks.
    op.create_table(
        "vulnerability_reports",
        _uuid_pk(),
        sa.Column("run_id", UUID(as_uuid=True), sa.ForeignKey("runs.id"), nullable=False),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("body_markdown", sa.Text, nullable=False),
        sa.Column(
            "requires_approval",
            sa.Boolean,
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("approved_by", sa.String(120), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        _ts(),
        sa.UniqueConstraint("run_id", name="uq_vulnerability_reports_run_id"),
    )

    op.create_table(
        "regression_cases",
        _uuid_pk(),
        sa.Column(
            "source_finding_id",
            UUID(as_uuid=True),
            sa.ForeignKey("findings.id"),
            nullable=False,
        ),
        sa.Column(
            "canonical_attack_ids",
            sa.JSON,
            nullable=False,
            server_default=sa.text("'[]'::json"),
        ),
        sa.Column(
            "refusal_exemplar_text",
            sa.Text,
            nullable=False,
            server_default="",
        ),
        sa.Column("refusal_exemplar_embedding", sa.JSON, nullable=True),
        sa.Column(
            "locked_rubric_version_id",
            UUID(as_uuid=True),
            sa.ForeignKey("rubric_versions.id"),
            nullable=True,
        ),
        _ts(),
    )

    op.create_table(
        "audit_log",
        _uuid_pk(),
        sa.Column("actor", sa.String(200), nullable=False),
        sa.Column("action", sa.String(200), nullable=False),
        sa.Column("target_kind", sa.String(64), nullable=False),
        sa.Column("target_id", UUID(as_uuid=True), nullable=True),
        sa.Column("payload", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("trace_id", sa.String(120), nullable=True),
        # 0002 will ALTER this to add server_default now(); leave it off here.
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "source_access_log",
        _uuid_pk(),
        sa.Column("specialist", sa.String(64), nullable=False),
        sa.Column(
            "campaign_id",
            UUID(as_uuid=True),
            sa.ForeignKey("campaigns.id"),
            nullable=True,
        ),
        sa.Column("run_id", UUID(as_uuid=True), sa.ForeignKey("runs.id"), nullable=True),
        sa.Column("path", sa.Text, nullable=False),
        sa.Column("tool", sa.String(64), nullable=False),
        sa.Column("payload", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
    )

    # Append-only audit_log enforcement: revoke UPDATE/DELETE + deny trigger.
    # asyncpg can't prepare multi-statement strings, so each statement is its
    # own op.execute() call.
    op.execute("REVOKE UPDATE, DELETE ON TABLE audit_log FROM PUBLIC")
    op.execute(
        """
        CREATE OR REPLACE FUNCTION audit_log_block_mutation()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'audit_log is append-only';
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute("DROP TRIGGER IF EXISTS audit_log_no_update ON audit_log")
    op.execute(
        """
        CREATE TRIGGER audit_log_no_update
            BEFORE UPDATE ON audit_log
            FOR EACH ROW EXECUTE FUNCTION audit_log_block_mutation()
        """
    )
    op.execute("DROP TRIGGER IF EXISTS audit_log_no_delete ON audit_log")
    op.execute(
        """
        CREATE TRIGGER audit_log_no_delete
            BEFORE DELETE ON audit_log
            FOR EACH ROW EXECUTE FUNCTION audit_log_block_mutation()
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_log_no_update ON audit_log")
    op.execute("DROP TRIGGER IF EXISTS audit_log_no_delete ON audit_log")
    op.execute("DROP FUNCTION IF EXISTS audit_log_block_mutation()")
    # Reverse dependency order
    op.drop_table("source_access_log")
    op.drop_table("audit_log")
    op.drop_table("regression_cases")
    op.drop_table("vulnerability_reports")
    op.drop_table("finding_executions")
    op.drop_table("findings")
    op.drop_table("attack_executions")
    op.drop_table("judge_verdicts")
    op.drop_table("rubric_versions")
    op.drop_table("attacks")
    op.drop_table("runs")
    op.drop_table("campaigns")
    op.drop_table("project_versions")
    op.drop_table("projects")
