"""R8 regression verification — sweeps + runs.

Adds ``regression_sweeps`` and ``regression_runs`` for the triple-gate
fix-held verification harness (ARCHITECTURE.md §6.4). One sweep per
deploy webhook firing (or manual CLI run); one ``regression_runs`` row
per RegressionCase the sweep touches. Also adds a unique constraint on
``regression_cases.source_finding_id`` so the auto-promotion hook is
idempotent — a Finding maps to exactly one RegressionCase.

Revision ID: 20260513_0007
Revises: 20260513_0006
Create Date: 2026-05-13
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260513_0007"
down_revision: str | None = "20260513_0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_unique_constraint(
        "uq_regression_cases_source_finding",
        "regression_cases",
        ["source_finding_id"],
    )

    op.create_table(
        "regression_sweeps",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "project_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("projects.id"),
            nullable=False,
        ),
        sa.Column("version_tag", sa.String(120), nullable=False, server_default=""),
        sa.Column("triggered_by", sa.String(32), nullable=False, server_default="manual_cli"),
        sa.Column("status", sa.String(20), nullable=False, server_default="running"),
        sa.Column("num_cases", sa.Integer, nullable=False, server_default=sa.text("0")),
        sa.Column("num_fixed", sa.Integer, nullable=False, server_default=sa.text("0")),
        sa.Column("num_regressed", sa.Integer, nullable=False, server_default=sa.text("0")),
        sa.Column("num_needs_review", sa.Integer, nullable=False, server_default=sa.text("0")),
        sa.Column("num_errored", sa.Integer, nullable=False, server_default=sa.text("0")),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint(
            "status IN ('running','completed','failed')",
            name="ck_regression_sweeps_status",
        ),
    )

    op.create_table(
        "regression_runs",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "regression_case_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("regression_cases.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "sweep_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("regression_sweeps.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("gate_deterministic", sa.Boolean, nullable=True),
        sa.Column("gate_judge", sa.Boolean, nullable=True),
        sa.Column("gate_fingerprint", sa.Boolean, nullable=True),
        sa.Column("reason", sa.Text, nullable=False, server_default=""),
        sa.Column("response_text", sa.Text, nullable=False, server_default=""),
        sa.Column("trace_id", sa.String(120), nullable=False, server_default=""),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("triggered_by", sa.String(32), nullable=False, server_default="manual_cli"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint(
            "status IN ('fixed_held','regressed','needs_review','error')",
            name="ck_regression_runs_status",
        ),
    )
    op.create_index("ix_regression_runs_case_id", "regression_runs", ["regression_case_id"])
    op.create_index("ix_regression_runs_sweep_id", "regression_runs", ["sweep_id"])


def downgrade() -> None:
    op.drop_index("ix_regression_runs_sweep_id", table_name="regression_runs")
    op.drop_index("ix_regression_runs_case_id", table_name="regression_runs")
    op.drop_table("regression_runs")
    op.drop_table("regression_sweeps")
    op.drop_constraint(
        "uq_regression_cases_source_finding",
        "regression_cases",
        type_="unique",
    )
