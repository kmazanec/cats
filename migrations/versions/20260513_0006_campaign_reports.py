"""Campaign-level report rollup.

Adds ``campaign_reports``: one row per campaign carrying the
Documentation Agent's end-of-campaign rollup — narrative markdown,
referenced visual artifacts (SVG paths), and the per-call cost
accounting. ``UNIQUE(campaign_id)`` enforces one report per campaign;
re-runs UPDATE rather than INSERT so the operator always sees the
latest narrative.

Revision ID: 20260513_0006
Revises: 20260512_0005
Create Date: 2026-05-13
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260513_0006"
down_revision: str | None = "20260512_0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "campaign_reports",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "campaign_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("campaigns.id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("body_markdown", sa.Text, nullable=False, server_default=""),
        sa.Column(
            "artifacts",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("model", sa.String(120), nullable=False, server_default=""),
        sa.Column("tokens_in", sa.Integer, nullable=False, server_default=sa.text("0")),
        sa.Column("tokens_out", sa.Integer, nullable=False, server_default=sa.text("0")),
        sa.Column("usd_estimate", sa.Float, nullable=False, server_default=sa.text("0")),
        sa.Column(
            "tool_transcript",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint(
            "status IN ('pending','generating','completed','failed')",
            name="ck_campaign_reports_status",
        ),
    )
    op.create_index(
        "ix_campaign_reports_campaign_id",
        "campaign_reports",
        ["campaign_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_campaign_reports_campaign_id", table_name="campaign_reports")
    op.drop_table("campaign_reports")
