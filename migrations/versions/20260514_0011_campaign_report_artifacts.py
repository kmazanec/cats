"""Move documenter SVG artifacts from disk to Postgres.

The Documentation Agent's campaign-report writer previously persisted
its rendered SVG charts under ``settings.campaign_reports_dir``
(default ``/tmp/cats-campaign-reports``) and the api served them
straight off disk. That only worked single-process; in multi-container
deployments the documentation worker's ``/tmp`` is not the api
container's ``/tmp`` and the artifact-serving route 404'd.

This migration adds ``campaign_report_artifacts``: one row per
rendered SVG, keyed by ``(campaign_id, name)``, body stored as text
(SVG is XML). The api now serves these straight out of the db.

Revision ID: 20260514_0011
Revises: 20260513_0010
Create Date: 2026-05-14
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260514_0011"
down_revision: str | None = "20260513_0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "campaign_report_artifacts",
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
        ),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("kind", sa.String(64), nullable=False, server_default=""),
        sa.Column("title", sa.String(300), nullable=False, server_default=""),
        sa.Column("alt", sa.String(300), nullable=False, server_default=""),
        sa.Column(
            "content_type",
            sa.String(80),
            nullable=False,
            server_default="image/svg+xml",
        ),
        sa.Column("body", sa.Text, nullable=False, server_default=""),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.UniqueConstraint(
            "campaign_id",
            "name",
            name="uq_campaign_report_artifacts_campaign_id_name",
        ),
    )
    op.create_index(
        "ix_campaign_report_artifacts_campaign_id",
        "campaign_report_artifacts",
        ["campaign_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_campaign_report_artifacts_campaign_id",
        table_name="campaign_report_artifacts",
    )
    op.drop_table("campaign_report_artifacts")
