"""Briefing kickoff turn — one row per Run.

Every adversarial Run against the Co-Pilot must open with a bare
``default_briefing`` request (the Co-Pilot ignores the user ``question``
on that task — see openemr/agent/src/server/briefingRunner.ts:281). The
kickoff harvests the server-minted ``conversationId`` so subsequent
``follow_up`` turns ride the same conversation and actually have their
``question`` honored.

Kickoff turns are not attack attempts, so they live in a sibling table
rather than ``attack_executions`` — keeps Judge inputs, regression
counters, and turns-fired metrics clean.

Revision ID: 20260514_0012
Revises: 20260514_0011
Create Date: 2026-05-14
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260514_0012"
down_revision: str | None = "20260514_0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "kickoff_turns",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "run_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("runs.id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        sa.Column("conversation_id", sa.String(120), nullable=True),
        sa.Column(
            "target_response",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("target_status_code", sa.Integer(), nullable=True),
        sa.Column("target_latency_ms", sa.Integer(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("kickoff_turns")
