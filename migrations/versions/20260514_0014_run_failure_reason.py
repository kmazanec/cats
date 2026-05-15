"""Add failure_reason column to runs.

Runs that the platform marks ``status='failed'`` had no surfaced
explanation — the UI just showed a red dot. This adds a short
operator-readable code (e.g. ``orphan_sweep``, ``agent_no_turns``,
``agent_crash``) so the run-detail view can tell you *why*.

Revision ID: 20260514_0014
Revises: 20260514_0013
Create Date: 2026-05-15
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260514_0014"
down_revision: str | None = "20260514_0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "runs",
        sa.Column("failure_reason", sa.String(64), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("runs", "failure_reason")
