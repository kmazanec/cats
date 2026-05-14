"""R10 multi-turn attacks — decisive turn + per-execution seed_idx.

Adds:
- ``judge_verdicts.decisive_seed_idx`` (nullable int) — which turn of a
  multi-turn conversation crossed the line, set by the Judge when the
  verdict is ``pass`` over a transcript with > 1 turn.
- ``judge_verdicts.total_seeds`` (int, default 1) — how many turns the
  Judge weighed. ``1`` for the legacy single-turn path; > 1 when the
  Red Team chose to escalate.
- ``findings.decisive_seed_idx`` (nullable int) — mirror from the
  Judge's verdict, surfaced on the finding-detail page so the user can
  see which turn was decisive without joining to judge_verdicts.
- ``findings.total_seeds`` (int, default 1) — conversation length the
  finding was confirmed over.
- ``attack_executions.seed_idx`` (int, default 0) — which turn of the
  conversation this execution is. Lets the run-detail UI show per-turn
  cost without inferring from the AttackEvent payload.

Revision ID: 20260513_0009
Revises: 20260513_0008
Create Date: 2026-05-13
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260513_0009"
down_revision: str | None = "20260513_0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "judge_verdicts",
        sa.Column("decisive_seed_idx", sa.Integer(), nullable=True),
    )
    op.add_column(
        "judge_verdicts",
        sa.Column(
            "total_seeds",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("1"),
        ),
    )
    op.add_column(
        "findings",
        sa.Column("decisive_seed_idx", sa.Integer(), nullable=True),
    )
    op.add_column(
        "findings",
        sa.Column(
            "total_seeds",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("1"),
        ),
    )
    op.add_column(
        "attack_executions",
        sa.Column(
            "seed_idx",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
    )


def downgrade() -> None:
    op.drop_column("attack_executions", "seed_idx")
    op.drop_column("findings", "total_seeds")
    op.drop_column("findings", "decisive_seed_idx")
    op.drop_column("judge_verdicts", "total_seeds")
    op.drop_column("judge_verdicts", "decisive_seed_idx")
