"""R10-follow-up — allow ``red_team_agent`` in ``attacks.source``.

The LangGraph Red Team agent introduced in this round persists its
per-turn ``attacks`` rows with ``source='red_team_agent'`` so the
audit trail distinguishes agent-driven turns from the legacy graph
path's ``red_team`` / ``mutator`` rows. Without this migration, the
``ck_attacks_source`` CHECK constraint rejects the new literal.

Revision ID: 20260513_0010
Revises: 20260513_0009
Create Date: 2026-05-13
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "20260513_0010"
down_revision: str | Sequence[str] | None = "20260513_0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_constraint("ck_attacks_source", "attacks", type_="check")
    op.create_check_constraint(
        "ck_attacks_source",
        "attacks",
        "source IN ('seed','red_team','mutator','regression','red_team_agent')",
    )


def downgrade() -> None:
    # Downgrade is a one-way door: existing red_team_agent rows would
    # violate the narrower constraint. Drop the constraint first; if
    # rows are present the operator must reclassify them before
    # restoring the narrow constraint.
    op.drop_constraint("ck_attacks_source", "attacks", type_="check")
    op.create_check_constraint(
        "ck_attacks_source",
        "attacks",
        "source IN ('seed','red_team','mutator','regression')",
    )
