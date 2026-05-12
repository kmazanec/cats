"""server-side default for audit_log.at + source_access_log.at.

Revision ID: 20260511_0002
Revises: 20260511_0001

"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "20260511_0002"
down_revision: str | None = "20260511_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("ALTER TABLE audit_log ALTER COLUMN at SET DEFAULT now()")
    op.execute("ALTER TABLE source_access_log ALTER COLUMN at SET DEFAULT now()")


def downgrade() -> None:
    op.execute("ALTER TABLE audit_log ALTER COLUMN at DROP DEFAULT")
    op.execute("ALTER TABLE source_access_log ALTER COLUMN at DROP DEFAULT")
