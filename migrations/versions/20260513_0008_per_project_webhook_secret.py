"""Per-project deploy-webhook secret.

R8 shipped with a single global ``settings.deploy_webhook_secret``,
which meant exactly one upstream CI could authenticate the deploy
webhook — a hard cap of one project per CATS instance. This
migration adds ``projects.deploy_webhook_secret_encrypted`` (Fernet,
nullable) so each project carries its own secret. The
``POST /webhooks/deploy`` route is reshaped to
``POST /webhooks/deploy/{project_id}`` in the same change set so the
server can look up the correct secret before verifying the signature.

Revision ID: 20260513_0008
Revises: 20260513_0007
Create Date: 2026-05-13
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260513_0008"
down_revision: str | None = "20260513_0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "projects",
        sa.Column("deploy_webhook_secret_encrypted", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("projects", "deploy_webhook_secret_encrypted")
