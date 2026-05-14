"""File-borne attack payloads (uploaded .docx etc).

Persists the bytes that the target ingests via document_upload.php +
extract.php so (a) run forensics can let an operator download the exact
artifact that was uploaded and (b) regression replays reconstruct a
byte-identical AttachmentSpec instead of re-synthesizing.

Revision ID: 20260514_0013
Revises: 20260514_0012
Create Date: 2026-05-14
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260514_0013"
down_revision: str | None = "20260514_0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "attack_artifacts",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "attack_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("attacks.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.String(16), nullable=False, server_default="docx"),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column(
            "content_type",
            sa.String(255),
            nullable=False,
            server_default="application/octet-stream",
        ),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("data", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("attack_id", "sha256", name="uq_attack_artifacts_attack_sha"),
        sa.CheckConstraint(
            "kind IN ('docx','pdf','image','other')",
            name="ck_attack_artifacts_kind",
        ),
    )
    op.create_index("ix_attack_artifacts_attack_id", "attack_artifacts", ["attack_id"])
    op.create_index("ix_attack_artifacts_sha256", "attack_artifacts", ["sha256"])


def downgrade() -> None:
    op.drop_index("ix_attack_artifacts_sha256", table_name="attack_artifacts")
    op.drop_index("ix_attack_artifacts_attack_id", table_name="attack_artifacts")
    op.drop_table("attack_artifacts")
