"""initial schema + audit_log append-only enforcement.

Revision ID: 20260511_0001
Revises:
Create Date: 2026-05-11

"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

from cats.db.schema import metadata

revision: str = "20260511_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")  # gen_random_uuid()
    bind = op.get_bind()
    metadata.create_all(bind=bind)

    # Append-only audit_log enforcement: revoke UPDATE/DELETE + deny trigger.
    # asyncpg can't prepare multi-statement strings, so each statement is its
    # own op.execute() call.
    op.execute("REVOKE UPDATE, DELETE ON TABLE audit_log FROM PUBLIC")
    op.execute(
        """
        CREATE OR REPLACE FUNCTION audit_log_block_mutation()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'audit_log is append-only';
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute("DROP TRIGGER IF EXISTS audit_log_no_update ON audit_log")
    op.execute(
        """
        CREATE TRIGGER audit_log_no_update
            BEFORE UPDATE ON audit_log
            FOR EACH ROW EXECUTE FUNCTION audit_log_block_mutation()
        """
    )
    op.execute("DROP TRIGGER IF EXISTS audit_log_no_delete ON audit_log")
    op.execute(
        """
        CREATE TRIGGER audit_log_no_delete
            BEFORE DELETE ON audit_log
            FOR EACH ROW EXECUTE FUNCTION audit_log_block_mutation()
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_log_no_update ON audit_log")
    op.execute("DROP TRIGGER IF EXISTS audit_log_no_delete ON audit_log")
    op.execute("DROP FUNCTION IF EXISTS audit_log_block_mutation()")
    bind = op.get_bind()
    metadata.drop_all(bind=bind)
