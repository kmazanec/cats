"""R4 — typed Postgres-backed message bus + per-agent durable state.

Adds:
- ``agent_messages``: the bus. One row per envelope. Indexed for
  ``FOR UPDATE SKIP LOCKED`` dispatch on ``(to_agent, visible_after)
  WHERE consumed_at IS NULL``; unique on ``idempotency_key``.
- ``agent_dead_letters``: parking lot for envelopes that exceeded the
  retry budget. The bus dashboard reads this.
- ``red_team_attempts``: durable per-``attack_id`` iteration counter
  for the Red Team's partial-loop, so a crashed worker can resume
  (ARCHITECTURE.md §2.7).
- ``documentation_drafts``: per-finding draft state with an
  ``awaiting_approval`` flag — R4 establishes the row; R9 wires the
  critical-severity gate.
- ``worker_heartbeats``: ``/healthz`` reads the most recent beat per
  worker; older than 2x the agent's visibility timeout = unhealthy.
- ``campaign_plans``: stores ``proposed`` and ``approved`` plan JSON
  alongside the operator who approved + the diff, so the audit
  trail is queryable without re-reading bus envelopes.

Revision ID: 20260512_0005
Revises: 20260512_0004
Create Date: 2026-05-12
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260512_0005"
down_revision: str | None = "20260512_0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "agent_messages",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("from_agent", sa.String(32), nullable=False),
        sa.Column("to_agent", sa.String(32), nullable=False),
        sa.Column("kind", sa.String(64), nullable=False),
        sa.Column(
            "payload_json",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("trace_id", sa.String(120), nullable=False, server_default=""),
        sa.Column("campaign_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("attack_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("idempotency_key", sa.Text, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "visible_after",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consumed_by", sa.String(200), nullable=True),
        sa.Column("attempts", sa.Integer, nullable=False, server_default="0"),
        sa.Column("last_error", sa.Text, nullable=True),
        sa.CheckConstraint(
            "from_agent IN ('trigger','orchestrator','red_team','judge',"
            "'documentation','operator','system')",
            name="ck_agent_messages_from",
        ),
        sa.CheckConstraint(
            "to_agent IN ('orchestrator','red_team','judge','documentation','operator','system')",
            name="ck_agent_messages_to",
        ),
    )
    op.create_index(
        "uq_agent_messages_idempotency_key",
        "agent_messages",
        ["idempotency_key"],
        unique=True,
    )
    op.create_index(
        "ix_agent_messages_inbox",
        "agent_messages",
        ["to_agent", "visible_after"],
        postgresql_where=sa.text("consumed_at IS NULL"),
    )
    op.create_index("ix_agent_messages_campaign_id", "agent_messages", ["campaign_id"])
    op.create_index("ix_agent_messages_attack_id", "agent_messages", ["attack_id"])

    op.create_table(
        "agent_dead_letters",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "message_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("agent_messages.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("to_agent", sa.String(32), nullable=False),
        sa.Column("kind", sa.String(64), nullable=False),
        sa.Column("last_error", sa.Text, nullable=False, server_default=""),
        sa.Column(
            "dead_lettered_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("requeued_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("requeued_by", sa.String(200), nullable=True),
    )
    op.create_index(
        "ix_agent_dead_letters_to_agent",
        "agent_dead_letters",
        ["to_agent"],
        postgresql_where=sa.text("requeued_at IS NULL"),
    )

    op.create_table(
        "red_team_attempts",
        sa.Column(
            "attack_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("attacks.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("iteration", sa.Integer, nullable=False, server_default="0"),
        sa.Column("max_iterations", sa.Integer, nullable=False, server_default="2"),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint(
            "status IN ('active','exhausted','complete','failed')",
            name="ck_red_team_attempts_status",
        ),
    )

    op.create_table(
        "documentation_drafts",
        sa.Column(
            "finding_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("findings.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("status", sa.String(16), nullable=False, server_default="draft"),
        sa.Column(
            "awaiting_approval",
            sa.Boolean,
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint(
            "status IN ('draft','published','rejected')",
            name="ck_documentation_drafts_status",
        ),
    )

    op.create_table(
        "worker_heartbeats",
        sa.Column("worker_name", sa.String(64), nullable=False),
        sa.Column("host_pid", sa.String(200), nullable=False),
        sa.Column(
            "last_beat_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("worker_name", "host_pid"),
    )
    op.create_index(
        "ix_worker_heartbeats_worker_name",
        "worker_heartbeats",
        ["worker_name", "last_beat_at"],
    )

    op.create_table(
        "campaign_plans",
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
        sa.Column("status", sa.String(20), nullable=False, server_default="proposed"),
        sa.Column(
            "proposed_plan",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("approved_plan", postgresql.JSONB, nullable=True),
        sa.Column(
            "tool_transcript",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("rationale", sa.Text, nullable=False, server_default=""),
        sa.Column("approver_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "diff_summary",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint(
            "status IN ('proposed','approved','edited','rejected','dispatched','failed')",
            name="ck_campaign_plans_status",
        ),
    )
    op.create_index(
        "ix_campaign_plans_campaign_id",
        "campaign_plans",
        ["campaign_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_campaign_plans_campaign_id", table_name="campaign_plans")
    op.drop_table("campaign_plans")
    op.drop_index("ix_worker_heartbeats_worker_name", table_name="worker_heartbeats")
    op.drop_table("worker_heartbeats")
    op.drop_table("documentation_drafts")
    op.drop_table("red_team_attempts")
    op.drop_index("ix_agent_dead_letters_to_agent", table_name="agent_dead_letters")
    op.drop_table("agent_dead_letters")
    op.drop_index("ix_agent_messages_attack_id", table_name="agent_messages")
    op.drop_index("ix_agent_messages_campaign_id", table_name="agent_messages")
    op.drop_index("ix_agent_messages_inbox", table_name="agent_messages")
    op.drop_index("uq_agent_messages_idempotency_key", table_name="agent_messages")
    op.drop_table("agent_messages")
