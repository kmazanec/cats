"""``cats project`` subcommands.

For now: managing the per-project deploy webhook secret. More project
admin (create / list / promote-to-runnable) will move here too once
the operator workflow is mature enough to need it; today those still
live in the UI / direct SQL.
"""

from __future__ import annotations

import asyncio
import secrets as _secrets
from typing import Annotated
from uuid import UUID

import typer
from sqlalchemy import select, update

from cats.db.engine import session_scope
from cats.db.repositories.audit_repo import write_audit
from cats.db.schema import projects
from cats.security.crypto import encrypt

project_app = typer.Typer(no_args_is_help=True, help="Project management (R8 followup).")


@project_app.command("set-webhook-secret")
def set_webhook_secret(
    project_id: Annotated[
        str,
        typer.Argument(help="UUID of the project to configure."),
    ],
    secret: Annotated[
        str | None,
        typer.Option(
            "--secret",
            help="Webhook HMAC secret. Omit to generate a random 32-byte hex.",
        ),
    ] = None,
) -> None:
    """Set (or rotate) the deploy-webhook HMAC secret for a project.

    The secret is Fernet-encrypted at rest. After running this, plug
    the printed secret into the project's upstream CI as
    ``CATS_WEBHOOK_SECRET`` and the project's UUID as
    ``CATS_PROJECT_ID``. The webhook URL is
    ``POST /webhooks/deploy/<project-id>``.
    """
    pid = UUID(project_id)
    generated = secret is None
    raw_secret = secret or _secrets.token_hex(32)
    asyncio.run(_persist(pid, raw_secret))
    typer.echo(f"webhook secret stored for project {pid}")
    if generated:
        # Print the generated secret exactly once — the operator must
        # capture it for the CI side. We do not store the plaintext.
        typer.echo("")
        typer.echo(f"  CATS_WEBHOOK_SECRET={raw_secret}")
        typer.echo(f"  CATS_PROJECT_ID={pid}")
        typer.echo("")
        typer.echo("Capture the secret above — it is not retrievable from CATS later.")


async def _persist(project_id: UUID, plain_secret: str) -> None:
    encrypted = encrypt(plain_secret)
    async with session_scope() as session:
        existing = (
            await session.execute(select(projects.c.id).where(projects.c.id == project_id))
        ).scalar_one_or_none()
        if existing is None:
            raise typer.BadParameter(f"no project with id {project_id}")
        await session.execute(
            update(projects)
            .where(projects.c.id == project_id)
            .values(deploy_webhook_secret_encrypted=encrypted)
        )
        await write_audit(
            session,
            actor="cats.cli.project",
            action="project.webhook_secret.set",
            target_kind="project",
            target_id=project_id,
            payload={"rotated": True},
        )
