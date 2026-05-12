"""`cats` CLI entrypoint."""

from __future__ import annotations

import asyncio
import sys
from typing import Annotated

import typer

from cats.cli.smoke import run_smoke

app = typer.Typer(no_args_is_help=True, help="CATS adversarial platform CLI.")
user_app = typer.Typer(no_args_is_help=True, help="User management.")
app.add_typer(user_app, name="user")


@app.command()
def version() -> None:
    """Print the CATS version."""
    from cats import __version__

    typer.echo(__version__)


@app.command()
def smoke(
    target_url: Annotated[
        str | None,
        typer.Option("--target-url", help="Override the default target base URL."),
    ] = None,
) -> None:
    """End-to-end no-LLM smoke path. Writes Run/Attack/Execution/Verdict/Finding rows."""
    asyncio.run(run_smoke(target_url=target_url))


@app.command()
def categories() -> None:
    """List registered attack categories."""
    from cats.categories import REGISTERED_CATEGORIES

    for cat in REGISTERED_CATEGORIES:
        typer.echo(cat)


@app.command()
def health() -> None:
    """Reachability check against every external dependency. Exits non-zero
    when any configured dependency fails."""
    from cats.health.checks import run_all_checks

    async def _go() -> int:
        report = await run_all_checks()
        for r in report.checks:
            marker = (
                "✓ ok"
                if r.status == "ok"
                else "✗ fail"
                if r.status == "fail"
                else "· not configured"
            )
            typer.echo(f"{marker:18} {r.name:14} {r.detail}")
        typer.echo("")
        if report.overall_ok:
            typer.echo("OVERALL: ok")
            return 0
        typer.echo("OVERALL: blocked")
        return 1

    code = asyncio.run(_go())
    raise typer.Exit(code=code)


@user_app.command("create")
def user_create(
    email: Annotated[str, typer.Argument(help="Email address — used as login.")],
    role: Annotated[
        str,
        typer.Option(
            "--role",
            "-r",
            help="One of viewer | operator | senior_operator | admin",
        ),
    ] = "viewer",
    password: Annotated[
        str,
        typer.Option(
            "--password",
            "-p",
            help="Initial password (>= 8 chars). Prompts if omitted.",
            prompt=True,
            hide_input=True,
            confirmation_prompt=False,
        ),
    ] = "",
) -> None:
    """Create a user from the command line. Useful for first-deploy bootstrap
    when CATS_ADMIN_* env vars weren't set."""
    if role not in ("viewer", "operator", "senior_operator", "admin"):
        typer.echo(f"role must be one of viewer|operator|senior_operator|admin (got {role!r})")
        raise typer.Exit(code=2)
    if len(password) < 8:
        typer.echo("password must be at least 8 characters")
        raise typer.Exit(code=2)

    from cats.db.engine import session_scope
    from cats.db.repositories.user_repo import create_user, get_user_by_email

    async def _go() -> int:
        async with session_scope() as session:
            existing = await get_user_by_email(session, email)
            if existing is not None:
                typer.echo(f"user {email!r} already exists")
                return 1
            user_id = await create_user(
                session,
                email=email,
                password=password,
                role=role,  # type: ignore[arg-type]
            )
        typer.echo(f"created user {email} ({role}) id={user_id}")
        return 0

    code = asyncio.run(_go())
    raise typer.Exit(code=code)


if __name__ == "__main__":
    app()
    sys.exit(0)
