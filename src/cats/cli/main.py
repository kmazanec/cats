"""`cats` CLI entrypoint."""

from __future__ import annotations

import asyncio
from typing import Annotated

import typer

from cats.cli.smoke import run_smoke

app = typer.Typer(no_args_is_help=True, help="CATS adversarial platform CLI.")


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


if __name__ == "__main__":
    app()
