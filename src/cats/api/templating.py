"""Shared Jinja2Templates instance. Every route module imports `templates`
from here so they all see the same env (filters, globals, autoescape).

Specifically, the CSRF helper (`csrf_input(request)`) is added once on this
shared instance and is then available in every template via
`{{ csrf_input(request) | safe }}`.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import Request
from fastapi.templating import Jinja2Templates

TEMPLATES_DIR = Path(__file__).parent / "templates"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.filters["pluralize"] = lambda n, suffix="s": "" if n == 1 else suffix


def _csrf_input(request: Request) -> str:
    """Render the hidden CSRF input field. Templates call as:

        <form method="post" action="...">
            {{ csrf_input(request) | safe }}
            ...
        </form>

    Tokens are URL-safe base64 so they don't need HTML-entity encoding,
    but we strip embedded quotes anyway as defense-in-depth.
    """
    token = getattr(request.state, "csrf_token", "") or ""
    safe = token.replace('"', "")
    return f'<input type="hidden" name="csrf_token" value="{safe}" />'


templates.env.globals["csrf_input"] = _csrf_input
