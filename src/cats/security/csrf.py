"""Double-submit CSRF token.

R1 deferred CSRF to R2 because the campaign-fire endpoint dramatically
raises blast radius. The chosen pattern:

1. On every request that renders a form, the response sets a
   `cats_csrf` cookie (samesite=lax, httponly=false so the form can read
   it, secure when on https).
2. Every form renders a hidden `csrf_token` field with the same value.
3. POST handlers depend on `require_csrf`, which compares the form
   value (or `X-CSRF-Token` header) against the cookie. Mismatch -> 403.

The cookie value is a 32-byte urlsafe-base64 random string. It rotates
when missing; existing tokens are valid until cookie expiry.

This is independent of the session cookie — having a valid session
isn't enough to fire a state-changing POST.
"""

from __future__ import annotations

import secrets
from typing import Final

from fastapi import HTTPException, Request, status
from fastapi.responses import Response

CSRF_COOKIE_NAME: Final = "cats_csrf"
CSRF_FORM_FIELD: Final = "csrf_token"
CSRF_HEADER_NAME: Final = "X-CSRF-Token"
CSRF_TOKEN_BYTES: Final = 32
CSRF_COOKIE_MAX_AGE: Final = 60 * 60 * 24 * 7  # 1 week


def generate_token() -> str:
    return secrets.token_urlsafe(CSRF_TOKEN_BYTES)


def ensure_token(request: Request) -> str:
    """Return the current request's CSRF token. Generates and stashes one
    on `request.state` if the cookie is missing — the templating layer
    then writes it back into the response."""
    existing = request.cookies.get(CSRF_COOKIE_NAME, "")
    if existing:
        request.state.csrf_token = existing
        return existing
    token = generate_token()
    request.state.csrf_token = token
    request.state.csrf_token_is_new = True
    return token


def attach_cookie_if_new(request: Request, response: Response) -> None:
    """If `ensure_token` minted a fresh token on this request, write it
    to the response cookie. Called by the template-response wrapper."""
    if not getattr(request.state, "csrf_token_is_new", False):
        return
    token = getattr(request.state, "csrf_token", "")
    if not token:
        return
    response.set_cookie(
        CSRF_COOKIE_NAME,
        token,
        max_age=CSRF_COOKIE_MAX_AGE,
        httponly=False,  # readable so HTMX / JS can echo it in headers
        samesite="lax",
        secure=request.url.scheme == "https",
        path="/",
    )


async def require_csrf(request: Request) -> None:
    """FastAPI dependency: validates the CSRF token on every state-changing
    POST. Reads the cookie + the form field (or header), compares with
    constant-time equality, raises 403 on mismatch.
    """
    cookie = request.cookies.get(CSRF_COOKIE_NAME, "")
    if not cookie:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF cookie missing — refresh the page and try again.",
        )

    supplied = request.headers.get(CSRF_HEADER_NAME, "")
    if not supplied:
        # Drain the form body to read the hidden field. FastAPI's form
        # parser is idempotent across one request.
        try:
            form = await request.form()
            supplied = str(form.get(CSRF_FORM_FIELD, "") or "")
        except Exception:
            supplied = ""

    if not supplied or not secrets.compare_digest(cookie, supplied):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token mismatch — refresh the page and try again.",
        )
