"""Login + logout. Sets/clears the signed session cookie."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from cats.api.auth import (
    SESSION_COOKIE_NAME,
    Principal,
    authenticate,
    current_principal,
    issue_session_token,
)
from cats.config import settings
from cats.db.engine import session_scope
from cats.db.repositories.audit_repo import write_audit

router = APIRouter()

TEMPLATES_DIR = Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


@router.get("/login")
async def login_form(
    request: Request,
    principal: Principal | None = Depends(current_principal),
) -> Any:
    if principal is not None:
        return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse(
        request,
        "login.html",
        {
            "active": "",
            "principal": None,
            "env_tag": settings.default_target_env,
            "build_tag": settings.build_sha,
            "now_utc": "",
            "db_status": "—",
            "redis_status": "—",
            "openrouter_status": "—",
            "error": None,
        },
    )


@router.post("/login")
async def login_submit(
    request: Request,
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
) -> Any:
    async with session_scope() as session:
        principal = await authenticate(session, email, password)
        if principal is None:
            return templates.TemplateResponse(
                request,
                "login.html",
                {
                    "active": "",
                    "principal": None,
                    "env_tag": settings.default_target_env,
                    "build_tag": settings.build_sha,
                    "now_utc": "",
                    "db_status": "—",
                    "redis_status": "—",
                    "openrouter_status": "—",
                    "error": "Email or password not recognized.",
                },
                status_code=401,
            )
        await write_audit(
            session,
            actor=principal.email,
            action="auth.login",
            target_kind="user",
            target_id=principal.user_id,
            payload={"role": principal.role},
        )

    token = issue_session_token(principal.user_id)
    response = RedirectResponse(url="/", status_code=302)
    response.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        max_age=settings.session_max_age_seconds,
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
        path="/",
    )
    return response


@router.post("/logout")
async def logout(
    principal: Principal | None = Depends(current_principal),
) -> Response:
    if principal is not None:
        async with session_scope() as session:
            await write_audit(
                session,
                actor=principal.email,
                action="auth.logout",
                target_kind="user",
                target_id=principal.user_id,
                payload={},
            )
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return response
