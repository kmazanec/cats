"""Admin-only user management. Lists, creates, and deactivates users."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any, get_args
from uuid import UUID

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from cats.api.auth import Principal, Role, require_role
from cats.config import settings
from cats.db.engine import session_scope
from cats.db.repositories.audit_repo import write_audit
from cats.db.repositories.user_repo import (
    create_user,
    get_user_by_email,
    list_users,
    set_user_active,
)

router = APIRouter()

TEMPLATES_DIR = Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


_VALID_ROLES = set(get_args(Role))


def _chrome_ctx(principal: Principal) -> dict[str, Any]:
    return {
        "active": "users",
        "principal": principal,
        "env_tag": settings.default_target_env,
        "build_tag": settings.build_sha,
        "build_pipeline_url": settings.gitlab_pipeline_url,
        "now_utc": "",
        "db_status": "—",
        "redis_status": "—",
        "openrouter_status": "—",
    }


@router.get("")
async def list_users_page(
    request: Request,
    principal: Principal = Depends(require_role("admin")),
) -> Any:
    async with session_scope() as session:
        rows = await list_users(session)
    ctx = _chrome_ctx(principal)
    ctx.update({"users": rows, "roles": sorted(_VALID_ROLES), "error": None})
    return templates.TemplateResponse(request, "users_list.html", ctx)


@router.post("")
async def create_user_submit(
    request: Request,
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
    role: Annotated[str, Form()],
    principal: Principal = Depends(require_role("admin")),
) -> Any:
    email_norm = email.strip().lower()
    if role not in _VALID_ROLES:
        raise HTTPException(status_code=400, detail=f"role must be one of {sorted(_VALID_ROLES)}")
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="password must be at least 8 characters")

    async with session_scope() as session:
        existing = await get_user_by_email(session, email_norm)
        if existing is not None:
            rows = await list_users(session)
            ctx = _chrome_ctx(principal)
            ctx.update(
                {
                    "users": rows,
                    "roles": sorted(_VALID_ROLES),
                    "error": f"A user with email {email_norm!r} already exists.",
                }
            )
            return templates.TemplateResponse(request, "users_list.html", ctx, status_code=400)
        new_id = await create_user(
            session,
            email=email_norm,
            password=password,
            role=role,  # type: ignore[arg-type]
        )
        await write_audit(
            session,
            actor=principal.email,
            action="user.create",
            target_kind="user",
            target_id=new_id,
            payload={"email": email_norm, "role": role},
        )
    return RedirectResponse(url="/users", status_code=303)


@router.post("/{user_id}/deactivate")
async def deactivate_user(
    user_id: UUID,
    principal: Principal = Depends(require_role("admin")),
) -> RedirectResponse:
    if principal.user_id == user_id:
        raise HTTPException(status_code=400, detail="cannot deactivate your own account")
    async with session_scope() as session:
        await set_user_active(session, user_id=user_id, active=False)
        await write_audit(
            session,
            actor=principal.email,
            action="user.deactivate",
            target_kind="user",
            target_id=user_id,
            payload={},
        )
    return RedirectResponse(url="/users", status_code=303)


@router.post("/{user_id}/reactivate")
async def reactivate_user(
    user_id: UUID,
    principal: Principal = Depends(require_role("admin")),
) -> RedirectResponse:
    async with session_scope() as session:
        await set_user_active(session, user_id=user_id, active=True)
        await write_audit(
            session,
            actor=principal.email,
            action="user.reactivate",
            target_kind="user",
            target_id=user_id,
            payload={},
        )
    return RedirectResponse(url="/users", status_code=303)
