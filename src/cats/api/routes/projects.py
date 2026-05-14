"""Projects routes — list / create / edit / delete.

- viewer can list and view detail.
- operator can create and edit.
- admin can delete.

Every mutation lands in the audit log."""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse

from cats.api.auth import Principal, require_role, require_user
from cats.api.templating import templates
from cats.config import settings
from cats.db.engine import session_scope
from cats.db.repositories.audit_repo import write_audit
from cats.db.repositories.project_repo import (
    create_project,
    delete_project,
    get_project,
    list_projects,
    update_project,
)
from cats.security.csrf import require_csrf

router = APIRouter()


def _chrome_ctx(principal: Principal) -> dict[str, Any]:
    return {
        "active": "projects",
        "principal": principal,
        "env_tag": settings.default_target_env,
        "build_tag": settings.build_sha,
        "build_pipeline_url": settings.gitlab_pipeline_url,
        "now_utc": "",
        "db_status": "—",
        "redis_status": "—",
        "openrouter_status": "—",
    }


def _validate_env(env: str) -> str:
    if env not in ("local", "staging", "prod"):
        raise HTTPException(
            status_code=400,
            detail=f"env must be one of local|staging|prod (got {env!r})",
        )
    return env


def _validate_base_url(base_url: str) -> str:
    base_url = base_url.strip()
    if not base_url.startswith(("http://", "https://")):
        raise HTTPException(
            status_code=400,
            detail="base_url must start with http:// or https://",
        )
    return base_url


@router.get("")
async def list_projects_page(
    request: Request,
    principal: Principal = Depends(require_user),
) -> Any:
    async with session_scope() as session:
        rows = await list_projects(session)
    ctx = _chrome_ctx(principal)
    ctx["projects"] = rows
    return templates.TemplateResponse(request, "projects_list.html", ctx)


@router.get("/new")
async def new_project_form(
    request: Request,
    principal: Principal = Depends(require_role("operator")),
) -> Any:
    ctx = _chrome_ctx(principal)
    ctx.update(
        {
            "project": None,
            "form_action": "/projects",
            "form_title": "Register a new project",
            "submit_label": "create",
        }
    )
    return templates.TemplateResponse(request, "project_form.html", ctx)


def _validate_target_kind(kind: str) -> str:
    if kind not in ("copilot_proxy", "copilot_internal"):
        raise HTTPException(
            status_code=400,
            detail=f"target_kind must be copilot_proxy|copilot_internal (got {kind!r})",
        )
    return kind


@router.post("", dependencies=[Depends(require_csrf)])
async def create_project_submit(
    name: Annotated[str, Form()],
    base_url: Annotated[str, Form()],
    env: Annotated[str, Form()],
    description: Annotated[str, Form()] = "",
    allow_run_against: Annotated[str | None, Form()] = None,
    target_kind: Annotated[str, Form()] = "copilot_proxy",
    target_username: Annotated[str, Form()] = "",
    target_password: Annotated[str, Form()] = "",
    principal: Principal = Depends(require_role("operator")),
) -> RedirectResponse:
    from cats.security.crypto import encrypt

    env = _validate_env(env)
    base_url = _validate_base_url(base_url)
    target_kind = _validate_target_kind(target_kind)
    allow = allow_run_against == "on"
    if target_kind == "copilot_proxy" and target_username and not target_password:
        raise HTTPException(
            status_code=400,
            detail="target_password required when target_username is set on a proxy target",
        )
    async with session_scope() as session:
        new_id = await create_project(
            session,
            name=name.strip(),
            description=description.strip(),
            base_url=base_url,
            env=env,
            allow_run_against=allow,
            target_kind=target_kind,
            target_username=target_username.strip(),
            target_password_encrypted=(encrypt(target_password) if target_password else ""),
        )
        await write_audit(
            session,
            actor=principal.email,
            action="project.create",
            target_kind="project",
            target_id=new_id,
            payload={
                "name": name.strip(),
                "env": env,
                "base_url": base_url,
                "allow_run_against": allow,
                "target_kind": target_kind,
                "has_target_username": bool(target_username),
                "has_target_password": bool(target_password),
            },
        )
    return RedirectResponse(url="/projects", status_code=303)


@router.get("/{project_id}/edit")
async def edit_project_form(
    request: Request,
    project_id: UUID,
    principal: Principal = Depends(require_role("operator")),
) -> Any:
    async with session_scope() as session:
        project = await get_project(session, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="project not found")
    ctx = _chrome_ctx(principal)
    ctx.update(
        {
            "project": project,
            "form_action": f"/projects/{project_id}",
            "form_title": f"Edit {project['name']}",
            "submit_label": "save",
        }
    )
    return templates.TemplateResponse(request, "project_form.html", ctx)


@router.post("/{project_id}", dependencies=[Depends(require_csrf)])
async def update_project_submit(
    project_id: UUID,
    name: Annotated[str, Form()],
    base_url: Annotated[str, Form()],
    env: Annotated[str, Form()],
    description: Annotated[str, Form()] = "",
    allow_run_against: Annotated[str | None, Form()] = None,
    target_kind: Annotated[str, Form()] = "copilot_proxy",
    target_username: Annotated[str, Form()] = "",
    target_password: Annotated[str, Form()] = "",
    principal: Principal = Depends(require_role("operator")),
) -> RedirectResponse:
    from cats.security.crypto import encrypt

    env = _validate_env(env)
    base_url = _validate_base_url(base_url)
    target_kind = _validate_target_kind(target_kind)
    allow = allow_run_against == "on"
    async with session_scope() as session:
        existing = await get_project(session, project_id)
        if existing is None:
            raise HTTPException(status_code=404, detail="project not found")
        # Empty target_password on edit = keep existing; we never display
        # the stored password back to the user.
        encrypted_pw: str | None = encrypt(target_password) if target_password else None
        await update_project(
            session,
            project_id=project_id,
            name=name.strip(),
            description=description.strip(),
            base_url=base_url,
            env=env,
            allow_run_against=allow,
            target_kind=target_kind,
            target_username=target_username.strip(),
            target_password_encrypted=encrypted_pw,
        )
        await write_audit(
            session,
            actor=principal.email,
            action="project.update",
            target_kind="project",
            target_id=project_id,
            payload={
                "name": name.strip(),
                "env": env,
                "base_url": base_url,
                "allow_run_against": allow,
                "target_kind": target_kind,
                "has_target_username": bool(target_username),
                "rotated_target_password": bool(target_password),
            },
        )
    return RedirectResponse(url="/projects", status_code=303)


@router.post(
    "/{project_id}/webhook-secret/generate",
    dependencies=[Depends(require_csrf)],
)
async def generate_webhook_secret(
    request: Request,
    project_id: UUID,
    principal: Principal = Depends(require_role("operator")),
) -> Any:
    """Mint a 32-byte hex HMAC secret, encrypt + persist, and render
    it back to the operator EXACTLY ONCE so they can copy it into the
    project's upstream CI. The plaintext is never retrievable from
    CATS after this response; rotating overwrites the stored secret
    and invalidates the previous one."""
    import secrets as _secrets

    from sqlalchemy import update

    from cats.db.schema import projects
    from cats.security.crypto import encrypt

    plain_secret = _secrets.token_hex(32)
    async with session_scope() as session:
        existing = await get_project(session, project_id)
        if existing is None:
            raise HTTPException(status_code=404, detail="project not found")
        await session.execute(
            update(projects)
            .where(projects.c.id == project_id)
            .values(deploy_webhook_secret_encrypted=encrypt(plain_secret))
        )
        await write_audit(
            session,
            actor=principal.email,
            action="project.webhook_secret.generated",
            target_kind="project",
            target_id=project_id,
            payload={"rotated": existing["has_deploy_webhook_secret"]},
        )
    ctx = _chrome_ctx(principal)
    ctx.update(
        {
            "project": existing,
            "secret": plain_secret,
            "webhook_url_path": f"/webhooks/deploy/{project_id}",
        }
    )
    return templates.TemplateResponse(request, "project_webhook_secret.html", ctx)


@router.post(
    "/{project_id}/webhook-secret/revoke",
    dependencies=[Depends(require_csrf)],
)
async def revoke_webhook_secret(
    project_id: UUID,
    principal: Principal = Depends(require_role("operator")),
) -> RedirectResponse:
    """Clear the project's webhook secret. The webhook returns 503
    after revocation — useful when an upstream CI's credential leaks
    and you want to stop accepting signed payloads immediately."""
    from sqlalchemy import update

    from cats.db.schema import projects

    async with session_scope() as session:
        existing = await get_project(session, project_id)
        if existing is None:
            raise HTTPException(status_code=404, detail="project not found")
        await session.execute(
            update(projects)
            .where(projects.c.id == project_id)
            .values(deploy_webhook_secret_encrypted=None)
        )
        await write_audit(
            session,
            actor=principal.email,
            action="project.webhook_secret.revoked",
            target_kind="project",
            target_id=project_id,
            payload={},
        )
    return RedirectResponse(url=f"/projects/{project_id}/edit", status_code=303)


@router.post("/{project_id}/delete", dependencies=[Depends(require_csrf)])
async def delete_project_submit(
    project_id: UUID,
    principal: Principal = Depends(require_role("admin")),
) -> RedirectResponse:
    async with session_scope() as session:
        existing = await get_project(session, project_id)
        if existing is None:
            raise HTTPException(status_code=404, detail="project not found")
        await delete_project(session, project_id=project_id)
        await write_audit(
            session,
            actor=principal.email,
            action="project.delete",
            target_kind="project",
            target_id=project_id,
            payload={"name": existing["name"]},
        )
    return RedirectResponse(url="/projects", status_code=303)
