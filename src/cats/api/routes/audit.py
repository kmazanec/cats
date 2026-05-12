"""Audit-log view. Read-only listing for any signed-in user."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, Request

from cats.api.auth import Principal, require_user
from cats.api.templating import templates
from cats.config import settings
from cats.db.engine import session_scope
from cats.db.repositories.audit_repo import list_audit

router = APIRouter()


@router.get("")
async def audit_page(
    request: Request,
    principal: Principal = Depends(require_user),
    actor: str | None = Query(default=None),
    action: str | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=1000),
) -> Any:
    async with session_scope() as session:
        rows = await list_audit(session, limit=limit, actor=actor, action=action)
    ctx: dict[str, Any] = {
        "active": "audit",
        "principal": principal,
        "env_tag": settings.default_target_env,
        "build_tag": settings.build_sha,
        "build_pipeline_url": settings.gitlab_pipeline_url,
        "now_utc": "",
        "db_status": "—",
        "redis_status": "—",
        "openrouter_status": "—",
        "audit_rows": rows,
        "filter_actor": actor or "",
        "filter_action": action or "",
        "limit": limit,
    }
    return templates.TemplateResponse(request, "audit.html", ctx)
