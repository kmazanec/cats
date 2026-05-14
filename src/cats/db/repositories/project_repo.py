"""Project CRUD for the R1 dashboard. The smoke-path repo
(`smoke_repo.upsert_project`) keeps its own narrow shape; this module is the
general one routes use."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import delete, insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from cats.db.schema import projects


def _utcnow() -> datetime:
    return datetime.now(UTC)


async def list_projects(session: AsyncSession) -> list[dict[str, Any]]:
    rows = (
        await session.execute(
            select(
                projects.c.id,
                projects.c.name,
                projects.c.description,
                projects.c.base_url,
                projects.c.env,
                projects.c.allow_run_against,
                projects.c.target_kind,
                projects.c.target_username,
                projects.c.target_password_encrypted,
                projects.c.created_at,
            ).order_by(projects.c.created_at.desc())
        )
    ).all()
    return [
        {
            "id": r.id,
            "name": r.name,
            "description": r.description,
            "base_url": r.base_url,
            "env": r.env,
            "allow_run_against": r.allow_run_against,
            "target_kind": r.target_kind,
            "target_username": r.target_username,
            "has_target_password": bool(r.target_password_encrypted),
            "created_at": r.created_at,
        }
        for r in rows
    ]


async def get_project(session: AsyncSession, project_id: UUID) -> dict[str, Any] | None:
    row = (
        await session.execute(
            select(
                projects.c.id,
                projects.c.name,
                projects.c.description,
                projects.c.base_url,
                projects.c.env,
                projects.c.allow_run_against,
                projects.c.target_kind,
                projects.c.target_username,
                projects.c.target_password_encrypted,
                projects.c.deploy_webhook_secret_encrypted,
                projects.c.created_at,
            ).where(projects.c.id == project_id)
        )
    ).first()
    if row is None:
        return None
    return {
        "id": row.id,
        "name": row.name,
        "description": row.description,
        "base_url": row.base_url,
        "env": row.env,
        "allow_run_against": row.allow_run_against,
        "target_kind": row.target_kind,
        "target_username": row.target_username,
        "has_target_password": bool(row.target_password_encrypted),
        "has_deploy_webhook_secret": bool(row.deploy_webhook_secret_encrypted),
        "created_at": row.created_at,
    }


async def create_project(
    session: AsyncSession,
    *,
    name: str,
    base_url: str,
    env: str,
    description: str = "",
    allow_run_against: bool = False,
    target_kind: str = "copilot_proxy",
    target_username: str = "",
    target_password_encrypted: str = "",
) -> UUID:
    new_id = uuid4()
    await session.execute(
        insert(projects).values(
            id=new_id,
            name=name,
            description=description,
            base_url=base_url,
            env=env,
            allow_run_against=allow_run_against,
            target_kind=target_kind,
            target_username=target_username or None,
            target_password_encrypted=target_password_encrypted or None,
            created_at=_utcnow(),
        )
    )
    return new_id


async def update_project(
    session: AsyncSession,
    *,
    project_id: UUID,
    name: str,
    base_url: str,
    env: str,
    description: str,
    allow_run_against: bool,
    target_kind: str = "copilot_proxy",
    target_username: str = "",
    target_password_encrypted: str | None = None,
) -> None:
    """Update a project. `target_password_encrypted=None` means 'keep
    the existing password'; an empty string clears it."""
    values: dict[str, Any] = {
        "name": name,
        "description": description,
        "base_url": base_url,
        "env": env,
        "allow_run_against": allow_run_against,
        "target_kind": target_kind,
        "target_username": target_username or None,
    }
    if target_password_encrypted is not None:
        values["target_password_encrypted"] = target_password_encrypted or None
    await session.execute(update(projects).where(projects.c.id == project_id).values(**values))


async def delete_project(session: AsyncSession, *, project_id: UUID) -> None:
    await session.execute(delete(projects).where(projects.c.id == project_id))
