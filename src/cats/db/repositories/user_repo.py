"""User-table CRUD. Hand-written async SQL — thin layer."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from cats.api.auth import Role, hash_password
from cats.db.schema import users


def _utcnow() -> datetime:
    return datetime.now(UTC)


async def create_user(
    session: AsyncSession,
    *,
    email: str,
    password: str,
    role: Role,
) -> UUID:
    new_id = uuid4()
    await session.execute(
        insert(users).values(
            id=new_id,
            email=email.lower(),
            password_hash=hash_password(password),
            role=role,
            is_active=True,
            created_at=_utcnow(),
        )
    )
    return new_id


async def get_user_by_email(session: AsyncSession, email: str) -> dict[str, Any] | None:
    row = (
        await session.execute(
            select(
                users.c.id,
                users.c.email,
                users.c.role,
                users.c.is_active,
                users.c.created_at,
            ).where(users.c.email == email.lower())
        )
    ).first()
    if row is None:
        return None
    return {
        "id": row.id,
        "email": row.email,
        "role": row.role,
        "is_active": row.is_active,
        "created_at": row.created_at,
    }


async def list_users(session: AsyncSession) -> list[dict[str, Any]]:
    rows = (
        await session.execute(
            select(
                users.c.id,
                users.c.email,
                users.c.role,
                users.c.is_active,
                users.c.created_at,
            ).order_by(users.c.created_at.desc())
        )
    ).all()
    return [
        {
            "id": r.id,
            "email": r.email,
            "role": r.role,
            "is_active": r.is_active,
            "created_at": r.created_at,
        }
        for r in rows
    ]


async def set_user_active(session: AsyncSession, *, user_id: UUID, active: bool) -> None:
    await session.execute(update(users).where(users.c.id == user_id).values(is_active=active))


async def ensure_admin_seeded(session: AsyncSession, *, email: str, password: str) -> UUID | None:
    """Create the bootstrap admin if absent. Returns the user id when created,
    None when an account already exists for that email (or when inputs blank).
    Idempotent."""
    if not email or not password:
        return None
    existing = await get_user_by_email(session, email)
    if existing is not None:
        return None
    return await create_user(
        session,
        email=email,
        password=password,
        role="admin",
    )
