"""Session-based auth for the R1 dashboard.

Bcrypt-hashed passwords stored in `users` table; signed session cookie carries
the user id; role gate enforced server-side via FastAPI dependencies.
Replaceable with OIDC later without changing call sites — `current_principal`
is the only entry point routes use.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Literal
from uuid import UUID

import bcrypt
from fastapi import Cookie, Depends, HTTPException, Request, status
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cats.config import settings
from cats.db.engine import session_scope
from cats.db.schema import users

Role = Literal["viewer", "operator", "senior_operator", "admin"]

ROLE_RANK: dict[Role, int] = {
    "viewer": 0,
    "operator": 1,
    "senior_operator": 2,
    "admin": 3,
}

SESSION_COOKIE_NAME = "cats_session"


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------


MIN_PASSWORD_LENGTH = 8


def hash_password(plain: str) -> str:
    """Hash a password with bcrypt. Enforces an 8-char floor so every caller
    (route, CLI, future code) gets the same minimum without relying on the
    caller to validate."""
    if len(plain) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    if not plain or not hashed:
        return False
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Session cookie (signed, time-limited)
# ---------------------------------------------------------------------------


def _serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(settings.session_secret, salt="cats-session-v1")


def issue_session_token(user_id: UUID) -> str:
    return _serializer().dumps(str(user_id))


def read_session_token(token: str) -> UUID | None:
    try:
        raw = _serializer().loads(token, max_age=settings.session_max_age_seconds)
    except (BadSignature, SignatureExpired):
        return None
    try:
        return UUID(str(raw))
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Principal + lookups
# ---------------------------------------------------------------------------


class Principal:
    __slots__ = ("email", "role", "user_id")

    def __init__(self, *, user_id: UUID, email: str, role: Role) -> None:
        self.user_id = user_id
        self.email = email
        self.role = role

    def has_role(self, minimum: Role) -> bool:
        return ROLE_RANK[self.role] >= ROLE_RANK[minimum]


async def _load_principal(session: AsyncSession, user_id: UUID) -> Principal | None:
    row = (
        await session.execute(
            select(users.c.id, users.c.email, users.c.role, users.c.is_active).where(
                users.c.id == user_id
            )
        )
    ).first()
    if row is None or not row.is_active:
        return None
    return Principal(user_id=row.id, email=row.email, role=row.role)


async def authenticate(session: AsyncSession, email: str, password: str) -> Principal | None:
    """Look up by email and verify the bcrypt password. Returns Principal or None."""
    if not email or not password:
        return None
    row = (
        await session.execute(
            select(
                users.c.id,
                users.c.email,
                users.c.role,
                users.c.is_active,
                users.c.password_hash,
            ).where(users.c.email == email.lower())
        )
    ).first()
    if row is None or not row.is_active:
        return None
    if not verify_password(password, row.password_hash):
        return None
    return Principal(user_id=row.id, email=row.email, role=row.role)


# ---------------------------------------------------------------------------
# FastAPI dependencies
# ---------------------------------------------------------------------------


async def current_principal(
    request: Request,
    cats_session: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
) -> Principal | None:
    """Returns the signed-in Principal, or None if no valid session.

    Routes that *require* a user should depend on `require_user` instead.
    """
    if not cats_session:
        return None
    user_id = read_session_token(cats_session)
    if user_id is None:
        return None
    async with session_scope() as session:
        principal = await _load_principal(session, user_id)
    request.state.principal = principal
    return principal


async def require_user(
    principal: Principal | None = Depends(current_principal),
) -> Principal:
    if principal is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sign in required.",
            headers={"Location": "/login"},
        )
    return principal


def require_role(minimum: Role) -> Callable[[Principal], Awaitable[Principal]]:
    """Dependency factory: 403 with a *visible* message (not silent swallow)
    when a user lacks the required role."""

    async def _dep(
        principal: Principal = Depends(require_user),
    ) -> Principal:
        if not principal.has_role(minimum):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Role '{principal.role}' is not permitted to perform this action. "
                    f"Required role: '{minimum}' or higher."
                ),
            )
        return principal

    return _dep
