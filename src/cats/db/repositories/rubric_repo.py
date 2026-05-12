"""Rubric version registry. The locked rubric file at
`cats/categories/<cat>/rubric/v<n>.md` is the source of truth; this
table just maps (category, version) -> UUID so judge_verdicts can
reference it.
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from cats.db.schema import rubric_versions

_CATS_DIR = Path(__file__).parent.parent.parent / "categories"


def _rubric_version_int(version: str) -> int:
    # "v1" -> 1, "v12" -> 12
    return int(version.lstrip("vV"))


async def ensure_rubric_version(session: AsyncSession, *, category: str, version: str) -> UUID:
    """Idempotent. Loads the rubric file off disk and records it on
    first use so judge_verdicts can FK to it.
    """
    vint = _rubric_version_int(version)
    existing = await session.execute(
        select(rubric_versions.c.id)
        .where(rubric_versions.c.category == category)
        .where(rubric_versions.c.version == vint)
    )
    found = existing.scalar_one_or_none()
    if found:
        return found  # type: ignore[no-any-return]
    path = _CATS_DIR / category / "rubric" / f"{version}.md"
    text = path.read_text(encoding="utf-8")
    new_id = uuid4()
    stmt = (
        pg_insert(rubric_versions)
        .values(id=new_id, category=category, version=vint, prompt_text=text)
        .on_conflict_do_nothing(index_elements=["category", "version"])
        .returning(rubric_versions.c.id)
    )
    result = await session.execute(stmt)
    row = result.scalar_one_or_none()
    if row:
        return row  # type: ignore[no-any-return]
    again = await session.execute(
        select(rubric_versions.c.id)
        .where(rubric_versions.c.category == category)
        .where(rubric_versions.c.version == vint)
    )
    return again.scalar_one()  # type: ignore[no-any-return]
