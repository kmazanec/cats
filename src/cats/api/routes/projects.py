"""Projects routes. Scaffold stub."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

router = APIRouter()


@router.get("")
async def list_projects() -> list[dict[str, Any]]:
    # TODO: read from Postgres
    return []
