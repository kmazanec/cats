"""Findings routes. Scaffold stubs."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

router = APIRouter()


@router.get("")
async def list_findings() -> list[dict[str, Any]]:
    return []
