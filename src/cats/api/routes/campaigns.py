"""Campaign routes. Scaffold stubs."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter

router = APIRouter()


@router.get("")
async def list_campaigns() -> list[dict[str, Any]]:
    return []


@router.post("")
async def fire_campaign(body: dict[str, Any]) -> dict[str, Any]:
    _ = body
    return {"status": "not_implemented"}


@router.get("/{campaign_id}")
async def get_campaign(campaign_id: UUID) -> dict[str, Any]:
    return {"id": str(campaign_id), "status": "not_implemented"}
