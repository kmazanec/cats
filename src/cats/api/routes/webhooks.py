"""CI deploy-trigger webhook. Scaffold stub."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

router = APIRouter()


@router.post("/deploy")
async def deploy_webhook(body: dict[str, Any]) -> dict[str, Any]:
    _ = body
    return {"status": "queued"}
