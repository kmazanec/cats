"""Pydantic mirrors of the target Co-Pilot's HTTP shapes.

These are *our* model of the target's API, not imports from the openemr
repo (that boundary is read-only by design). They'll grow as we hit more
endpoints.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class CopilotRequest(BaseModel):
    """Generic shape of a Co-Pilot API request body."""

    endpoint: str
    method: str = "POST"
    payload: dict[str, Any] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)


class CopilotResponse(BaseModel):
    status_code: int
    headers: dict[str, str] = Field(default_factory=dict)
    body: dict[str, Any] | str | None = None
    latency_ms: int = 0
    error: str | None = None


class AttackEnvelope(BaseModel):
    """High-level shape the graph passes to the TargetClient. The client
    knows how to translate this into the target's actual HTTP contract
    (OpenEMR PHP proxy vs. internal /v1/agent/*)."""

    model_config = ConfigDict(frozen=True)

    user_message: str
    canary: str = ""
    extra: dict[str, Any] = Field(default_factory=dict)


class TargetCallResult(BaseModel):
    """Return value of `TargetClient.attack`. `text` is what the Judge
    inspects; `raw_body` is preserved for the AttackExecution row and
    forensic replay."""

    text: str
    status_code: int
    latency_ms: int
    raw_body: dict[str, Any] | str | None = None
    error: str | None = None
