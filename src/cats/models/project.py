from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, HttpUrl

ProjectEnv = Literal["local", "staging", "prod"]


class Project(BaseModel):
    """A target system under test. Reusable; same Project can have many
    ProjectVersions over time."""

    model_config = ConfigDict(frozen=False)

    id: UUID = Field(default_factory=uuid4)
    name: str
    description: str = ""
    base_url: HttpUrl
    env: ProjectEnv = "local"
    api_contract: dict[str, Any] = Field(default_factory=dict)
    auth_material_encrypted: str | None = None
    allow_run_against: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
