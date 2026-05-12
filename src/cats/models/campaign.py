from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

CampaignMode = Literal["blackhat", "whitehat", "both"]
CampaignTrigger = Literal["on_demand", "nightly", "deploy"]


class CampaignBudget(BaseModel):
    max_usd: float | None = None
    max_attacks: int | None = None
    max_wall_seconds: int | None = None


class Campaign(BaseModel):
    """Reusable intent: which project, which categories, in what mode, with
    what budget. A Campaign is fired one or more times producing Runs."""

    id: UUID = Field(default_factory=uuid4)
    name: str
    project_id: UUID
    mode: CampaignMode = "blackhat"
    trigger: CampaignTrigger = "on_demand"
    category_weights: dict[str, float] = Field(default_factory=dict)
    budget: CampaignBudget = Field(default_factory=CampaignBudget)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
