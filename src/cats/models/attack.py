from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

AttackSource = Literal["seed", "red_team", "mutator", "regression"]


class Attack(BaseModel):
    """A reusable attack template. The *thing* you fire; one Attack can be
    fired many times across runs, versions, and projects (see
    AttackExecution).

    Mutator-produced variants point back at their seed via
    `parent_attack_id` so lineage is preserved.
    """

    id: UUID = Field(default_factory=uuid4)
    category: str
    title: str
    description: str = ""
    payload: dict[str, Any] = Field(default_factory=dict)
    signature: str = ""
    parent_attack_id: UUID | None = None
    source: AttackSource = "seed"
    created_in_run_id: UUID | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def compute_signature(self) -> str:
        """Stable content hash for dedup. Order-independent over payload keys."""
        body = json.dumps(
            {"category": self.category, "payload": self.payload},
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(body.encode("utf-8")).hexdigest()[:32]
